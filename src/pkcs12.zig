const std = @import("std");
const sys = @import("boringssl");

const bio_mod = @import("bio.zig");
const hash_mod = @import("hash.zig");
const internal = @import("internal.zig");
const nid_mod = @import("nid.zig");
const pkey_mod = @import("pkey.zig");
const stack_mod = @import("stack.zig");
const x509_mod = @import("x509.zig");
const BoringError = internal.BoringError;

/// Upper bound on a PKCS#12 password. PKCS#12 permits arbitrary lengths; we
/// The static cap keeps the NUL-terminated copy on the stack.
pub const MaxPasswordBytes: usize = 1024;

/// Upper bound on a PKCS#12 friendly name. Also bounded for stack-copy safety.
pub const MaxFriendlyNameBytes: usize = 256;

/// Default iteration count used by OpenSSL-compatible callers.
pub const DefaultIterations: c_int = 2048;

/// Owned PKCS#12 archive. Wraps BoringSSL's `PKCS12` structure.
pub const Pkcs12 = struct {
    ptr: ?*sys.PKCS12,

    pub fn fromRawOwned(ptr: *sys.PKCS12) Pkcs12 {
        return .{ .ptr = ptr };
    }

    pub fn fromDer(bytes: []const u8) BoringError!Pkcs12 {
        try internal.require_non_empty(bytes);

        var input = try bio_mod.MemBio.initConstSlice(bytes);
        defer input.deinit();
        const raw_ptr = sys.d2i_PKCS12_bio(try input.raw(), null) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *Pkcs12) void {
        if (self.ptr) |raw_ptr| {
            sys.PKCS12_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const Pkcs12) BoringError!*sys.PKCS12 {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *Pkcs12) BoringError!*sys.PKCS12 {
        const raw_ptr = try self.raw();
        self.ptr = null;

        return raw_ptr;
    }

    pub fn toDerBio(self: *const Pkcs12, out: *bio_mod.MemBio) BoringError!void {
        try internal.require_one(sys.i2d_PKCS12_bio(try out.raw(), try self.raw()));
    }

    /// Parses the archive.
    /// The returned components include the leaf certificate, private key, and
    /// CA chain.
    pub fn parse(self: *const Pkcs12, password: []const u8) BoringError!ParsedPkcs12 {
        try require_password_bounds(password);

        var password_buffer: [MaxPasswordBytes + 1]u8 = undefined;
        const password_z = copy_zero_terminated(&password_buffer, password);

        var raw_pkey: ?*sys.EVP_PKEY = null;
        var raw_cert: ?*sys.X509 = null;
        var raw_ca: ?*sys.struct_stack_st_X509 = null;

        try internal.require_one(sys.PKCS12_parse(
            try self.raw(),
            password_z.ptr,
            &raw_pkey,
            &raw_cert,
            &raw_ca,
        ));
        errdefer release_optional_components(raw_pkey, raw_cert, raw_ca);

        return .{
            .pkey = if (raw_pkey) |key| pkey_mod.PKey{ .ptr = key } else null,
            .cert = if (raw_cert) |cert| x509_mod.X509.fromRawOwned(cert) else null,
            .ca = if (raw_ca) |stack| stack_mod.X509Stack.fromRawOwned(stack) else null,
        };
    }
};

/// Outputs from `Pkcs12.parse`.
/// Missing entries remain null.
pub const ParsedPkcs12 = struct {
    pkey: ?pkey_mod.PKey,
    cert: ?x509_mod.X509,
    ca: ?stack_mod.X509Stack,

    pub fn deinit(self: *ParsedPkcs12) void {
        if (self.pkey) |*key| {
            var owned_key = key.*;
            owned_key.deinit();
            self.pkey = null;
        }
        if (self.cert) |*cert| {
            var owned_cert = cert.*;
            owned_cert.deinit();
            self.cert = null;
        }
        if (self.ca) |*stack| {
            var owned_stack = stack.*;
            owned_stack.deinit();
            self.ca = null;
        }
    }
};

/// Builder for PKCS#12 archives.
/// Static bounds keep caller-supplied strings short enough for stack copies.
pub const Pkcs12Builder = struct {
    key_nid: nid_mod.Nid = nid_mod.Nid.undef,
    cert_nid: nid_mod.Nid = nid_mod.Nid.undef,
    iterations: c_int = DefaultIterations,
    mac_iterations: c_int = DefaultIterations,
    ca: ?*const stack_mod.X509Stack = null,

    pub fn init() Pkcs12Builder {
        return .{};
    }

    pub fn keyAlgorithm(self: *Pkcs12Builder, nid: nid_mod.Nid) void {
        self.key_nid = nid;
    }

    pub fn certAlgorithm(self: *Pkcs12Builder, nid: nid_mod.Nid) void {
        self.cert_nid = nid;
    }

    pub fn keyIterations(self: *Pkcs12Builder, iterations: u31) void {
        self.iterations = @intCast(iterations);
    }

    pub fn macIterations(self: *Pkcs12Builder, iterations: u31) void {
        self.mac_iterations = @intCast(iterations);
    }

    pub fn caChain(self: *Pkcs12Builder, chain: *const stack_mod.X509Stack) void {
        self.ca = chain;
    }

    /// Produces a fully constructed PKCS#12 archive. The archive is signed
    /// The archive is built with the provided `pkey`.
    /// `cert` is encrypted together with any chain attached via `caChain`.
    pub fn build(
        self: *const Pkcs12Builder,
        password: []const u8,
        friendly_name: []const u8,
        pkey: *const pkey_mod.PKey,
        cert: *const x509_mod.X509,
    ) BoringError!Pkcs12 {
        try require_password_bounds(password);
        if (friendly_name.len > MaxFriendlyNameBytes) return error.Overflow;

        var password_buffer: [MaxPasswordBytes + 1]u8 = undefined;
        var name_buffer: [MaxFriendlyNameBytes + 1]u8 = undefined;
        const password_z = copy_zero_terminated(&password_buffer, password);
        const name_z = copy_zero_terminated(&name_buffer, friendly_name);

        const chain_ptr: ?*const sys.struct_stack_st_X509 = if (self.ca) |chain_ref|
            try chain_ref.raw()
        else
            null;

        const raw_ptr = sys.PKCS12_create(
            password_z.ptr,
            name_z.ptr,
            try pkey.raw(),
            try cert.raw(),
            chain_ptr,
            self.key_nid.asRaw(),
            self.cert_nid.asRaw(),
            self.iterations,
            self.mac_iterations,
            0,
        ) orelse return error.BoringSSL;

        return Pkcs12.fromRawOwned(raw_ptr);
    }
};

fn require_password_bounds(password: []const u8) BoringError!void {
    if (password.len > MaxPasswordBytes) return error.Overflow;
}

fn copy_zero_terminated(buffer: []u8, source: []const u8) [:0]const u8 {
    std.debug.assert(buffer.len > source.len);

    @memcpy(buffer[0..source.len], source);
    buffer[source.len] = 0;

    return buffer[0..source.len :0];
}

fn release_optional_components(
    pkey: ?*sys.EVP_PKEY,
    cert: ?*sys.X509,
    ca: ?*sys.struct_stack_st_X509,
) void {
    if (pkey) |key| sys.EVP_PKEY_free(key);
    if (cert) |leaf| sys.X509_free(leaf);
    if (ca) |stack| {
        var owned = stack_mod.X509Stack.fromRawOwned(stack);
        owned.deinit();
    }
}

comptime {
    std.debug.assert(MaxPasswordBytes >= 64);
    std.debug.assert(MaxFriendlyNameBytes >= 32);
    std.debug.assert(DefaultIterations >= 1);
}
