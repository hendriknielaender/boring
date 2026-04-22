const std = @import("std");
const sys = @import("boringssl");

const asn1_mod = @import("asn1.zig");
const bio_mod = @import("bio.zig");
const hash_mod = @import("hash.zig");
const internal = @import("internal.zig");
const nid_mod = @import("nid.zig");
const pkey_mod = @import("pkey.zig");
const stack_mod = @import("stack.zig");
const BoringError = internal.BoringError;

pub const MaxCertificateBytes: usize = 64 * 1024;
pub const MaxDigestBytes: usize = sys.EVP_MAX_MD_SIZE;
pub const MaxExtensionConfigBytes: usize = 256;
pub const MaxNameStackEntries: usize = stack_mod.MaxStackEntries;
pub const MaxPemStackCertificates: usize = 16;

const PemStackState = enum {
    read,
    check_error,
    done,
};

pub const X509Ref = struct {
    ptr: *sys.X509,

    pub fn fromRaw(ptr: *sys.X509) X509Ref {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: X509Ref) *sys.X509 {
        return self.ptr;
    }

    pub fn subjectName(self: X509Ref) X509NameRef {
        const name = sys.X509_get_subject_name(self.ptr);
        std.debug.assert(name != null);

        return X509NameRef.fromRaw(name.?);
    }

    pub fn issuerName(self: X509Ref) X509NameRef {
        const name = sys.X509_get_issuer_name(self.ptr);
        std.debug.assert(name != null);

        return X509NameRef.fromRaw(name.?);
    }

    pub fn serialNumber(self: X509Ref) asn1_mod.Asn1Integer {
        const sn_ptr = sys.X509_get_serialNumber(self.ptr);
        std.debug.assert(sn_ptr != null);

        return .{ .ptr = sn_ptr };
    }

    pub fn notBefore(self: X509Ref) asn1_mod.Asn1Time {
        const nb_ptr = X509_getm_notBefore(self.ptr);
        std.debug.assert(nb_ptr != null);

        return .{ .ptr = nb_ptr };
    }

    pub fn notAfter(self: X509Ref) asn1_mod.Asn1Time {
        const na_ptr = X509_getm_notAfter(self.ptr);
        std.debug.assert(na_ptr != null);

        return .{ .ptr = na_ptr };
    }

    pub fn publicKey(self: X509Ref) BoringError!pkey_mod.PKey {
        const pkey = sys.X509_get_pubkey(self.ptr) orelse return error.BoringSSL;

        return pkey_mod.PKey{ .ptr = pkey };
    }

    pub fn digest(self: X509Ref, md: hash_mod.MessageDigest, output: []u8) BoringError!usize {
        if (output.len == 0) return error.InvalidArgument;
        if (output.len > MaxDigestBytes) return error.Overflow;

        var produced: c_uint = 0;
        try internal.require_one(sys.X509_digest(self.ptr, md.raw(), output.ptr, &produced));
        if (produced > output.len) return error.Overflow;

        return @intCast(produced);
    }

    pub fn verify(self: X509Ref, key: *const pkey_mod.PKey) BoringError!bool {
        const result = sys.X509_verify(self.ptr, try key.raw());

        return result > 0;
    }

    pub fn checkHost(self: X509Ref, host: [:0]const u8) BoringError!bool {
        const result = sys.X509_check_host(
            self.ptr,
            host.ptr,
            host.len,
            0,
            null,
        );

        return result == 1;
    }

    pub fn toDerBio(self: X509Ref, out: *bio_mod.MemBio) BoringError!void {
        try internal.require_one(sys.i2d_X509_bio(try out.raw(), self.ptr));
    }

    pub fn toPemBio(self: X509Ref, out: *bio_mod.MemBio) BoringError!void {
        try internal.require_one(sys.PEM_write_bio_X509(try out.raw(), self.ptr));
    }

    pub fn subjectAltNames(self: X509Ref) ?GeneralNameStack {
        var critical: c_int = 0;
        var idx: c_int = 0;
        const raw_stack = sys.X509_get_ext_d2i(
            self.ptr,
            nid_mod.Nid.subjectAltName.asRaw(),
            &critical,
            &idx,
        );
        if (raw_stack == null) return null;

        return GeneralNameStack.fromRawOwned(
            @ptrCast(@alignCast(raw_stack.?)),
        );
    }

    pub fn subjectKeyId(self: X509Ref) ?[]const u8 {
        const octet = sys.X509_get0_subject_key_id(self.ptr);
        if (octet == null) return null;

        const data = sys.ASN1_STRING_get0_data(@ptrCast(octet));
        const len = sys.ASN1_STRING_length(@ptrCast(octet));
        if (len <= 0) return null;

        return data[0..@intCast(len)];
    }

    pub fn authorityKeyId(self: X509Ref) ?[]const u8 {
        const octet = sys.X509_get0_authority_key_id(self.ptr);
        if (octet == null) return null;

        const data = sys.ASN1_STRING_get0_data(@ptrCast(octet));
        const len = sys.ASN1_STRING_length(@ptrCast(octet));
        if (len <= 0) return null;

        return data[0..@intCast(len)];
    }

    pub fn checkIpAsc(self: X509Ref, ip: [:0]const u8) bool {
        const result = sys.X509_check_ip_asc(self.ptr, ip.ptr, 0);
        return result == 1;
    }

    pub fn issued(self: X509Ref, subject: *const X509) c_int {
        const subject_ptr = subject.ptr orelse return sys.X509_V_ERR_UNSPECIFIED;
        return sys.X509_check_issued(self.ptr, subject_ptr);
    }

    pub fn signature(self: X509Ref) ?asn1_mod.Asn1BitString {
        var sig: ?*const sys.ASN1_BIT_STRING = null;
        sys.X509_get0_signature(&sig, null, self.ptr);
        if (sig == null) return null;

        return asn1_mod.Asn1BitString.fromRaw(@constCast(sig.?));
    }

    pub fn signatureAlgorithm(self: X509Ref) ?X509AlgorithmRef {
        var alg: ?*const sys.X509_ALGOR = null;
        sys.X509_get0_signature(null, &alg, self.ptr);
        if (alg == null) return null;

        return X509AlgorithmRef.fromRaw(alg.?);
    }
};

extern fn X509_getm_notBefore(x: *sys.X509) ?*sys.ASN1_TIME;
extern fn X509_getm_notAfter(x: *sys.X509) ?*sys.ASN1_TIME;

pub const X509 = struct {
    ptr: ?*sys.X509,

    pub fn init() BoringError!X509 {
        const raw_ptr = sys.X509_new() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn fromRawOwned(ptr: *sys.X509) X509 {
        return .{ .ptr = ptr };
    }

    pub fn fromDer(bytes: []const u8) BoringError!X509 {
        try internal.require_non_empty(bytes);
        if (bytes.len > MaxCertificateBytes) return error.Overflow;

        var input = try bio_mod.MemBio.initConstSlice(bytes);
        defer input.deinit();
        const raw_ptr = sys.d2i_X509_bio(try input.raw(), null) orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn fromPem(bytes: []const u8) BoringError!X509 {
        try internal.require_non_empty(bytes);
        if (bytes.len > MaxCertificateBytes) return error.Overflow;

        var input = try bio_mod.MemBio.initConstSlice(bytes);
        defer input.deinit();
        const raw_ptr = sys.PEM_read_bio_X509(try input.raw(), null, null, null) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *X509) void {
        if (self.ptr) |raw_ptr| {
            sys.X509_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const X509) BoringError!*sys.X509 {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *X509) BoringError!*sys.X509 {
        const raw_ptr = try self.raw();
        self.ptr = null;

        return raw_ptr;
    }

    pub fn clone(self: *const X509) BoringError!X509 {
        const raw_ptr = try self.raw();
        try internal.require_one(sys.X509_up_ref(raw_ptr));

        return .{ .ptr = raw_ptr };
    }

    pub fn asRef(self: *const X509) BoringError!X509Ref {
        return X509Ref.fromRaw(try self.raw());
    }

    pub fn subjectName(self: *const X509) BoringError!X509NameRef {
        return (try self.asRef()).subjectName();
    }

    pub fn issuerName(self: *const X509) BoringError!X509NameRef {
        return (try self.asRef()).issuerName();
    }

    pub fn digest(self: *const X509, md: hash_mod.MessageDigest, output: []u8) BoringError!usize {
        return (try self.asRef()).digest(md, output);
    }

    pub fn toDerBio(self: *const X509, out: *bio_mod.MemBio) BoringError!void {
        try (try self.asRef()).toDerBio(out);
    }

    pub fn toPemBio(self: *const X509, out: *bio_mod.MemBio) BoringError!void {
        try (try self.asRef()).toPemBio(out);
    }

    pub fn stackFromPem(bytes: []const u8) BoringError!stack_mod.X509Stack {
        try internal.require_non_empty(bytes);
        if (bytes.len > MaxCertificateBytes * MaxPemStackCertificates) return error.Overflow;

        var input = try bio_mod.MemBio.initConstSlice(bytes);
        defer input.deinit();

        var stack = try stack_mod.X509Stack.init();
        errdefer stack.deinit();

        var certificates_count: usize = 0;

        state: switch (PemStackState.read) {
            .read => {
                const raw_ptr = sys.PEM_read_bio_X509(
                    try input.raw(),
                    null,
                    null,
                    null,
                ) orelse continue :state .check_error;
                if (certificates_count >= MaxPemStackCertificates) {
                    sys.X509_free(raw_ptr);
                    return error.Overflow;
                }

                certificates_count += 1;
                std.debug.assert(certificates_count <= MaxPemStackCertificates);
                std.debug.assert(certificates_count <= stack_mod.MaxStackEntries);

                var temp_cert = X509.fromRawOwned(raw_ptr);
                try stack.push(&temp_cert);
                continue :state .read;
            },
            .check_error => {
                const err = sys.ERR_peek_last_error();
                if (err == 0) continue :state .done;
                if (sys.ERR_GET_REASON(err) == sys.PEM_R_NO_START_LINE) {
                    sys.ERR_clear_error();
                    continue :state .done;
                }

                return error.BoringSSL;
            },
            .done => return stack,
        }
    }
};

pub const X509NameRef = struct {
    ptr: *sys.X509_NAME,

    pub fn fromRaw(ptr: *sys.X509_NAME) X509NameRef {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: X509NameRef) *sys.X509_NAME {
        return self.ptr;
    }

    pub fn entriesByNid(self: X509NameRef, nid_value: nid_mod.Nid) X509NameEntries {
        return .{
            .name = self.ptr,
            .nid_filter = nid_value.asRaw(),
            .loc = -1,
        };
    }

    pub fn entries(self: X509NameRef) X509NameEntries {
        return .{
            .name = self.ptr,
            .nid_filter = null,
            .loc = -1,
        };
    }

    pub fn printEx(
        self: X509NameRef,
        out: *bio_mod.MemBio,
        flags: c_ulong,
    ) BoringError!void {
        try internal.require_one(
            sys.X509_NAME_print_ex(try out.raw(), self.ptr, 0, flags),
        );
    }

    pub fn toDer(
        self: X509NameRef,
        allocator: std.mem.Allocator,
    ) BoringError!?[]const u8 {
        const len = sys.i2d_X509_NAME(self.ptr, null);
        if (len <= 0) return null;

        const buf = try allocator.alloc(u8, @intCast(len));
        errdefer allocator.free(buf);

        var ptr: [*c]u8 = buf.ptr;
        _ = sys.i2d_X509_NAME(self.ptr, @ptrCast(&ptr));

        return buf;
    }
};

pub const X509NameEntries = struct {
    name: *sys.X509_NAME,
    nid_filter: ?c_int,
    loc: c_int,

    pub fn next(self: *X509NameEntries) ?X509NameEntryRef {
        if (self.nid_filter) |filter| {
            self.loc = sys.X509_NAME_get_index_by_NID(self.name, filter, self.loc);
            if (self.loc == -1) return null;
        } else {
            self.loc += 1;
            const count = sys.X509_NAME_entry_count(self.name);
            if (self.loc >= count) return null;
        }

        const entry = sys.X509_NAME_get_entry(self.name, self.loc);
        std.debug.assert(entry != null);

        return X509NameEntryRef.fromRaw(entry.?);
    }
};

pub const X509NameEntryRef = struct {
    ptr: *sys.X509_NAME_ENTRY,

    pub fn fromRaw(ptr: *sys.X509_NAME_ENTRY) X509NameEntryRef {
        return .{ .ptr = ptr };
    }

    pub fn data(self: X509NameEntryRef) asn1_mod.Asn1String {
        const raw = sys.X509_NAME_ENTRY_get_data(self.ptr);
        std.debug.assert(raw != null);

        return .{ .ptr = raw };
    }

    pub fn object(self: X509NameEntryRef) asn1_mod.Asn1Object {
        const raw = sys.X509_NAME_ENTRY_get_object(self.ptr);
        std.debug.assert(raw != null);

        return .{ .ptr = raw };
    }
};

pub const X509Name = struct {
    ptr: ?*sys.X509_NAME,

    pub fn init() BoringError!X509Name {
        const raw_ptr = sys.X509_NAME_new() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *X509Name) void {
        if (self.ptr) |raw_ptr| {
            sys.X509_NAME_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const X509Name) BoringError!*sys.X509_NAME {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *X509Name) BoringError!*sys.X509_NAME {
        const raw_ptr = try self.raw();
        self.ptr = null;

        return raw_ptr;
    }

    pub fn appendEntryByNid(
        self: *X509Name,
        nid_value: nid_mod.Nid,
        value: []const u8,
    ) BoringError!void {
        try internal.require_non_empty(value);
        const length = std.math.cast(sys.ossl_ssize_t, value.len) orelse {
            return error.Overflow;
        };

        try internal.require_one(sys.X509_NAME_add_entry_by_NID(
            try self.raw(),
            nid_value.asRaw(),
            sys.MBSTRING_UTF8,
            value.ptr,
            length,
            -1,
            0,
        ));
    }

    pub fn builder() BoringError!X509Name {
        return init();
    }

    pub fn loadClientCaFile(path: [:0]const u8) BoringError!X509NameStack {
        const stack = sys.SSL_load_client_CA_file(path.ptr) orelse return error.BoringSSL;

        return X509NameStack.fromRawOwned(stack);
    }

    pub fn fromDer(der: []const u8) BoringError!X509Name {
        try internal.require_non_empty(der);
        if (der.len > MaxCertificateBytes) return error.Overflow;

        var input: [*c]const u8 = der.ptr;
        const raw_ptr = sys.d2i_X509_NAME(
            null,
            @ptrCast(&input),
            @intCast(der.len),
        ) orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }
};

pub const X509NameStack = struct {
    ptr: ?*sys.struct_stack_st_X509_NAME,

    pub fn fromRawOwned(raw_ptr: *sys.struct_stack_st_X509_NAME) X509NameStack {
        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *X509NameStack) void {
        if (self.ptr) |stack_ptr| {
            sys.sk_X509_NAME_pop_free(stack_ptr, sys.X509_NAME_free);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const X509NameStack) BoringError!*sys.struct_stack_st_X509_NAME {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *X509NameStack) BoringError!*sys.struct_stack_st_X509_NAME {
        const raw_ptr = try self.raw();
        self.ptr = null;

        return raw_ptr;
    }

    pub fn len(self: *const X509NameStack) BoringError!usize {
        const count = sys.sk_X509_NAME_num(try self.raw());
        if (count > MaxNameStackEntries) return error.Overflow;

        return count;
    }

    pub fn get(self: *const X509NameStack, index: usize) BoringError!?X509NameRef {
        const count = try self.len();
        if (index >= count) return null;

        const name = sys.sk_X509_NAME_value(try self.raw(), index) orelse {
            return error.BoringSSL;
        };

        return X509NameRef.fromRaw(name);
    }
};

pub const X509Extension = struct {
    ptr: ?*sys.X509_EXTENSION,

    pub fn deinit(self: *X509Extension) void {
        if (self.ptr) |raw_ptr| {
            sys.X509_EXTENSION_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const X509Extension) BoringError!*sys.X509_EXTENSION {
        return self.ptr orelse error.Closed;
    }

    pub fn fromNid(
        nid_value: nid_mod.Nid,
        value: [:0]const u8,
    ) BoringError!X509Extension {
        const raw_ptr = sys.X509V3_EXT_nconf_nid(
            null,
            null,
            nid_value.asRaw(),
            value.ptr,
        ) orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn toDer(
        self: *const X509Extension,
        allocator: std.mem.Allocator,
    ) BoringError!?[]const u8 {
        const ext = self.ptr orelse return null;
        const len = sys.i2d_X509_EXTENSION(ext, null);
        if (len <= 0) return null;

        const buf = try allocator.alloc(u8, @intCast(len));
        errdefer allocator.free(buf);

        var ptr: [*c]u8 = buf.ptr;
        _ = sys.i2d_X509_EXTENSION(ext, @ptrCast(&ptr));

        return buf;
    }
};

pub const X509Builder = struct {
    cert: X509,

    pub fn init() BoringError!X509Builder {
        const cert = try X509.init();

        return .{ .cert = cert };
    }

    pub fn deinit(self: *X509Builder) void {
        self.cert.deinit();
    }

    pub fn setVersion(self: *X509Builder, version: u8) BoringError!void {
        try internal.require_one(sys.X509_set_version(
            try self.cert.raw(),
            @intCast(version),
        ));
    }

    pub fn setSerialNumber(
        self: *X509Builder,
        serial: *const asn1_mod.Asn1Integer,
    ) BoringError!void {
        try internal.require_one(sys.X509_set_serialNumber(
            try self.cert.raw(),
            try serial.raw(),
        ));
    }

    pub fn setNotBefore(
        self: *X509Builder,
        moment: *const asn1_mod.Asn1Time,
    ) BoringError!void {
        try internal.require_one(sys.X509_set1_notBefore(
            try self.cert.raw(),
            try moment.raw(),
        ));
    }

    pub fn setNotAfter(
        self: *X509Builder,
        moment: *const asn1_mod.Asn1Time,
    ) BoringError!void {
        try internal.require_one(sys.X509_set1_notAfter(
            try self.cert.raw(),
            try moment.raw(),
        ));
    }

    pub fn setSubjectName(self: *X509Builder, name: *const X509Name) BoringError!void {
        try internal.require_one(sys.X509_set_subject_name(
            try self.cert.raw(),
            try name.raw(),
        ));
    }

    pub fn setIssuerName(self: *X509Builder, name: *const X509Name) BoringError!void {
        try internal.require_one(sys.X509_set_issuer_name(
            try self.cert.raw(),
            try name.raw(),
        ));
    }

    pub fn setPubkey(self: *X509Builder, key: *const pkey_mod.PKey) BoringError!void {
        try internal.require_one(sys.X509_set_pubkey(
            try self.cert.raw(),
            try key.raw(),
        ));
    }

    pub fn appendExtension(
        self: *X509Builder,
        extension: *const X509Extension,
    ) BoringError!void {
        try internal.require_one(sys.X509_add_ext(
            try self.cert.raw(),
            try extension.raw(),
            -1,
        ));
    }

    pub fn sign(
        self: *X509Builder,
        key: *const pkey_mod.PKey,
        md: hash_mod.MessageDigest,
    ) BoringError!void {
        const signed_bytes = sys.X509_sign(try self.cert.raw(), try key.raw(), md.raw());
        if (signed_bytes <= 0) return error.BoringSSL;
    }

    pub fn build(self: *X509Builder) BoringError!X509 {
        const raw_ptr = try self.cert.intoRaw();

        return X509.fromRawOwned(raw_ptr);
    }
};

pub const X509Req = struct {
    ptr: ?*sys.X509_REQ,

    pub fn fromDer(bytes: []const u8) BoringError!X509Req {
        try internal.require_non_empty(bytes);
        if (bytes.len > MaxCertificateBytes) return error.Overflow;

        var input = try bio_mod.MemBio.initConstSlice(bytes);
        defer input.deinit();
        const raw_ptr = sys.d2i_X509_REQ_bio(try input.raw(), null) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = raw_ptr };
    }

    pub fn fromPem(bytes: []const u8) BoringError!X509Req {
        try internal.require_non_empty(bytes);
        if (bytes.len > MaxCertificateBytes) return error.Overflow;

        var input = try bio_mod.MemBio.initConstSlice(bytes);
        defer input.deinit();
        const raw_ptr = sys.PEM_read_bio_X509_REQ(try input.raw(), null, null, null) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *X509Req) void {
        if (self.ptr) |raw_ptr| {
            sys.X509_REQ_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const X509Req) BoringError!*sys.X509_REQ {
        return self.ptr orelse error.Closed;
    }

    pub fn version(self: *const X509Req) i32 {
        const req = self.ptr orelse return 0;
        const version_value = sys.X509_REQ_get_version(req);

        return @intCast(version_value);
    }

    pub fn subjectName(self: *const X509Req) BoringError!X509NameRef {
        const req = try self.raw();
        const name = sys.X509_REQ_get_subject_name(req);
        std.debug.assert(name != null);

        return X509NameRef.fromRaw(name.?);
    }

    pub fn publicKey(self: *const X509Req) BoringError!pkey_mod.PKey {
        const req = try self.raw();
        const pkey = sys.X509_REQ_get_pubkey(req) orelse return error.BoringSSL;

        return .{ .ptr = pkey };
    }

    pub fn verify(self: *const X509Req, key: *const pkey_mod.PKey) BoringError!bool {
        const req = try self.raw();
        const result = sys.X509_REQ_verify(req, try key.raw());

        return result > 0;
    }

    pub fn extensions(self: *const X509Req) ?X509ExtensionsStack {
        const req = try self.raw();
        const raw_stack = sys.X509_REQ_get_extensions(req);
        if (raw_stack == null) return null;

        return X509ExtensionsStack.fromRawOwned(raw_stack.?);
    }

    pub fn toDerBio(self: *const X509Req, out: *bio_mod.MemBio) BoringError!void {
        try internal.require_one(sys.i2d_X509_REQ_bio(try out.raw(), try self.raw()));
    }

    pub fn toPemBio(self: *const X509Req, out: *bio_mod.MemBio) BoringError!void {
        try internal.require_one(sys.PEM_write_bio_X509_REQ(try out.raw(), try self.raw()));
    }
};

pub const X509ExtensionsStack = struct {
    ptr: ?*sys.struct_stack_st_X509_EXTENSION,

    pub fn fromRawOwned(ptr: *sys.struct_stack_st_X509_EXTENSION) X509ExtensionsStack {
        return .{ .ptr = ptr };
    }

    pub fn deinit(self: *X509ExtensionsStack) void {
        if (self.ptr) |stack_ptr| {
            sys.struct_stack_st_X509_EXTENSION.sk_X509_EXTENSION_pop_free(
                stack_ptr,
                sys.X509_EXTENSION_free,
            );
            self.ptr = null;
        }
    }

    pub fn len(self: *const X509ExtensionsStack) usize {
        const stack_ptr = self.ptr orelse return 0;
        const count = sys.struct_stack_st_X509_EXTENSION.sk_X509_EXTENSION_num(stack_ptr);
        if (count < 0) return 0;

        return @intCast(count);
    }
};

pub const X509ReqBuilder = struct {
    req: X509Req,

    pub fn init() BoringError!X509ReqBuilder {
        const raw_ptr = sys.X509_REQ_new() orelse return error.BoringSSL;
        const req = X509Req{ .ptr = raw_ptr };

        return .{ .req = req };
    }

    pub fn deinit(self: *X509ReqBuilder) void {
        self.req.deinit();
    }

    pub fn setVersion(self: *X509ReqBuilder, version: i32) BoringError!void {
        try internal.require_one(sys.X509_REQ_set_version(try self.req.raw(), version));
    }

    pub fn setSubjectName(self: *X509ReqBuilder, name: *const X509Name) BoringError!void {
        try internal.require_one(sys.X509_REQ_set_subject_name(
            try self.req.raw(),
            try name.raw(),
        ));
    }

    pub fn setPubkey(self: *X509ReqBuilder, key: *const pkey_mod.PKey) BoringError!void {
        try internal.require_one(sys.X509_REQ_set_pubkey(try self.req.raw(), try key.raw()));
    }

    pub fn sign(
        self: *X509ReqBuilder,
        key: *const pkey_mod.PKey,
        md: hash_mod.MessageDigest,
    ) BoringError!void {
        const result = sys.X509_REQ_sign(try self.req.raw(), try key.raw(), md.raw());
        if (result <= 0) return error.BoringSSL;
    }

    pub fn build(self: *X509ReqBuilder) BoringError!X509Req {
        const raw_ptr = try self.req.raw();
        self.req.ptr = null;

        return X509Req{ .ptr = raw_ptr };
    }
};

pub const KeyUsage = struct {
    flags: KeyUsageFlags,

    pub fn init() KeyUsage {
        return .{ .flags = .{} };
    }

    pub fn digitalSignature(self: KeyUsage) KeyUsage {
        var next = self;
        next.flags.digital_signature = true;

        return next;
    }

    pub fn keyEncipherment(self: KeyUsage) KeyUsage {
        var next = self;
        next.flags.key_encipherment = true;

        return next;
    }

    pub fn keyCertSign(self: KeyUsage) KeyUsage {
        var next = self;
        next.flags.key_cert_sign = true;

        return next;
    }

    pub fn crlSign(self: KeyUsage) KeyUsage {
        var next = self;
        next.flags.crl_sign = true;

        return next;
    }

    pub fn critical(self: KeyUsage) KeyUsage {
        var next = self;
        next.flags.critical = true;

        return next;
    }

    pub fn build(self: KeyUsage) BoringError!X509Extension {
        var buffer: [MaxExtensionConfigBytes]u8 = undefined;
        const value = try self.flags.render(&buffer);

        return X509Extension.fromNid(nid_mod.Nid.keyUsage, value);
    }
};

const KeyUsageFlags = struct {
    critical: bool = false,
    digital_signature: bool = false,
    non_repudiation: bool = false,
    key_encipherment: bool = false,
    data_encipherment: bool = false,
    key_agreement: bool = false,
    key_cert_sign: bool = false,
    crl_sign: bool = false,
    encipher_only: bool = false,
    decipher_only: bool = false,

    fn render(self: KeyUsageFlags, buffer: []u8) BoringError![:0]const u8 {
        const TagEntry = struct { tag: []const u8, enabled: bool };
        const entries = [_]TagEntry{
            .{ .tag = "digitalSignature", .enabled = self.digital_signature },
            .{ .tag = "nonRepudiation", .enabled = self.non_repudiation },
            .{ .tag = "keyEncipherment", .enabled = self.key_encipherment },
            .{ .tag = "dataEncipherment", .enabled = self.data_encipherment },
            .{ .tag = "keyAgreement", .enabled = self.key_agreement },
            .{ .tag = "keyCertSign", .enabled = self.key_cert_sign },
            .{ .tag = "cRLSign", .enabled = self.crl_sign },
            .{ .tag = "encipherOnly", .enabled = self.encipher_only },
            .{ .tag = "decipherOnly", .enabled = self.decipher_only },
        };

        var written: usize = 0;
        if (self.critical) {
            try copy_fragment(buffer, &written, "critical");
        }

        for (entries) |entry| {
            if (!entry.enabled) continue;
            if (written > 0) try copy_fragment(buffer, &written, ",");
            try copy_fragment(buffer, &written, entry.tag);
        }

        if (written >= buffer.len) return error.Overflow;
        buffer[written] = 0;

        return buffer[0..written :0];
    }
};

pub const BasicConstraints = struct {
    is_critical: bool = false,
    is_ca: bool = false,
    path_length: ?u32 = null,

    pub fn init() BasicConstraints {
        return .{};
    }

    pub fn critical(self: BasicConstraints) BasicConstraints {
        var next = self;
        next.is_critical = true;

        return next;
    }

    pub fn ca(self: BasicConstraints) BasicConstraints {
        var next = self;
        next.is_ca = true;

        return next;
    }

    pub fn pathLength(self: BasicConstraints, length: u32) BasicConstraints {
        var next = self;
        next.path_length = length;

        return next;
    }

    pub fn build(self: BasicConstraints) BoringError!X509Extension {
        var buffer: [MaxExtensionConfigBytes]u8 = undefined;
        var written: usize = 0;

        if (self.is_critical) {
            try copy_fragment(&buffer, &written, "critical,");
        }
        try copy_fragment(&buffer, &written, "CA:");
        if (self.is_ca) {
            try copy_fragment(&buffer, &written, "TRUE");
        } else {
            try copy_fragment(&buffer, &written, "FALSE");
        }
        if (self.path_length) |plen| {
            var num_buf: [32]u8 = undefined;
            const plen_str = std.fmt.bufPrintZ(&num_buf, ",pathlen:{}", .{plen}) catch {
                return error.Overflow;
            };
            try copy_fragment(&buffer, &written, plen_str);
        }

        if (written >= buffer.len) return error.Overflow;
        buffer[written] = 0;

        return X509Extension.fromNid(nid_mod.Nid.basicConstraints, buffer[0..written :0]);
    }
};

pub const ExtendedKeyUsage = struct {
    is_critical: bool = false,
    count: usize = 0,
    items: [MaxExtendedKeyUsageEntries]ExtendedKeyUsageEntry,

    const MaxExtendedKeyUsageEntries: usize = 16;

    pub fn init() ExtendedKeyUsage {
        return .{ .items = undefined };
    }

    pub fn critical(self: ExtendedKeyUsage) ExtendedKeyUsage {
        var next = self;
        next.is_critical = true;

        return next;
    }

    pub fn serverAuth(self: ExtendedKeyUsage) BoringError!ExtendedKeyUsage {
        return self.append("serverAuth");
    }

    pub fn clientAuth(self: ExtendedKeyUsage) BoringError!ExtendedKeyUsage {
        return self.append("clientAuth");
    }

    pub fn other(self: ExtendedKeyUsage, oid_text: [:0]const u8) BoringError!ExtendedKeyUsage {
        return self.append(oid_text);
    }

    fn append(self: ExtendedKeyUsage, oid_text: [:0]const u8) BoringError!ExtendedKeyUsage {
        if (self.count >= MaxExtendedKeyUsageEntries) return error.Overflow;
        var next = self;
        next.items[next.count] = .{ .text = oid_text };
        next.count += 1;

        return next;
    }

    pub fn build(self: ExtendedKeyUsage) BoringError!X509Extension {
        var written: usize = 0;
        var buffer: [MaxExtensionConfigBytes]u8 = undefined;

        if (self.is_critical) {
            try copy_fragment(&buffer, &written, "critical,");
        }

        for (self.items[0..self.count], 0..) |entry, i| {
            if (i > 0) try copy_fragment(&buffer, &written, ",");
            try copy_fragment(&buffer, &written, entry.text);
        }

        if (written >= buffer.len) return error.Overflow;
        buffer[written] = 0;

        return X509Extension.fromNid(nid_mod.Nid.extKeyUsage, buffer[0..written :0]);
    }
};

const ExtendedKeyUsageEntry = struct {
    text: [:0]const u8,
};

pub const SubjectAlternativeName = struct {
    is_critical: bool = false,
    count: usize = 0,
    items: [MaxSanEntries]SanEntry,

    const MaxSanEntries: usize = 16;

    pub fn init() SubjectAlternativeName {
        return .{ .items = undefined };
    }

    pub fn critical(self: SubjectAlternativeName) SubjectAlternativeName {
        var next = self;
        next.is_critical = true;

        return next;
    }

    pub fn dns(
        self: SubjectAlternativeName,
        hostname: [:0]const u8,
    ) BoringError!SubjectAlternativeName {
        return self.append(.dns, hostname);
    }

    pub fn email(
        self: SubjectAlternativeName,
        addr: [:0]const u8,
    ) BoringError!SubjectAlternativeName {
        return self.append(.email, addr);
    }

    pub fn uri(
        self: SubjectAlternativeName,
        link: [:0]const u8,
    ) BoringError!SubjectAlternativeName {
        return self.append(.uri, link);
    }

    fn append(
        self: SubjectAlternativeName,
        tag: SanTag,
        value: [:0]const u8,
    ) BoringError!SubjectAlternativeName {
        if (self.count >= MaxSanEntries) return error.Overflow;
        var next = self;
        next.items[next.count] = .{ .tag = tag, .value = value };
        next.count += 1;

        return next;
    }

    pub fn build(self: SubjectAlternativeName) BoringError!X509Extension {
        var written: usize = 0;
        var buffer: [MaxExtensionConfigBytes]u8 = undefined;

        if (self.is_critical) {
            try copy_fragment(&buffer, &written, "critical,");
        }

        for (self.items[0..self.count], 0..) |entry, i| {
            if (i > 0) try copy_fragment(&buffer, &written, ",");
            const prefix = switch (entry.tag) {
                .dns => "DNS:",
                .email => "email:",
                .uri => "URI:",
            };
            try copy_fragment(&buffer, &written, prefix);
            try copy_fragment(&buffer, &written, entry.value);
        }

        if (written >= buffer.len) return error.Overflow;
        buffer[written] = 0;

        return X509Extension.fromNid(nid_mod.Nid.subjectAltName, buffer[0..written :0]);
    }
};

const SanTag = enum { dns, email, uri };

const SanEntry = struct {
    tag: SanTag,
    value: [:0]const u8,
};

pub const MaxGeneralNameEntries: usize = 64;

pub const X509AlgorithmRef = struct {
    ptr: *const sys.X509_ALGOR,

    pub fn fromRaw(ptr: *const sys.X509_ALGOR) X509AlgorithmRef {
        return .{ .ptr = ptr };
    }

    pub fn object(self: X509AlgorithmRef) BoringError!asn1_mod.Asn1Object {
        var oid: ?*const sys.ASN1_OBJECT = null;
        sys.X509_ALGOR_get0(&oid, null, null, self.ptr);
        std.debug.assert(oid != null);

        return asn1_mod.Asn1Object{ .ptr = @constCast(oid.?) };
    }
};

pub const GeneralNameTag = enum(c_int) {
    email = sys.GEN_EMAIL,
    dns = sys.GEN_DNS,
    dirname = sys.GEN_DIRNAME,
    uri = sys.GEN_URI,
    ipadd = sys.GEN_IPADD,
    rid = sys.GEN_RID,
};

pub const GeneralNameRef = struct {
    ptr: *sys.GENERAL_NAME,

    pub fn fromRaw(ptr: *sys.GENERAL_NAME) GeneralNameRef {
        return .{ .ptr = ptr };
    }

    pub fn tag(self: GeneralNameRef) GeneralNameTag {
        return @enumFromInt(self.ptr.type);
    }

    pub fn dnsName(self: GeneralNameRef) ?[]const u8 {
        if (self.ptr.type != sys.GEN_DNS) return null;
        return general_name_string(self.ptr);
    }

    pub fn emailAddress(self: GeneralNameRef) ?[]const u8 {
        if (self.ptr.type != sys.GEN_EMAIL) return null;
        return general_name_string(self.ptr);
    }

    pub fn uriName(self: GeneralNameRef) ?[]const u8 {
        if (self.ptr.type != sys.GEN_URI) return null;
        return general_name_string(self.ptr);
    }

    pub fn ipAddress(self: GeneralNameRef) ?[]const u8 {
        if (self.ptr.type != sys.GEN_IPADD) return null;
        var name_type: c_int = self.ptr.type;
        const data_ptr = sys.GENERAL_NAME_get0_value(
            self.ptr,
            @ptrCast(&name_type),
        ) orelse return null;
        const data: *sys.ASN1_STRING = @ptrCast(@alignCast(data_ptr));
        const bytes = sys.ASN1_STRING_get0_data(data);
        const len = sys.ASN1_STRING_length(data);
        if (len <= 0) return null;

        return bytes[0..@intCast(len)];
    }
};

fn general_name_string(name: *sys.GENERAL_NAME) ?[]const u8 {
    var name_type: c_int = name.type;
    const data_ptr = sys.GENERAL_NAME_get0_value(name, @ptrCast(&name_type)) orelse return null;
    const data: *sys.ASN1_STRING = @ptrCast(@alignCast(data_ptr));
    const bytes = sys.ASN1_STRING_get0_data(data);
    const len = sys.ASN1_STRING_length(data);
    if (len <= 0) return null;

    return bytes[0..@intCast(len)];
}

pub const GeneralNameStack = struct {
    ptr: ?*sys.struct_stack_st_GENERAL_NAME,

    pub fn fromRawOwned(ptr: *sys.struct_stack_st_GENERAL_NAME) GeneralNameStack {
        return .{ .ptr = ptr };
    }

    pub fn deinit(self: *GeneralNameStack) void {
        if (self.ptr) |stack_ptr| {
            sys.struct_stack_st_GENERAL_NAME.sk_GENERAL_NAME_pop_free(
                stack_ptr,
                sys.GENERAL_NAME_free,
            );
            self.ptr = null;
        }
    }

    pub fn len(self: *const GeneralNameStack) BoringError!usize {
        const stack_ptr = self.ptr orelse return 0;
        const count = sys.struct_stack_st_GENERAL_NAME.sk_GENERAL_NAME_num(stack_ptr);
        if (count > MaxGeneralNameEntries) return error.Overflow;

        return @intCast(count);
    }

    pub fn get(self: *const GeneralNameStack, index: usize) ?GeneralNameRef {
        const stack_ptr = self.ptr orelse return null;
        const entry = sys.struct_stack_st_GENERAL_NAME.sk_GENERAL_NAME_value(stack_ptr, index);
        if (entry == null) return null;

        return GeneralNameRef.fromRaw(entry.?);
    }
};

fn copy_fragment(buffer: []u8, written: *usize, fragment: []const u8) BoringError!void {
    if (fragment.len == 0) return;
    if (written.* + fragment.len >= buffer.len) return error.Overflow;

    @memcpy(buffer[written.* .. written.* + fragment.len], fragment);
    written.* += fragment.len;
}

comptime {
    std.debug.assert(MaxCertificateBytes >= 4 * 1024);
    std.debug.assert(MaxDigestBytes >= 32);
    std.debug.assert(MaxExtensionConfigBytes >= 128);
    std.debug.assert(MaxNameStackEntries >= 16);
    std.debug.assert(MaxPemStackCertificates > 0);
    std.debug.assert(MaxPemStackCertificates <= stack_mod.MaxStackEntries);
}
