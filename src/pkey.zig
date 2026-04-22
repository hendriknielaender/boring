const std = @import("std");
const sys = @import("boringssl");

const bio_mod = @import("bio.zig");
const dsa_mod = @import("dsa.zig");
const ec_mod = @import("ec.zig");
const internal = @import("internal.zig");
const rsa_mod = @import("rsa.zig");
const BoringError = internal.BoringError;

pub const Id = struct {
    raw_value: c_int,

    pub const none = fromRaw(sys.EVP_PKEY_NONE);
    pub const rsa = fromRaw(sys.EVP_PKEY_RSA);
    pub const rsaPss = fromRaw(sys.EVP_PKEY_RSA_PSS);
    pub const dsa = fromRaw(sys.EVP_PKEY_DSA);
    pub const dh = fromRaw(sys.EVP_PKEY_DH);
    pub const ec = fromRaw(sys.EVP_PKEY_EC);
    pub const ed25519 = fromRaw(sys.EVP_PKEY_ED25519);
    pub const ed448 = fromRaw(sys.EVP_PKEY_ED448);
    pub const x25519 = fromRaw(sys.EVP_PKEY_X25519);
    pub const x448 = fromRaw(sys.EVP_PKEY_X448);

    pub fn fromRaw(raw_value: c_int) Id {
        return .{ .raw_value = raw_value };
    }

    pub fn asRaw(self: Id) c_int {
        return self.raw_value;
    }
};

pub const PKey = struct {
    ptr: ?*sys.EVP_PKEY,

    pub fn init() BoringError!PKey {
        const pkey = sys.EVP_PKEY_new() orelse return error.BoringSSL;

        return .{ .ptr = pkey };
    }

    pub fn fromRsa(rsa_key: *rsa_mod.Rsa) BoringError!PKey {
        var pkey = try init();
        errdefer pkey.deinit();

        const raw_rsa = try rsa_key.intoRaw();
        errdefer sys.RSA_free(raw_rsa);
        try internal.require_one(sys.EVP_PKEY_assign_RSA(try pkey.raw(), raw_rsa));

        return pkey;
    }

    pub fn fromEcKey(ec_key: *ec_mod.EcKey) BoringError!PKey {
        var pkey = try init();
        errdefer pkey.deinit();

        const raw_key = try ec_key.intoRaw();
        errdefer sys.EC_KEY_free(raw_key);
        try internal.require_one(sys.EVP_PKEY_assign_EC_KEY(try pkey.raw(), raw_key));

        return pkey;
    }

    pub fn fromDsa(dsa_key: *dsa_mod.Dsa) BoringError!PKey {
        var pkey = try init();
        errdefer pkey.deinit();

        const raw_key = try dsa_key.intoRaw();
        errdefer sys.DSA_free(raw_key);
        try internal.require_one(sys.EVP_PKEY_assign_DSA(try pkey.raw(), raw_key));

        return pkey;
    }

    pub fn fromRawPrivateKey(id_value: Id, input: []const u8) BoringError!PKey {
        const pkey = sys.EVP_PKEY_new_raw_private_key(
            id_value.asRaw(),
            null,
            input.ptr,
            input.len,
        ) orelse return error.BoringSSL;

        return .{ .ptr = pkey };
    }

    pub fn fromRawPublicKey(id_value: Id, input: []const u8) BoringError!PKey {
        const pkey = sys.EVP_PKEY_new_raw_public_key(
            id_value.asRaw(),
            null,
            input.ptr,
            input.len,
        ) orelse return error.BoringSSL;

        return .{ .ptr = pkey };
    }

    pub fn fromPem(input: []const u8) BoringError!PKey {
        var bio = try bio_mod.MemBio.initConstSlice(input);
        defer bio.deinit();

        const pkey = sys.PEM_read_bio_PrivateKey(
            try bio.raw(),
            null,
            null,
            null,
        ) orelse return error.BoringSSL;

        return .{ .ptr = pkey };
    }

    pub fn fromPemWithPassword(input: []const u8, password: []const u8) BoringError!PKey {
        var bio = try bio_mod.MemBio.initConstSlice(input);
        defer bio.deinit();

        var state = internal.PasswordCallbackState{ .password = password };
        const pkey = sys.PEM_read_bio_PrivateKey(
            try bio.raw(),
            null,
            internal.password_callback,
            &state,
        ) orelse return error.BoringSSL;

        return .{ .ptr = pkey };
    }

    pub fn setRsa(self: *PKey, rsa_key: *const rsa_mod.Rsa) BoringError!void {
        try internal.require_one(sys.EVP_PKEY_set1_RSA(try self.raw(), try rsa_key.raw()));
    }

    pub fn deinit(self: *PKey) void {
        if (self.ptr) |pkey| {
            sys.EVP_PKEY_free(pkey);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const PKey) BoringError!*sys.EVP_PKEY {
        return self.ptr orelse error.Closed;
    }

    pub fn clone(self: *const PKey) BoringError!PKey {
        const pkey = try self.raw();
        try internal.require_one(sys.EVP_PKEY_up_ref(pkey));

        return .{ .ptr = pkey };
    }

    pub fn rsa(self: *const PKey) BoringError!rsa_mod.Rsa {
        const rsa_key = sys.EVP_PKEY_get1_RSA(try self.raw()) orelse return error.BoringSSL;

        return rsa_mod.Rsa.fromRawOwned(rsa_key);
    }

    pub fn ecKey(self: *const PKey) BoringError!ec_mod.EcKey {
        const ec_key = sys.EVP_PKEY_get1_EC_KEY(try self.raw()) orelse return error.BoringSSL;

        return ec_mod.EcKey.fromRawOwned(ec_key);
    }

    pub fn dsa(self: *const PKey) BoringError!dsa_mod.Dsa {
        const dsa_key = sys.EVP_PKEY_get1_DSA(try self.raw()) orelse return error.BoringSSL;

        return dsa_mod.Dsa.fromRawOwned(dsa_key);
    }

    pub fn id(self: *const PKey) BoringError!Id {
        return Id.fromRaw(sys.EVP_PKEY_id(try self.raw()));
    }

    pub fn size(self: *const PKey) BoringError!usize {
        const result = sys.EVP_PKEY_size(try self.raw());
        if (result < 0) return error.BoringSSL;

        return @intCast(result);
    }

    pub fn bits(self: *const PKey) BoringError!usize {
        const result = sys.EVP_PKEY_bits(try self.raw());
        if (result < 0) return error.BoringSSL;

        return @intCast(result);
    }

    pub fn isOpaque(self: *const PKey) BoringError!bool {
        return sys.EVP_PKEY_is_opaque(try self.raw()) == 1;
    }

    pub fn missingParameters(self: *const PKey) BoringError!bool {
        return sys.EVP_PKEY_missing_parameters(try self.raw()) == 1;
    }

    pub fn publicEq(self: *const PKey, other: *const PKey) BoringError!bool {
        return sys.EVP_PKEY_cmp(try self.raw(), try other.raw()) == 1;
    }

    pub fn rawPublicKeyLength(self: *const PKey) BoringError!usize {
        var len: usize = 0;
        try internal.require_one(sys.EVP_PKEY_get_raw_public_key(
            try self.raw(),
            null,
            &len,
        ));

        return len;
    }

    pub fn rawPublicKey(self: *const PKey, output: []u8) BoringError!usize {
        var len = output.len;
        try internal.require_one(sys.EVP_PKEY_get_raw_public_key(
            try self.raw(),
            output.ptr,
            &len,
        ));

        return len;
    }

    pub fn rawPrivateKeyLength(self: *const PKey) BoringError!usize {
        var len: usize = 0;
        try internal.require_one(sys.EVP_PKEY_get_raw_private_key(
            try self.raw(),
            null,
            &len,
        ));

        return len;
    }

    pub fn rawPrivateKey(self: *const PKey, output: []u8) BoringError!usize {
        var len = output.len;
        try internal.require_one(sys.EVP_PKEY_get_raw_private_key(
            try self.raw(),
            output.ptr,
            &len,
        ));

        return len;
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.EVP_PKEY) > 0);
}
