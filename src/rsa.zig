const std = @import("std");
const sys = @import("boringssl");

const bio_mod = @import("bio.zig");
const bn = @import("bn.zig");
const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const Padding = enum(c_int) {
    none = sys.RSA_NO_PADDING,
    pkcs1 = sys.RSA_PKCS1_PADDING,
    pkcs1Oaep = sys.RSA_PKCS1_OAEP_PADDING,
    pkcs1Pss = sys.RSA_PKCS1_PSS_PADDING,

    pub fn fromRaw(value: c_int) BoringError!Padding {
        return switch (value) {
            sys.RSA_NO_PADDING => .none,
            sys.RSA_PKCS1_PADDING => .pkcs1,
            sys.RSA_PKCS1_OAEP_PADDING => .pkcs1Oaep,
            sys.RSA_PKCS1_PSS_PADDING => .pkcs1Pss,
            else => error.InvalidArgument,
        };
    }

    pub fn raw(self: Padding) c_int {
        return @intFromEnum(self);
    }
};

pub const Rsa = struct {
    ptr: ?*sys.RSA,

    pub fn init() BoringError!Rsa {
        const rsa = sys.RSA_new() orelse return error.BoringSSL;

        return .{ .ptr = rsa };
    }

    pub fn generate(bit_count: u31) BoringError!Rsa {
        var rsa = try init();
        errdefer rsa.deinit();

        var exponent = try bn.BigNum.fromU32(65537);
        defer exponent.deinit();
        try internal.require_one(sys.RSA_generate_key_ex(
            try rsa.raw(),
            bit_count,
            try exponent.raw(),
            null,
        ));

        return rsa;
    }

    pub fn fromPem(input: []const u8) BoringError!Rsa {
        var bio = try bio_mod.MemBio.initConstSlice(input);
        defer bio.deinit();

        const rsa = sys.PEM_read_bio_RSAPrivateKey(
            try bio.raw(),
            null,
            null,
            null,
        ) orelse return error.BoringSSL;

        return .{ .ptr = rsa };
    }

    pub fn fromPemWithPassword(input: []const u8, password: []const u8) BoringError!Rsa {
        var bio = try bio_mod.MemBio.initConstSlice(input);
        defer bio.deinit();

        var state = internal.PasswordCallbackState{ .password = password };
        const rsa = sys.PEM_read_bio_RSAPrivateKey(
            try bio.raw(),
            null,
            internal.password_callback,
            &state,
        ) orelse return error.BoringSSL;

        return .{ .ptr = rsa };
    }

    pub fn fromPublicComponents(n: *const bn.BigNum, e: *const bn.BigNum) BoringError!Rsa {
        const rsa = sys.RSA_new_public_key(try n.raw(), try e.raw()) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = rsa };
    }

    pub fn deinit(self: *Rsa) void {
        if (self.ptr) |rsa| {
            sys.RSA_free(rsa);
            self.ptr = null;
        }
    }

    pub fn fromRawOwned(ptr: *sys.RSA) Rsa {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: *const Rsa) BoringError!*sys.RSA {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *Rsa) BoringError!*sys.RSA {
        const rsa = try self.raw();
        self.ptr = null;

        return rsa;
    }

    pub fn clone(self: *const Rsa) BoringError!Rsa {
        const rsa = try self.raw();
        try internal.require_one(sys.RSA_up_ref(rsa));

        return .{ .ptr = rsa };
    }

    pub fn bits(self: *const Rsa) BoringError!usize {
        return sys.RSA_bits(try self.raw());
    }

    pub fn size(self: *const Rsa) BoringError!usize {
        return sys.RSA_size(try self.raw());
    }

    pub fn checkKey(self: *const Rsa) BoringError!bool {
        const result = sys.RSA_check_key(try self.raw());
        if (result < 0) return error.BoringSSL;

        return result == 1;
    }

    pub fn publicEncrypt(
        self: *const Rsa,
        output: []u8,
        input: []const u8,
        padding: Padding,
    ) BoringError!usize {
        try require_output_len(self, output);
        return rsa_result(sys.RSA_public_encrypt(
            input.len,
            input.ptr,
            output.ptr,
            try self.raw(),
            padding.raw(),
        ));
    }

    pub fn privateDecrypt(
        self: *const Rsa,
        output: []u8,
        input: []const u8,
        padding: Padding,
    ) BoringError!usize {
        try require_output_len(self, output);
        return rsa_result(sys.RSA_private_decrypt(
            input.len,
            input.ptr,
            output.ptr,
            try self.raw(),
            padding.raw(),
        ));
    }

    pub fn privateEncrypt(
        self: *const Rsa,
        output: []u8,
        input: []const u8,
        padding: Padding,
    ) BoringError!usize {
        try require_output_len(self, output);
        return rsa_result(sys.RSA_private_encrypt(
            input.len,
            input.ptr,
            output.ptr,
            try self.raw(),
            padding.raw(),
        ));
    }

    pub fn publicDecrypt(
        self: *const Rsa,
        output: []u8,
        input: []const u8,
        padding: Padding,
    ) BoringError!usize {
        try require_output_len(self, output);
        return rsa_result(sys.RSA_public_decrypt(
            input.len,
            input.ptr,
            output.ptr,
            try self.raw(),
            padding.raw(),
        ));
    }
};

fn require_output_len(rsa: *const Rsa, output: []u8) BoringError!void {
    if (output.len >= try rsa.size()) return;

    return error.InvalidArgument;
}

fn rsa_result(result: c_int) BoringError!usize {
    if (result < 0) return error.BoringSSL;

    return @intCast(result);
}

comptime {
    std.debug.assert(@sizeOf(c_int) >= 4);
}
