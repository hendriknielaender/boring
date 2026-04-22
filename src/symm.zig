const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const nid_mod = @import("nid.zig");
const BoringError = internal.BoringError;

pub const Mode = enum(c_int) {
    decrypt = 0,
    encrypt = 1,

    fn raw(self: Mode) c_int {
        return @intFromEnum(self);
    }
};

pub const Cipher = struct {
    ptr: *const sys.EVP_CIPHER,

    pub fn fromNid(cipher_nid: nid_mod.Nid) ?Cipher {
        const ptr = sys.EVP_get_cipherbynid(cipher_nid.asRaw()) orelse return null;
        return .{ .ptr = ptr };
    }

    pub fn aes128Ecb() Cipher {
        return .{ .ptr = sys.EVP_aes_128_ecb() orelse unreachable };
    }

    pub fn aes128Cbc() Cipher {
        return .{ .ptr = sys.EVP_aes_128_cbc() orelse unreachable };
    }

    pub fn aes128Ctr() Cipher {
        return .{ .ptr = sys.EVP_aes_128_ctr() orelse unreachable };
    }

    pub fn aes128Gcm() Cipher {
        return .{ .ptr = sys.EVP_aes_128_gcm() orelse unreachable };
    }

    pub fn aes128Ofb() Cipher {
        return .{ .ptr = sys.EVP_aes_128_ofb() orelse unreachable };
    }

    pub fn aes192Ecb() Cipher {
        return .{ .ptr = sys.EVP_aes_192_ecb() orelse unreachable };
    }

    pub fn aes192Cbc() Cipher {
        return .{ .ptr = sys.EVP_aes_192_cbc() orelse unreachable };
    }

    pub fn aes192Ctr() Cipher {
        return .{ .ptr = sys.EVP_aes_192_ctr() orelse unreachable };
    }

    pub fn aes192Gcm() Cipher {
        return .{ .ptr = sys.EVP_aes_192_gcm() orelse unreachable };
    }

    pub fn aes192Ofb() Cipher {
        return .{ .ptr = sys.EVP_aes_192_ofb() orelse unreachable };
    }

    pub fn aes256Ecb() Cipher {
        return .{ .ptr = sys.EVP_aes_256_ecb() orelse unreachable };
    }

    pub fn aes256Cbc() Cipher {
        return .{ .ptr = sys.EVP_aes_256_cbc() orelse unreachable };
    }

    pub fn aes256Ctr() Cipher {
        return .{ .ptr = sys.EVP_aes_256_ctr() orelse unreachable };
    }

    pub fn aes256Gcm() Cipher {
        return .{ .ptr = sys.EVP_aes_256_gcm() orelse unreachable };
    }

    pub fn aes256Ofb() Cipher {
        return .{ .ptr = sys.EVP_aes_256_ofb() orelse unreachable };
    }

    pub fn desCbc() Cipher {
        return .{ .ptr = sys.EVP_des_cbc() orelse unreachable };
    }

    pub fn desEcb() Cipher {
        return .{ .ptr = sys.EVP_des_ecb() orelse unreachable };
    }

    pub fn desEde3() Cipher {
        return .{ .ptr = sys.EVP_des_ede3() orelse unreachable };
    }

    pub fn desEde3Cbc() Cipher {
        return .{ .ptr = sys.EVP_des_ede3_cbc() orelse unreachable };
    }

    pub fn rc4() Cipher {
        return .{ .ptr = sys.EVP_rc4() orelse unreachable };
    }

    pub fn raw(self: Cipher) *const sys.EVP_CIPHER {
        return self.ptr;
    }

    pub fn keyLength(self: Cipher) usize {
        return sys.EVP_CIPHER_key_length(self.ptr);
    }

    pub fn ivLength(self: Cipher) ?usize {
        const len = sys.EVP_CIPHER_iv_length(self.ptr);
        if (len == 0) return null;

        return len;
    }

    pub fn blockSize(self: Cipher) usize {
        return sys.EVP_CIPHER_block_size(self.ptr);
    }

    pub fn nid(self: Cipher) nid_mod.Nid {
        return nid_mod.Nid.fromRaw(sys.EVP_CIPHER_nid(self.ptr));
    }
};

pub const Crypter = struct {
    ctx: ?*sys.EVP_CIPHER_CTX,
    block_size: usize,

    pub fn init(
        cipher: Cipher,
        mode: Mode,
        key: []const u8,
        iv: ?[]const u8,
    ) BoringError!Crypter {
        const ctx = sys.EVP_CIPHER_CTX_new() orelse return error.BoringSSL;
        var self = Crypter{
            .ctx = ctx,
            .block_size = cipher.blockSize(),
        };

        errdefer self.deinit();
        try internal.require_one(sys.EVP_CipherInit_ex(
            ctx,
            cipher.raw(),
            null,
            null,
            null,
            mode.raw(),
        ));
        try internal.require_one(sys.EVP_CIPHER_CTX_set_key_length(
            ctx,
            try internal.c_uint_len(key.len),
        ));

        const iv_ptr = try set_iv_length(ctx, cipher, iv);
        try internal.require_one(sys.EVP_CipherInit_ex(
            ctx,
            null,
            null,
            key.ptr,
            iv_ptr,
            mode.raw(),
        ));

        return self;
    }

    pub fn deinit(self: *Crypter) void {
        if (self.ctx) |ctx| {
            sys.EVP_CIPHER_CTX_free(ctx);
            self.ctx = null;
        }
    }

    pub fn setPadding(self: *Crypter, enabled: bool) BoringError!void {
        const ctx = self.ctx orelse return error.Closed;
        try internal.require_one(sys.EVP_CIPHER_CTX_set_padding(ctx, @intFromBool(enabled)));
    }

    pub fn setTag(self: *Crypter, tag: []const u8) BoringError!void {
        const ctx = self.ctx orelse return error.Closed;
        try internal.require_non_empty(tag);
        try internal.require_one(sys.EVP_CIPHER_CTX_ctrl(
            ctx,
            sys.EVP_CTRL_GCM_SET_TAG,
            try internal.c_int_len(tag.len),
            @ptrCast(@constCast(tag.ptr)),
        ));
    }

    pub fn setTagLength(self: *Crypter, tag_len: usize) BoringError!void {
        const ctx = self.ctx orelse return error.Closed;
        try internal.require_one(sys.EVP_CIPHER_CTX_ctrl(
            ctx,
            sys.EVP_CTRL_GCM_SET_TAG,
            try internal.c_int_len(tag_len),
            null,
        ));
    }

    pub fn setDataLength(self: *Crypter, data_len: usize) BoringError!void {
        const ctx = self.ctx orelse return error.Closed;
        var output_len: c_int = 0;
        try internal.require_one(sys.EVP_CipherUpdate(
            ctx,
            null,
            &output_len,
            null,
            try internal.c_int_len(data_len),
        ));
    }

    pub fn aadUpdate(self: *Crypter, input: []const u8) BoringError!void {
        const ctx = self.ctx orelse return error.Closed;
        var output_len: c_int = 0;
        try internal.require_one(sys.EVP_CipherUpdate(
            ctx,
            null,
            &output_len,
            input.ptr,
            try internal.c_int_len(input.len),
        ));
    }

    pub fn update(
        self: *Crypter,
        output: []u8,
        input: []const u8,
    ) BoringError!usize {
        const ctx = self.ctx orelse return error.Closed;
        const extra_len = if (self.block_size > 1) self.block_size else 0;
        const required_len = std.math.add(usize, input.len, extra_len) catch {
            return error.Overflow;
        };
        if (output.len < required_len) return error.InvalidArgument;

        var output_len: c_int = 0;
        try internal.require_one(sys.EVP_CipherUpdate(
            ctx,
            output.ptr,
            &output_len,
            input.ptr,
            try internal.c_int_len(input.len),
        ));

        return @intCast(output_len);
    }

    pub fn finish(self: *Crypter, output: []u8) BoringError!usize {
        const ctx = self.ctx orelse return error.Closed;
        if (self.block_size > 1 and output.len < self.block_size) {
            return error.InvalidArgument;
        }

        var output_len: c_int = 0;
        try internal.require_one(sys.EVP_CipherFinal_ex(ctx, output.ptr, &output_len));

        return @intCast(output_len);
    }

    pub fn getTag(self: *const Crypter, tag: []u8) BoringError!void {
        const ctx = self.ctx orelse return error.Closed;
        try internal.require_non_empty(tag);
        try internal.require_one(sys.EVP_CIPHER_CTX_ctrl(
            ctx,
            sys.EVP_CTRL_GCM_GET_TAG,
            try internal.c_int_len(tag.len),
            @ptrCast(tag.ptr),
        ));
    }
};

pub fn encrypt(
    output: []u8,
    cipher: Cipher,
    key: []const u8,
    iv: ?[]const u8,
    input: []const u8,
) BoringError!usize {
    return run_cipher(output, cipher, .encrypt, key, iv, input);
}

pub fn decrypt(
    output: []u8,
    cipher: Cipher,
    key: []const u8,
    iv: ?[]const u8,
    input: []const u8,
) BoringError!usize {
    return run_cipher(output, cipher, .decrypt, key, iv, input);
}

pub fn encryptAead(
    output: []u8,
    tag: []u8,
    cipher: Cipher,
    key: []const u8,
    iv: ?[]const u8,
    aad: []const u8,
    input: []const u8,
) BoringError!usize {
    var crypter = try Crypter.init(cipher, .encrypt, key, iv);
    defer crypter.deinit();

    try crypter.aadUpdate(aad);
    const update_len = try crypter.update(output, input);
    const finish_len = try crypter.finish(output[update_len..]);
    try crypter.getTag(tag);

    return update_len + finish_len;
}

pub fn decryptAead(
    output: []u8,
    cipher: Cipher,
    key: []const u8,
    iv: ?[]const u8,
    aad: []const u8,
    input: []const u8,
    tag: []const u8,
) BoringError!usize {
    var crypter = try Crypter.init(cipher, .decrypt, key, iv);
    defer crypter.deinit();

    try crypter.aadUpdate(aad);
    const update_len = try crypter.update(output, input);
    try crypter.setTag(tag);
    const finish_len = try crypter.finish(output[update_len..]);

    return update_len + finish_len;
}

fn run_cipher(
    output: []u8,
    cipher: Cipher,
    mode: Mode,
    key: []const u8,
    iv: ?[]const u8,
    input: []const u8,
) BoringError!usize {
    var crypter = try Crypter.init(cipher, mode, key, iv);
    defer crypter.deinit();

    const update_len = try crypter.update(output, input);
    const finish_len = try crypter.finish(output[update_len..]);

    return update_len + finish_len;
}

pub const CipherCtxRef = struct {
    ptr: *sys.EVP_CIPHER_CTX,

    pub fn initEncrypt(
        self: *CipherCtxRef,
        cipher: Cipher,
        key: []const u8,
        iv: []const u8,
    ) BoringError!void {
        if (key.len != cipher.keyLength()) {
            return error.InvalidArgument;
        }

        try internal.require_one(sys.EVP_EncryptInit_ex(
            self.ptr,
            cipher.raw(),
            null,
            key.ptr,
            iv.ptr,
        ));
    }

    pub fn initDecrypt(
        self: *CipherCtxRef,
        cipher: Cipher,
        key: []const u8,
        iv: []const u8,
    ) BoringError!void {
        if (key.len != cipher.keyLength()) {
            return error.InvalidArgument;
        }

        try internal.require_one(sys.EVP_DecryptInit_ex(
            self.ptr,
            cipher.raw(),
            null,
            key.ptr,
            iv.ptr,
        ));
    }
};

fn set_iv_length(
    ctx: *sys.EVP_CIPHER_CTX,
    cipher: Cipher,
    iv: ?[]const u8,
) BoringError![*c]const u8 {
    const expected_len = cipher.ivLength() orelse return null;
    const value = iv orelse return error.InvalidArgument;
    if (value.len != expected_len) {
        try internal.require_one(sys.EVP_CIPHER_CTX_ctrl(
            ctx,
            sys.EVP_CTRL_GCM_SET_IVLEN,
            try internal.c_int_len(value.len),
            null,
        ));
    }

    return value.ptr;
}

comptime {
    std.debug.assert(@sizeOf(*sys.EVP_CIPHER_CTX) > 0);
    std.debug.assert(@sizeOf(*const sys.EVP_CIPHER) > 0);
}
