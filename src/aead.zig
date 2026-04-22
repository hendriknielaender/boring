const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const MaxKeyLength: usize = sys.EVP_AEAD_MAX_KEY_LENGTH;
pub const MaxNonceLength: usize = sys.EVP_AEAD_MAX_NONCE_LENGTH;
pub const MaxOverhead: usize = sys.EVP_AEAD_MAX_OVERHEAD;
pub const DefaultTagLength: usize = sys.EVP_AEAD_DEFAULT_TAG_LENGTH;

pub const Algorithm = struct {
    ptr: *const sys.EVP_AEAD,

    pub fn aes128Gcm() Algorithm {
        return .{ .ptr = sys.EVP_aead_aes_128_gcm() orelse unreachable };
    }

    pub fn aes192Gcm() Algorithm {
        return .{ .ptr = sys.EVP_aead_aes_192_gcm() orelse unreachable };
    }

    pub fn aes256Gcm() Algorithm {
        return .{ .ptr = sys.EVP_aead_aes_256_gcm() orelse unreachable };
    }

    pub fn chacha20Poly1305() Algorithm {
        return .{ .ptr = sys.EVP_aead_chacha20_poly1305() orelse unreachable };
    }

    pub fn xchacha20Poly1305() Algorithm {
        return .{ .ptr = sys.EVP_aead_xchacha20_poly1305() orelse unreachable };
    }

    pub fn aes128GcmSiv() Algorithm {
        return .{ .ptr = sys.EVP_aead_aes_128_gcm_siv() orelse unreachable };
    }

    pub fn aes256GcmSiv() Algorithm {
        return .{ .ptr = sys.EVP_aead_aes_256_gcm_siv() orelse unreachable };
    }

    pub fn keyLength(self: Algorithm) usize {
        return sys.EVP_AEAD_key_length(self.ptr);
    }

    pub fn nonceLength(self: Algorithm) usize {
        return sys.EVP_AEAD_nonce_length(self.ptr);
    }

    pub fn maxOverhead(self: Algorithm) usize {
        return sys.EVP_AEAD_max_overhead(self.ptr);
    }

    pub fn maxTagLength(self: Algorithm) usize {
        return sys.EVP_AEAD_max_tag_len(self.ptr);
    }

    pub fn raw(self: Algorithm) *const sys.EVP_AEAD {
        return self.ptr;
    }
};

pub const Context = struct {
    ptr: ?*sys.EVP_AEAD_CTX,
    algorithm: Algorithm,

    pub fn init(algorithm: Algorithm, key: []const u8, tag_len: usize) BoringError!Context {
        if (key.len != algorithm.keyLength()) return error.InvalidArgument;
        if (tag_len > algorithm.maxTagLength()) return error.InvalidArgument;

        const ctx = sys.EVP_AEAD_CTX_new(
            algorithm.raw(),
            key.ptr,
            key.len,
            tag_len,
        ) orelse return error.BoringSSL;

        return .{
            .ptr = ctx,
            .algorithm = algorithm,
        };
    }

    pub fn initDefaultTag(algorithm: Algorithm, key: []const u8) BoringError!Context {
        return init(algorithm, key, DefaultTagLength);
    }

    pub fn deinit(self: *Context) void {
        if (self.ptr) |ctx| {
            sys.EVP_AEAD_CTX_free(ctx);
            self.ptr = null;
        }
    }

    pub fn seal(
        self: *const Context,
        output: []u8,
        nonce: []const u8,
        input: []const u8,
        associated_data: []const u8,
    ) BoringError!usize {
        const ctx = self.ptr orelse return error.Closed;
        try self.require_nonce(nonce);
        if (output.len < input.len + self.algorithm.maxOverhead()) {
            return error.InvalidArgument;
        }

        var output_len: usize = 0;
        try internal.require_one(sys.EVP_AEAD_CTX_seal(
            ctx,
            output.ptr,
            &output_len,
            output.len,
            nonce.ptr,
            nonce.len,
            input.ptr,
            input.len,
            associated_data.ptr,
            associated_data.len,
        ));

        return output_len;
    }

    pub fn open(
        self: *const Context,
        output: []u8,
        nonce: []const u8,
        input: []const u8,
        associated_data: []const u8,
    ) BoringError!usize {
        const ctx = self.ptr orelse return error.Closed;
        try self.require_nonce(nonce);
        if (output.len < input.len) return error.InvalidArgument;

        var output_len: usize = 0;
        try internal.require_one(sys.EVP_AEAD_CTX_open(
            ctx,
            output.ptr,
            &output_len,
            output.len,
            nonce.ptr,
            nonce.len,
            input.ptr,
            input.len,
            associated_data.ptr,
            associated_data.len,
        ));

        return output_len;
    }

    fn require_nonce(self: *const Context, nonce: []const u8) BoringError!void {
        if (nonce.len == self.algorithm.nonceLength()) return;

        return error.InvalidArgument;
    }
};

comptime {
    std.debug.assert(MaxKeyLength > 0);
    std.debug.assert(MaxNonceLength > 0);
    std.debug.assert(MaxOverhead > 0);
}
