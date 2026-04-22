const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const DigestBytes = struct {
    pub const capacity: u8 = @intCast(sys.EVP_MAX_MD_SIZE);

    buffer: [capacity]u8 = undefined,
    len: u8 = 0,

    pub fn bytes(self: *const DigestBytes) []const u8 {
        return self.buffer[0..self.len];
    }
};

pub const MessageDigest = struct {
    ptr: *const sys.EVP_MD,

    pub fn md5() MessageDigest {
        return .{ .ptr = sys.EVP_md5() orelse unreachable };
    }

    pub fn sha1() MessageDigest {
        return .{ .ptr = sys.EVP_sha1() orelse unreachable };
    }

    pub fn sha224() MessageDigest {
        return .{ .ptr = sys.EVP_sha224() orelse unreachable };
    }

    pub fn sha256() MessageDigest {
        return .{ .ptr = sys.EVP_sha256() orelse unreachable };
    }

    pub fn sha384() MessageDigest {
        return .{ .ptr = sys.EVP_sha384() orelse unreachable };
    }

    pub fn sha512() MessageDigest {
        return .{ .ptr = sys.EVP_sha512() orelse unreachable };
    }

    pub fn sha512256() MessageDigest {
        return .{ .ptr = sys.EVP_sha512_256() orelse unreachable };
    }

    pub fn size(self: MessageDigest) usize {
        return sys.EVP_MD_size(self.ptr);
    }

    pub fn raw(self: MessageDigest) *const sys.EVP_MD {
        return self.ptr;
    }
};

pub const Hasher = struct {
    ctx: ?*sys.EVP_MD_CTX,
    digest: MessageDigest,
    finalized: bool,

    pub fn init(message_digest: MessageDigest) BoringError!Hasher {
        const ctx = sys.EVP_MD_CTX_new() orelse return error.BoringSSL;
        var self = Hasher{
            .ctx = ctx,
            .digest = message_digest,
            .finalized = true,
        };
        try self.reset();

        return self;
    }

    pub fn deinit(self: *Hasher) void {
        if (self.ctx) |ctx| {
            sys.EVP_MD_CTX_free(ctx);
            self.ctx = null;
        }
    }

    pub fn reset(self: *Hasher) BoringError!void {
        const ctx = self.ctx orelse return error.Closed;
        try internal.require_one(sys.EVP_DigestInit_ex(ctx, self.digest.ptr, null));
        self.finalized = false;
    }

    pub fn update(self: *Hasher, data: []const u8) BoringError!void {
        if (self.finalized) try self.reset();

        const ctx = self.ctx orelse return error.Closed;
        try internal.require_one(sys.EVP_DigestUpdate(ctx, data.ptr, data.len));
    }

    pub fn finish(self: *Hasher) BoringError!DigestBytes {
        const ctx = self.ctx orelse return error.Closed;
        if (self.finalized) try self.reset();

        var output = DigestBytes{};
        var output_len: c_uint = output.buffer.len;
        try internal.require_one(sys.EVP_DigestFinal_ex(ctx, &output.buffer, &output_len));

        std.debug.assert(output_len <= output.buffer.len);
        output.len = @intCast(output_len);
        self.finalized = true;

        return output;
    }
};

pub fn digest(message_digest: MessageDigest, data: []const u8) BoringError!DigestBytes {
    var output = DigestBytes{};
    var output_len: c_uint = output.buffer.len;
    try internal.require_one(sys.EVP_Digest(
        data.ptr,
        data.len,
        &output.buffer,
        &output_len,
        message_digest.ptr,
        null,
    ));

    std.debug.assert(output_len <= output.buffer.len);
    output.len = @intCast(output_len);

    return output;
}

comptime {
    std.debug.assert(DigestBytes.capacity >= 32);
    std.debug.assert(DigestBytes.capacity <= 64);
}
