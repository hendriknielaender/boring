const std = @import("std");
const sys = @import("boringssl");

const BoringError = @import("internal.zig").BoringError;
const hash = @import("hash.zig");
const internal = @import("internal.zig");
const sha = @import("sha.zig");

pub const SHA256DigestLength: usize = sha.SHA256DigestLength;

pub fn sha256(key: []const u8, data: []const u8) BoringError![SHA256DigestLength]u8 {
    return fixed(hash.MessageDigest.sha256(), key, data, SHA256DigestLength);
}

pub fn fixed(
    digest: hash.MessageDigest,
    key: []const u8,
    data: []const u8,
    comptime output_len: usize,
) BoringError![output_len]u8 {
    std.debug.assert(output_len <= sys.EVP_MAX_MD_SIZE);

    var output: [output_len]u8 = undefined;
    var output_len_c: c_uint = 0;
    const result = sys.HMAC(
        digest.raw(),
        pointer_or_null(key),
        key.len,
        data.ptr,
        data.len,
        &output,
        &output_len_c,
    );

    if (result == null) return error.BoringSSL;

    std.debug.assert(output_len_c == output.len);
    return output;
}

pub const HmacCtxRef = struct {
    ptr: *sys.HMAC_CTX,

    pub fn init(self: *HmacCtxRef, key: []const u8, digest: hash.MessageDigest) BoringError!void {
        try internal.require_one(sys.HMAC_Init_ex(
            self.ptr,
            pointer_or_null(key),
            key.len,
            digest.raw(),
            null,
        ));
    }
};

fn pointer_or_null(bytes: []const u8) ?*const anyopaque {
    if (bytes.len > 0) {
        return bytes.ptr;
    } else {
        return null;
    }
}

comptime {
    std.debug.assert(SHA256DigestLength == 32);
}
