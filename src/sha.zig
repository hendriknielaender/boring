const std = @import("std");
const sys = @import("boringssl");

pub const SHA256DigestLength: usize = sys.SHA256_DIGEST_LENGTH;

pub fn sha256(data: []const u8) [SHA256DigestLength]u8 {
    var output: [SHA256DigestLength]u8 = undefined;
    const result = sys.SHA256(data.ptr, data.len, &output);

    std.debug.assert(result != null);

    return output;
}

comptime {
    std.debug.assert(SHA256DigestLength == 32);
}
