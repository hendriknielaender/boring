const std = @import("std");
const sys = @import("boringssl");

pub fn constantTimeEq(a: []const u8, b: []const u8) bool {
    std.debug.assert(a.len == b.len);

    return sys.CRYPTO_memcmp(a.ptr, b.ptr, a.len) == 0;
}

comptime {
    std.debug.assert(@sizeOf(usize) >= 4);
}
