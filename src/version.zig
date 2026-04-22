const std = @import("std");
const sys = @import("boringssl");

pub fn text() []const u8 {
    const pointer = sys.OpenSSL_version(sys.OPENSSL_VERSION);

    std.debug.assert(pointer != null);
    return std.mem.span(pointer);
}

comptime {
    std.debug.assert(@sizeOf(usize) >= 4);
}
