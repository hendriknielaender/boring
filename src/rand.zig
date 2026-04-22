const std = @import("std");
const sys = @import("boringssl");

const BoringError = @import("internal.zig").BoringError;

pub fn bytes(output: []u8) BoringError!void {
    if (output.len == 0) return;

    if (sys.RAND_bytes(output.ptr, output.len) == 1) {
        return;
    } else {
        return error.BoringSSL;
    }
}

comptime {
    std.debug.assert(@sizeOf(usize) >= 4);
}
