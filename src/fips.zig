const std = @import("std");
const sys = @import("boringssl");

pub fn enabled() bool {
    return sys.FIPS_mode() != 0;
}

comptime {
    std.debug.assert(@sizeOf(c_int) >= 4);
}
