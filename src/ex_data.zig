const std = @import("std");

pub fn Index(comptime Container: type, comptime Data: type) type {
    _ = Container;
    _ = Data;

    return struct {
        slot: c_int,

        const Self = @This();

        pub fn fromRaw(slot: c_int) Self {
            std.debug.assert(slot >= 0);

            return .{ .slot = slot };
        }

        pub fn asRaw(self: Self) c_int {
            return self.slot;
        }
    };
}

comptime {
    std.debug.assert(@sizeOf(c_int) >= 4);
}
