const std = @import("std");
const sys = @import("boringssl");

const BoringError = @import("internal.zig").BoringError;

pub const OpenSslString = struct {
    ptr: [*c]u8,

    pub fn fromRaw(ptr: [*c]u8) BoringError!OpenSslString {
        if (ptr == null) return error.BoringSSL;

        return .{ .ptr = ptr };
    }

    pub fn deinit(self: *OpenSslString) void {
        if (self.ptr != null) {
            sys.OPENSSL_free(self.ptr);
            self.ptr = null;
        }
    }

    pub fn bytes(self: *const OpenSslString) []const u8 {
        if (self.ptr == null) return "";

        return std.mem.span(self.ptr);
    }

    pub fn span(self: *const OpenSslString) [:0]const u8 {
        if (self.ptr == null) return "";

        return std.mem.span(self.ptr);
    }
};

comptime {
    std.debug.assert(@sizeOf([*c]u8) > 0);
}
