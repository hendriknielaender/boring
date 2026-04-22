const std = @import("std");
const sys = @import("boringssl");

const bio = @import("bio.zig");
const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const ConfMethod = struct {
    ptr: ?*anyopaque,

    pub fn fromRaw(ptr: ?*anyopaque) ConfMethod {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: ConfMethod) ?*anyopaque {
        return self.ptr;
    }
};

pub const Conf = struct {
    ptr: ?*sys.CONF,

    pub fn init(method: ?ConfMethod) BoringError!Conf {
        const raw_method = if (method) |value| value.raw() else null;
        const conf = sys.NCONF_new(raw_method) orelse return error.BoringSSL;

        return .{ .ptr = conf };
    }

    pub fn deinit(self: *Conf) void {
        if (self.ptr) |conf| {
            sys.NCONF_free(conf);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const Conf) BoringError!*sys.CONF {
        return self.ptr orelse error.Closed;
    }

    pub fn loadBio(self: *Conf, input: *bio.MemBio) BoringError!void {
        var error_line: c_long = 0;
        try internal.require_one(sys.NCONF_load_bio(
            try self.raw(),
            try input.raw(),
            &error_line,
        ));
    }

    pub fn getString(
        self: *const Conf,
        section: [:0]const u8,
        name: [:0]const u8,
    ) BoringError!?[:0]const u8 {
        const value = sys.NCONF_get_string(try self.raw(), section.ptr, name.ptr);
        if (value == null) return null;

        return std.mem.span(value);
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.CONF) > 0);
}
