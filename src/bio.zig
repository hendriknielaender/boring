const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const MemBio = struct {
    ptr: ?*sys.BIO,

    pub fn init() BoringError!MemBio {
        const bio = sys.BIO_new(sys.BIO_s_mem()) orelse return error.BoringSSL;

        return .{ .ptr = bio };
    }

    pub fn initConstSlice(buffer: []const u8) BoringError!MemBio {
        const len = std.math.cast(sys.ossl_ssize_t, buffer.len) orelse {
            return error.Overflow;
        };
        const bio = sys.BIO_new_mem_buf(buffer.ptr, len) orelse return error.BoringSSL;

        return .{ .ptr = bio };
    }

    pub fn deinit(self: *MemBio) void {
        if (self.ptr) |bio| {
            sys.BIO_free_all(bio);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const MemBio) BoringError!*sys.BIO {
        return self.ptr orelse error.Closed;
    }

    pub fn pending(self: *const MemBio) BoringError!usize {
        return sys.BIO_pending(try self.raw());
    }

    pub fn bytes(self: *const MemBio) BoringError![]const u8 {
        const bio = try self.raw();
        var data: [*c]u8 = null;
        const len = sys.BIO_get_mem_data(bio, &data);
        if (len < 0) return error.BoringSSL;
        if (len == 0) return "";
        if (data == null) return error.BoringSSL;

        return data[0..@intCast(len)];
    }

    pub fn writeAll(self: *MemBio, input: []const u8) BoringError!void {
        const bio = try self.raw();
        try internal.require_one(sys.BIO_write_all(bio, input.ptr, input.len));
    }

    pub fn write(self: *MemBio, input: []const u8) BoringError!usize {
        const bio = try self.raw();
        const result = sys.BIO_write(
            bio,
            input.ptr,
            try internal.c_int_len(input.len),
        );
        if (result < 0) return error.BoringSSL;

        return @intCast(result);
    }

    pub fn read(self: *MemBio, output: []u8) BoringError!usize {
        const bio = try self.raw();
        const result = sys.BIO_read(
            bio,
            output.ptr,
            try internal.c_int_len(output.len),
        );
        if (result < 0) return error.BoringSSL;

        return @intCast(result);
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.BIO) > 0);
}
