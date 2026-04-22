const std = @import("std");

pub fn FixedBytes(comptime tag: []const u8, comptime len: usize, comptime Error: type) type {
    comptime {
        std.debug.assert(tag.len > 0);
        std.debug.assert(len > 0);
    }

    return struct {
        data: [len]u8,

        const Self = @This();

        pub const bytes_len = len;
        pub const type_tag = tag;

        pub fn fromBytes(input: []const u8) Error!Self {
            if (input.len != len) return error.InvalidArgument;

            var self: Self = undefined;
            @memcpy(self.data[0..], input);

            return self;
        }

        pub fn bytes(self: *const Self) []const u8 {
            return &self.data;
        }

        pub fn mutableBytes(self: *Self) []u8 {
            return &self.data;
        }
    };
}

pub fn BoundedBytes(comptime tag: []const u8, comptime capacity: usize, comptime Error: type) type {
    comptime {
        std.debug.assert(tag.len > 0);
        std.debug.assert(capacity > 0);
    }

    return struct {
        data: [capacity]u8,
        len: usize,

        const Self = @This();

        pub const bytes_capacity = capacity;
        pub const type_tag = tag;

        pub fn fromBytes(input: []const u8) Error!Self {
            if (input.len > capacity) return error.Overflow;

            var self = Self{
                .data = undefined,
                .len = input.len,
            };
            @memcpy(self.data[0..input.len], input);

            return self;
        }

        pub fn bytes(self: *const Self) []const u8 {
            std.debug.assert(self.len <= capacity);

            return self.data[0..self.len];
        }

        pub fn mutableBytes(self: *Self) []u8 {
            std.debug.assert(self.len <= capacity);

            return self.data[0..self.len];
        }
    };
}

test "fixed bytes validate exact input length" {
    const Error = error{ InvalidArgument, Overflow };
    const Key = FixedBytes("test-key", 4, Error);

    const key = try Key.fromBytes("abcd");
    try std.testing.expectEqualStrings("abcd", key.bytes());
    try std.testing.expectError(error.InvalidArgument, Key.fromBytes("abc"));
}

test "bounded bytes validate maximum input length" {
    const Error = error{ InvalidArgument, Overflow };
    const Buffer = BoundedBytes("test-buffer", 4, Error);

    const buffer = try Buffer.fromBytes("abc");
    try std.testing.expectEqualStrings("abc", buffer.bytes());
    try std.testing.expectError(error.Overflow, Buffer.fromBytes("abcde"));
}
