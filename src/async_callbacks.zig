const std = @import("std");

const internal = @import("internal.zig");
const ssl_mod = @import("ssl.zig");
const BoringError = internal.BoringError;

pub const OperationState = enum {
    idle,
    pending,
    ready,
    failed,
};

pub fn OperationPoll(comptime Result: type) type {
    return union(enum) {
        start,
        pending,
        ready: Result,
        failed,
    };
}

pub fn Operation(comptime Result: type) type {
    return struct {
        state: OperationState = .idle,
        result: Result = undefined,

        const Self = @This();

        pub fn begin(self: *Self) OperationPoll(Result) {
            return switch (self.state) {
                .idle => idle: {
                    self.state = .pending;
                    break :idle .start;
                },
                .pending => .pending,
                .ready => ready: {
                    const result = self.result;
                    self.state = .idle;
                    break :ready .{ .ready = result };
                },
                .failed => failed: {
                    self.state = .idle;
                    break :failed .failed;
                },
            };
        }

        pub fn complete(self: *Self, result: Result) void {
            std.debug.assert(self.state == .pending);

            self.result = result;
            self.state = .ready;
        }

        pub fn fail(self: *Self) void {
            std.debug.assert(self.state == .pending);

            self.state = .failed;
        }

        pub fn reset(self: *Self) void {
            self.state = .idle;
        }

        pub fn currentState(self: *const Self) OperationState {
            return self.state;
        }

        pub fn isIdle(self: *const Self) bool {
            return self.state == .idle;
        }

        pub fn isPending(self: *const Self) bool {
            return self.state == .pending;
        }

        pub fn isReady(self: *const Self) bool {
            return self.state == .ready;
        }
    };
}

pub const SelectCertificateOperation = Operation(ssl_mod.SelectCertificateResult);
pub const GetSessionOperation = Operation(ssl_mod.GetSessionResult);
pub const VerifyOperation = Operation(ssl_mod.VerifyCallbackResult);

pub fn PrivateKeyOutput(comptime max_len: usize) type {
    comptime {
        std.debug.assert(max_len > 0);
        std.debug.assert(max_len <= @as(usize, ssl_mod.MaxPrivateKeyOperationBytes));
    }

    return struct {
        bytes: [max_len]u8 = undefined,
        len: usize = 0,

        const Self = @This();

        pub fn fromBytes(bytes: []const u8) BoringError!Self {
            var self: Self = .{};
            try self.set(bytes);
            return self;
        }

        pub fn set(self: *Self, bytes: []const u8) BoringError!void {
            if (bytes.len > max_len) return error.Overflow;
            std.debug.assert(bytes.len <= @as(usize, ssl_mod.MaxPrivateKeyOperationBytes));

            @memcpy(self.bytes[0..bytes.len], bytes);
            self.len = bytes.len;
            std.debug.assert(self.len <= max_len);
        }

        pub fn slice(self: *const Self) []const u8 {
            std.debug.assert(self.len <= max_len);

            return self.bytes[0..self.len];
        }

        pub fn writeTo(self: *const Self, output: []u8) ssl_mod.PrivateKeyCallbackResult {
            const bytes = self.slice();
            if (output.len < bytes.len) return .failure;

            @memcpy(output[0..bytes.len], bytes);
            return .{ .success = bytes.len };
        }
    };
}

pub fn PrivateKeyOperation(comptime max_len: usize) type {
    return Operation(PrivateKeyOutput(max_len));
}

pub fn selectCertificateResult(
    poll: OperationPoll(ssl_mod.SelectCertificateResult),
) ssl_mod.SelectCertificateResult {
    return switch (poll) {
        .start => .retry,
        .pending => .retry,
        .ready => |result| result,
        .failed => .failure,
    };
}

pub fn getSessionResult(
    poll: OperationPoll(ssl_mod.GetSessionResult),
) ssl_mod.GetSessionResult {
    return switch (poll) {
        .start => .retry,
        .pending => .retry,
        .ready => |result| result,
        .failed => .none,
    };
}

pub fn verifyCallbackResult(
    poll: OperationPoll(ssl_mod.VerifyCallbackResult),
    failed_alert: ssl_mod.SslAlert,
) ssl_mod.VerifyCallbackResult {
    return switch (poll) {
        .start => .retry,
        .pending => .retry,
        .ready => |result| result,
        .failed => .{ .invalid = failed_alert },
    };
}

pub fn privateKeyResult(
    comptime max_len: usize,
    poll: OperationPoll(PrivateKeyOutput(max_len)),
    output: []u8,
) ssl_mod.PrivateKeyCallbackResult {
    return switch (poll) {
        .start => .retry,
        .pending => .retry,
        .ready => |result| result.writeTo(output),
        .failed => .failure,
    };
}

comptime {
    std.debug.assert(@sizeOf(OperationState) == 1);
}
