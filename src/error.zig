const std = @import("std");
const sys = @import("boringssl");

const BoringError = @import("internal.zig").BoringError;

pub const ErrorStack = struct {
    pub const capacity: u8 = 32;

    errors_buffer: [capacity]Error = undefined,
    errors_count: u8 = 0,
    overflow: bool = false,

    pub fn get() ErrorStack {
        var stack = ErrorStack{};

        while (stack.errors_count < capacity) {
            const code = sys.ERR_get_error();
            if (code == 0) return stack;

            const index: usize = stack.errors_count;
            stack.errors_buffer[index] = .{ .code = code };
            stack.errors_count += 1;
        }

        if (sys.ERR_get_error() != 0) {
            stack.overflow = true;
            clear();
        }

        return stack;
    }

    pub fn clear() void {
        sys.ERR_clear_error();
    }

    pub fn len(self: ErrorStack) u8 {
        return self.errors_count;
    }

    pub fn isEmpty(self: ErrorStack) bool {
        return self.errors_count == 0;
    }

    pub fn didOverflow(self: ErrorStack) bool {
        return self.overflow;
    }

    pub fn at(self: *const ErrorStack, index: u8) ?Error {
        if (index < self.errors_count) {
            return self.errors_buffer[index];
        } else {
            return null;
        }
    }

    pub fn last(self: *const ErrorStack) ?Error {
        if (self.errors_count > 0) {
            return self.errors_buffer[self.errors_count - 1];
        } else {
            return null;
        }
    }
};

pub const Error = struct {
    code: u32,

    pub fn raw(self: Error) u32 {
        return self.code;
    }

    pub fn library(self: Error) ?[]const u8 {
        return c_string(sys.ERR_lib_error_string(self.code));
    }

    pub fn reason(self: Error) ?[]const u8 {
        return c_string(sys.ERR_reason_error_string(self.code));
    }
};

fn c_string(pointer: [*c]const u8) ?[]const u8 {
    if (pointer == null) {
        return null;
    } else {
        return std.mem.span(pointer);
    }
}

pub fn get() BoringError!ErrorStack {
    const stack = ErrorStack.get();
    if (stack.isEmpty()) {
        return error.BoringSSL;
    } else {
        return stack;
    }
}

comptime {
    std.debug.assert(ErrorStack.capacity >= 8);
    std.debug.assert(ErrorStack.capacity <= std.math.maxInt(u8));
}
