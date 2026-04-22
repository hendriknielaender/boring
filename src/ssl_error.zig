const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const ErrorCode = struct {
    value: c_int,

    pub const none = ErrorCode{ .value = sys.SSL_ERROR_NONE };
    pub const zeroReturn = ErrorCode{ .value = sys.SSL_ERROR_ZERO_RETURN };
    pub const wantRead = ErrorCode{ .value = sys.SSL_ERROR_WANT_READ };
    pub const wantWrite = ErrorCode{ .value = sys.SSL_ERROR_WANT_WRITE };
    pub const wantX509Lookup = ErrorCode{ .value = sys.SSL_ERROR_WANT_X509_LOOKUP };
    pub const pendingSession = ErrorCode{ .value = sys.SSL_ERROR_PENDING_SESSION };
    pub const pendingCertificate = ErrorCode{ .value = sys.SSL_ERROR_PENDING_CERTIFICATE };
    pub const wantCertificateVerify = ErrorCode{
        .value = sys.SSL_ERROR_WANT_CERTIFICATE_VERIFY,
    };
    pub const wantPrivateKeyOperation = ErrorCode{
        .value = sys.SSL_ERROR_WANT_PRIVATE_KEY_OPERATION,
    };
    pub const pendingTicket = ErrorCode{ .value = sys.SSL_ERROR_PENDING_TICKET };
    pub const syscall = ErrorCode{ .value = sys.SSL_ERROR_SYSCALL };
    pub const ssl = ErrorCode{ .value = sys.SSL_ERROR_SSL };

    pub fn fromRaw(value: c_int) ErrorCode {
        std.debug.assert(value >= 0);
        std.debug.assert(value < 64);

        return .{ .value = value };
    }

    pub fn raw(self: ErrorCode) c_int {
        return self.value;
    }

    pub fn description(self: ErrorCode) ?[:0]const u8 {
        const msg = sys.SSL_error_description(self.value) orelse return null;

        return std.mem.span(msg);
    }
};

pub const Error = struct {
    error_code: ErrorCode,

    pub fn fromCode(error_code: ErrorCode) Error {
        return .{ .error_code = error_code };
    }

    pub fn code(self: Error) ErrorCode {
        return self.error_code;
    }

    pub fn wouldBlock(self: Error) bool {
        return self.error_code.value == sys.SSL_ERROR_WANT_READ or
            self.error_code.value == sys.SSL_ERROR_WANT_WRITE or
            self.error_code.value == sys.SSL_ERROR_WANT_X509_LOOKUP or
            self.error_code.value == sys.SSL_ERROR_PENDING_SESSION or
            self.error_code.value == sys.SSL_ERROR_PENDING_CERTIFICATE or
            self.error_code.value == sys.SSL_ERROR_WANT_PRIVATE_KEY_OPERATION or
            self.error_code.value == sys.SSL_ERROR_WANT_CERTIFICATE_VERIFY or
            self.error_code.value == sys.SSL_ERROR_PENDING_TICKET;
    }

    pub fn description(self: Error) ?[:0]const u8 {
        return self.error_code.description();
    }
};

pub const HandshakeError = error{
    SetupFailure,
    Failure,
    WouldBlock,
};

comptime {
    std.debug.assert(sys.SSL_ERROR_NONE == 0);
    std.debug.assert(sys.SSL_ERROR_SSL > 0);
}
