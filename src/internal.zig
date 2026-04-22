const std = @import("std");

pub const BoringError = error{
    BoringSSL,
    Closed,
    InvalidArgument,
    OutOfMemory,
    Overflow,
    PendingCertificate,
    PendingSession,
    PendingTicket,
    Syscall,
    WantAccept,
    WantCertificateVerify,
    WantConnect,
    WantPrivateKeyOperation,
    WantRead,
    WantRenegotiate,
    WantWrite,
    WantX509Lookup,
    ZeroReturn,
};

pub fn require_one(result: c_int) BoringError!void {
    if (result == 1) return;

    return error.BoringSSL;
}

pub fn require_zero(result: c_int) BoringError!void {
    if (result == 0) return;

    return error.BoringSSL;
}

pub fn c_int_len(len: usize) BoringError!c_int {
    if (len <= std.math.maxInt(c_int)) {
        return @intCast(len);
    } else {
        return error.Overflow;
    }
}

pub fn c_uint_len(len: usize) BoringError!c_uint {
    if (len <= std.math.maxInt(c_uint)) {
        return @intCast(len);
    } else {
        return error.Overflow;
    }
}

pub fn require_non_empty(bytes: []const u8) BoringError!void {
    if (bytes.len > 0) return;

    return error.InvalidArgument;
}

/// State for password callbacks when loading encrypted keys.
pub const PasswordCallbackState = struct {
    password: []const u8,
};

/// C-compatible password callback that copies password from state into buffer.
pub fn password_callback(
    buf: [*c]u8,
    size: c_int,
    _rwflag: c_int,
    userdata: ?*anyopaque,
) callconv(.c) c_int {
    _ = _rwflag;
    if (buf == null) return 0;
    if (userdata == null) return 0;

    const state: *PasswordCallbackState = @ptrCast(@alignCast(userdata.?));
    const limit = @min(state.password.len, @as(usize, @intCast(size)));
    if (limit == 0) return 0;

    @memcpy(buf.?[0..limit], state.password[0..limit]);
    return @intCast(limit);
}
