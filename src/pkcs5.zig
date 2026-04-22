const std = @import("std");
const sys = @import("boringssl");

const hash = @import("hash.zig");
const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub fn pbkdf2Hmac(
    output: []u8,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    digest: hash.MessageDigest,
) BoringError!void {
    try internal.require_non_empty(output);
    try internal.require_one(sys.PKCS5_PBKDF2_HMAC(
        password.ptr,
        password.len,
        salt.ptr,
        salt.len,
        iterations,
        digest.raw(),
        output.len,
        output.ptr,
    ));
}

pub fn pbkdf2HmacSha1(
    output: []u8,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
) BoringError!void {
    try internal.require_non_empty(output);
    try internal.require_one(sys.PKCS5_PBKDF2_HMAC_SHA1(
        password.ptr,
        password.len,
        salt.ptr,
        salt.len,
        iterations,
        output.len,
        output.ptr,
    ));
}

pub fn scrypt(
    output: []u8,
    password: []const u8,
    salt: []const u8,
    n: u64,
    r: u64,
    p: u64,
    max_mem: usize,
) BoringError!void {
    try internal.require_non_empty(output);
    try internal.require_one(sys.EVP_PBE_scrypt(
        password.ptr,
        password.len,
        salt.ptr,
        salt.len,
        n,
        r,
        p,
        max_mem,
        output.ptr,
        output.len,
    ));
}

comptime {
    std.debug.assert(@sizeOf(u64) == 8);
}
