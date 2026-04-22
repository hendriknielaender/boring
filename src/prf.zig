const std = @import("std");
const sys = @import("boringssl");

const hash_mod = @import("hash.zig");
const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub fn tls1Prf(
    digest: hash_mod.MessageDigest,
    output: []u8,
    secret: []const u8,
    label: []const u8,
    seed: []const u8,
) BoringError!void {
    if (output.len == 0) return error.InvalidArgument;

    const result = CRYPTO_tls1_prf(
        digest.raw(),
        output.ptr,
        output.len,
        secret.ptr,
        secret.len,
        label.ptr,
        label.len,
        seed.ptr,
        seed.len,
        null,
        0,
    );
    try internal.require_one(result);
}

extern fn CRYPTO_tls1_prf(
    digest: *const sys.EVP_MD,
    out: [*]u8,
    out_len: usize,
    secret: [*]const u8,
    secret_len: usize,
    label: [*]const u8,
    label_len: usize,
    seed: [*]const u8,
    seed_len: usize,
    extra_seed: ?*const anyopaque,
    extra_seed_len: usize,
) c_int;

comptime {
    std.debug.assert(@sizeOf(*const sys.EVP_MD) > 0);
}
