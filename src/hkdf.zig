const sys = @import("boringssl");

const hash = @import("hash.zig");
const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub fn derive(
    output: []u8,
    digest: hash.MessageDigest,
    secret: []const u8,
    salt: []const u8,
    info: []const u8,
) BoringError!void {
    try internal.require_one(sys.HKDF(
        output.ptr,
        output.len,
        digest.raw(),
        secret.ptr,
        secret.len,
        salt.ptr,
        salt.len,
        info.ptr,
        info.len,
    ));
}

pub fn extract(
    output: []u8,
    digest: hash.MessageDigest,
    secret: []const u8,
    salt: []const u8,
) BoringError!usize {
    var output_len: usize = output.len;
    try internal.require_one(sys.HKDF_extract(
        output.ptr,
        &output_len,
        digest.raw(),
        secret.ptr,
        secret.len,
        salt.ptr,
        salt.len,
    ));

    return output_len;
}

pub fn expand(
    output: []u8,
    digest: hash.MessageDigest,
    prk: []const u8,
    info: []const u8,
) BoringError!void {
    try internal.require_one(sys.HKDF_expand(
        output.ptr,
        output.len,
        digest.raw(),
        prk.ptr,
        prk.len,
        info.ptr,
        info.len,
    ));
}
