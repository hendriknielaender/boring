const std = @import("std");
const boringssl = @import("boringssl");

test "raw BoringSSL surface exposes TLS entry points" {
    try std.testing.expect(@hasDecl(boringssl, "SSL_CTX_new"));
    try std.testing.expect(@hasDecl(boringssl, "SSL_CTX_free"));
    try std.testing.expect(@hasDecl(boringssl, "SSL_new"));
    try std.testing.expect(@hasDecl(boringssl, "SSL_free"));
    try std.testing.expect(@hasDecl(boringssl, "RAND_bytes"));
    try std.testing.expect(@hasDecl(boringssl, "SHA256"));
    try std.testing.expect(@hasDecl(boringssl, "HMAC"));
    try std.testing.expect(@hasDecl(boringssl, "EVP_Digest"));
    try std.testing.expect(@hasDecl(boringssl, "HKDF"));
    try std.testing.expect(@hasDecl(boringssl, "AES_wrap_key"));
    try std.testing.expect(@hasDecl(boringssl, "EVP_AEAD_CTX_seal"));
}
