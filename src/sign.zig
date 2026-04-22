const std = @import("std");
const sys = @import("boringssl");

const error_mod = @import("error.zig");
const hash = @import("hash.zig");
const internal = @import("internal.zig");
const pkey_mod = @import("pkey.zig");
const rsa_mod = @import("rsa.zig");
const BoringError = internal.BoringError;

pub const RsaPssSaltLength = struct {
    raw_value: c_int,

    pub const digestLength = custom(-1);
    pub const maximumLength = custom(-2);

    pub fn custom(value: c_int) RsaPssSaltLength {
        return .{ .raw_value = value };
    }

    pub fn raw(self: RsaPssSaltLength) c_int {
        return self.raw_value;
    }
};

pub const Signer = struct {
    md_ctx: ?*sys.EVP_MD_CTX,
    pkey_ctx: ?*sys.EVP_PKEY_CTX,

    pub fn init(digest: hash.MessageDigest, pkey: *const pkey_mod.PKey) BoringError!Signer {
        return init_signer_with_optional_digest(digest.raw(), pkey);
    }

    pub fn initWithoutDigest(pkey: *const pkey_mod.PKey) BoringError!Signer {
        return init_signer_with_optional_digest(null, pkey);
    }

    pub fn deinit(self: *Signer) void {
        if (self.md_ctx) |ctx| {
            sys.EVP_MD_CTX_free(ctx);
            self.md_ctx = null;
            self.pkey_ctx = null;
        }
    }

    pub fn rsaPadding(self: *const Signer) BoringError!rsa_mod.Padding {
        var padding: c_int = 0;
        try internal.require_one(sys.EVP_PKEY_CTX_get_rsa_padding(
            try self.raw_pkey_context(),
            &padding,
        ));

        return rsa_mod.Padding.fromRaw(padding);
    }

    pub fn setRsaPadding(self: *Signer, padding: rsa_mod.Padding) BoringError!void {
        try internal.require_one(sys.EVP_PKEY_CTX_set_rsa_padding(
            try self.raw_pkey_context(),
            padding.raw(),
        ));
    }

    pub fn setRsaPssSaltLength(self: *Signer, len: RsaPssSaltLength) BoringError!void {
        try internal.require_one(sys.EVP_PKEY_CTX_set_rsa_pss_saltlen(
            try self.raw_pkey_context(),
            len.raw(),
        ));
    }

    pub fn setRsaMgf1Digest(self: *Signer, digest: hash.MessageDigest) BoringError!void {
        try internal.require_one(sys.EVP_PKEY_CTX_set_rsa_mgf1_md(
            try self.raw_pkey_context(),
            digest.raw(),
        ));
    }

    pub fn update(self: *Signer, input: []const u8) BoringError!void {
        try internal.require_one(sys.EVP_DigestSignUpdate(
            try self.raw_digest_context(),
            input.ptr,
            input.len,
        ));
    }

    pub fn signatureLength(self: *Signer) BoringError!usize {
        var len: usize = 0;
        try internal.require_one(sys.EVP_DigestSignFinal(
            try self.raw_digest_context(),
            null,
            &len,
        ));

        return len;
    }

    pub fn sign(self: *Signer, output: []u8) BoringError!usize {
        var len = output.len;
        try internal.require_one(sys.EVP_DigestSignFinal(
            try self.raw_digest_context(),
            output.ptr,
            &len,
        ));

        return len;
    }

    pub fn signOneShot(
        self: *Signer,
        output: []u8,
        input: []const u8,
    ) BoringError!usize {
        var len = output.len;
        try internal.require_one(sys.EVP_DigestSign(
            try self.raw_digest_context(),
            output.ptr,
            &len,
            input.ptr,
            input.len,
        ));

        return len;
    }

    fn raw_digest_context(self: *const Signer) BoringError!*sys.EVP_MD_CTX {
        return self.md_ctx orelse error.Closed;
    }

    fn raw_pkey_context(self: *const Signer) BoringError!*sys.EVP_PKEY_CTX {
        return self.pkey_ctx orelse error.Closed;
    }
};

pub const Verifier = struct {
    md_ctx: ?*sys.EVP_MD_CTX,
    pkey_ctx: ?*sys.EVP_PKEY_CTX,

    pub fn init(digest: hash.MessageDigest, pkey: *const pkey_mod.PKey) BoringError!Verifier {
        return init_verifier_with_optional_digest(digest.raw(), pkey);
    }

    pub fn initWithoutDigest(pkey: *const pkey_mod.PKey) BoringError!Verifier {
        return init_verifier_with_optional_digest(null, pkey);
    }

    pub fn deinit(self: *Verifier) void {
        if (self.md_ctx) |ctx| {
            sys.EVP_MD_CTX_free(ctx);
            self.md_ctx = null;
            self.pkey_ctx = null;
        }
    }

    pub fn rsaPadding(self: *const Verifier) BoringError!rsa_mod.Padding {
        var padding: c_int = 0;
        try internal.require_one(sys.EVP_PKEY_CTX_get_rsa_padding(
            try self.raw_pkey_context(),
            &padding,
        ));

        return rsa_mod.Padding.fromRaw(padding);
    }

    pub fn setRsaPadding(self: *Verifier, padding: rsa_mod.Padding) BoringError!void {
        try internal.require_one(sys.EVP_PKEY_CTX_set_rsa_padding(
            try self.raw_pkey_context(),
            padding.raw(),
        ));
    }

    pub fn setRsaPssSaltLength(self: *Verifier, len: RsaPssSaltLength) BoringError!void {
        try internal.require_one(sys.EVP_PKEY_CTX_set_rsa_pss_saltlen(
            try self.raw_pkey_context(),
            len.raw(),
        ));
    }

    pub fn setRsaMgf1Digest(self: *Verifier, digest: hash.MessageDigest) BoringError!void {
        try internal.require_one(sys.EVP_PKEY_CTX_set_rsa_mgf1_md(
            try self.raw_pkey_context(),
            digest.raw(),
        ));
    }

    pub fn update(self: *Verifier, input: []const u8) BoringError!void {
        try internal.require_one(sys.EVP_DigestVerifyUpdate(
            try self.raw_digest_context(),
            input.ptr,
            input.len,
        ));
    }

    pub fn verify(self: *Verifier, signature: []const u8) BoringError!bool {
        return verify_result(sys.EVP_DigestVerifyFinal(
            try self.raw_digest_context(),
            signature.ptr,
            signature.len,
        ));
    }

    pub fn verifyOneShot(
        self: *Verifier,
        signature: []const u8,
        input: []const u8,
    ) BoringError!bool {
        return verify_result(sys.EVP_DigestVerify(
            try self.raw_digest_context(),
            signature.ptr,
            signature.len,
            input.ptr,
            input.len,
        ));
    }

    fn raw_digest_context(self: *const Verifier) BoringError!*sys.EVP_MD_CTX {
        return self.md_ctx orelse error.Closed;
    }

    fn raw_pkey_context(self: *const Verifier) BoringError!*sys.EVP_PKEY_CTX {
        return self.pkey_ctx orelse error.Closed;
    }
};

fn init_signer_with_optional_digest(
    digest: ?*const sys.EVP_MD,
    pkey: *const pkey_mod.PKey,
) BoringError!Signer {
    const ctx = sys.EVP_MD_CTX_new() orelse return error.BoringSSL;
    var pkey_ctx: ?*sys.EVP_PKEY_CTX = null;
    const result = sys.EVP_DigestSignInit(ctx, &pkey_ctx, digest, null, try pkey.raw());
    if (result != 1) {
        sys.EVP_MD_CTX_free(ctx);
        return error.BoringSSL;
    }

    return .{
        .md_ctx = ctx,
        .pkey_ctx = pkey_ctx orelse return error.BoringSSL,
    };
}

fn init_verifier_with_optional_digest(
    digest: ?*const sys.EVP_MD,
    pkey: *const pkey_mod.PKey,
) BoringError!Verifier {
    const ctx = sys.EVP_MD_CTX_new() orelse return error.BoringSSL;
    var pkey_ctx: ?*sys.EVP_PKEY_CTX = null;
    const result = sys.EVP_DigestVerifyInit(ctx, &pkey_ctx, digest, null, try pkey.raw());
    if (result != 1) {
        sys.EVP_MD_CTX_free(ctx);
        return error.BoringSSL;
    }

    return .{
        .md_ctx = ctx,
        .pkey_ctx = pkey_ctx orelse return error.BoringSSL,
    };
}

fn verify_result(result: c_int) BoringError!bool {
    if (result == 1) return true;
    if (result == 0) {
        error_mod.ErrorStack.clear();
        return false;
    }

    return error.BoringSSL;
}

comptime {
    std.debug.assert(@sizeOf(c_int) >= 4);
}
