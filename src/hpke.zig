const std = @import("std");
const fixed_bytes = @import("fixed_bytes");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const MaxPublicKeyBytes: usize = 32 + 2;
pub const MaxPrivateKeyBytes: usize = 32;
pub const MaxEncapsulatedKeyBytes: usize = 32 + 2;
pub const MaxSharedSecretBytes: usize = 32;

pub const Kem = struct {
    ptr: *const sys.EVP_HPKE_KEM,

    pub fn x25519HkdfSha256() Kem {
        return .{ .ptr = sys.EVP_hpke_x25519_hkdf_sha256() orelse unreachable };
    }

    pub fn raw(self: Kem) *const sys.EVP_HPKE_KEM {
        return self.ptr;
    }
};

pub const Kdf = struct {
    ptr: *const sys.EVP_HPKE_KDF,

    pub fn hkdfSha256() Kdf {
        return .{ .ptr = sys.EVP_hpke_hkdf_sha256() orelse unreachable };
    }

    pub fn raw(self: Kdf) *const sys.EVP_HPKE_KDF {
        return self.ptr;
    }
};

pub const AeadId = struct {
    ptr: *const sys.EVP_HPKE_AEAD,

    pub fn aes128Gcm() AeadId {
        return .{ .ptr = sys.EVP_hpke_aes_128_gcm() orelse unreachable };
    }

    pub fn aes256Gcm() AeadId {
        return .{ .ptr = sys.EVP_hpke_aes_256_gcm() orelse unreachable };
    }

    pub fn chacha20Poly1305() AeadId {
        return .{ .ptr = sys.EVP_hpke_chacha20_poly1305() orelse unreachable };
    }

    pub fn raw(self: AeadId) *const sys.EVP_HPKE_AEAD {
        return self.ptr;
    }
};

pub const HpkeKey = struct {
    ptr: ?*sys.EVP_HPKE_KEY,

    pub fn init() BoringError!HpkeKey {
        const raw_ptr = sys.EVP_HPKE_KEY_new() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn initWithPrivateKey(kem_arg: Kem, private_key: []const u8) BoringError!HpkeKey {
        var self = try init();
        errdefer self.deinit();

        try internal.require_one(sys.EVP_HPKE_KEY_init(
            try self.raw(),
            kem_arg.raw(),
            private_key.ptr,
            private_key.len,
        ));

        return self;
    }

    pub fn generate(kem_arg: Kem) BoringError!HpkeKey {
        var self = try init();
        errdefer self.deinit();

        try internal.require_one(sys.EVP_HPKE_KEY_generate(try self.raw(), kem_arg.raw()));

        return self;
    }

    pub fn deinit(self: *HpkeKey) void {
        if (self.ptr) |raw_ptr| {
            sys.EVP_HPKE_KEY_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const HpkeKey) BoringError!*sys.EVP_HPKE_KEY {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *HpkeKey) BoringError!*sys.EVP_HPKE_KEY {
        const raw_ptr = try self.raw();
        self.ptr = null;

        return raw_ptr;
    }

    pub fn publicKey(self: *const HpkeKey, output: []u8) BoringError!usize {
        if (output.len == 0) return error.InvalidArgument;

        var out_len: usize = 0;
        try internal.require_one(sys.EVP_HPKE_KEY_public_key(
            try self.raw(),
            output.ptr,
            &out_len,
            output.len,
        ));

        if (out_len > output.len) return error.Overflow;

        return out_len;
    }

    pub fn privateKey(self: *const HpkeKey, output: []u8) BoringError!usize {
        if (output.len == 0) return error.InvalidArgument;

        var out_len: usize = 0;
        try internal.require_one(sys.EVP_HPKE_KEY_private_key(
            try self.raw(),
            output.ptr,
            &out_len,
            output.len,
        ));

        if (out_len > output.len) return error.Overflow;

        return out_len;
    }

    pub fn kem(self: *const HpkeKey) Kem {
        return .{ .ptr = sys.EVP_HPKE_KEY_kem(try self.raw()) };
    }
};

pub const HpkeContext = struct {
    ptr: ?*sys.EVP_HPKE_CTX,

    pub fn setupSender(
        kem: Kem,
        kdf: Kdf,
        aead: AeadId,
        recipient_public_key: []const u8,
        info: []const u8,
    ) BoringError!struct { HpkeContext, EncapsulatedKey } {
        var self = try init();
        errdefer self.deinit();

        var enc: [MaxEncapsulatedKeyBytes]u8 = undefined;
        var enc_len: usize = 0;
        try internal.require_one(sys.EVP_HPKE_CTX_setup_sender(
            try self.raw(),
            &enc,
            &enc_len,
            enc.len,
            kem.raw(),
            kdf.raw(),
            aead.raw(),
            recipient_public_key.ptr,
            recipient_public_key.len,
            info.ptr,
            info.len,
        ));

        return .{ self, .{ .data = enc, .len = enc_len } };
    }

    pub fn setupRecipient(
        kdf: Kdf,
        aead: AeadId,
        key: *const HpkeKey,
        encapsulated_key: []const u8,
        info: []const u8,
    ) BoringError!HpkeContext {
        var self = try init();
        errdefer self.deinit();

        try internal.require_one(sys.EVP_HPKE_CTX_setup_recipient(
            try self.raw(),
            try key.raw(),
            kdf.raw(),
            aead.raw(),
            encapsulated_key.ptr,
            encapsulated_key.len,
            info.ptr,
            info.len,
        ));

        return self;
    }

    fn init() BoringError!HpkeContext {
        const raw_ptr = sys.EVP_HPKE_CTX_new() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *HpkeContext) void {
        if (self.ptr) |raw_ptr| {
            sys.EVP_HPKE_CTX_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const HpkeContext) BoringError!*sys.EVP_HPKE_CTX {
        return self.ptr orelse error.Closed;
    }

    pub fn seal(
        self: *HpkeContext,
        output: []u8,
        plaintext: []const u8,
        aad: []const u8,
    ) BoringError!usize {
        if (output.len == 0) return error.InvalidArgument;

        var out_len: usize = output.len;
        try internal.require_one(sys.EVP_HPKE_CTX_seal(
            try self.raw(),
            output.ptr,
            &out_len,
            out_len,
            plaintext.ptr,
            plaintext.len,
            aad.ptr,
            aad.len,
        ));

        if (out_len > output.len) return error.Overflow;

        return out_len;
    }

    pub fn open(
        self: *HpkeContext,
        output: []u8,
        ciphertext: []const u8,
        aad: []const u8,
    ) BoringError!usize {
        if (output.len == 0) return error.InvalidArgument;

        var out_len: usize = output.len;
        try internal.require_one(sys.EVP_HPKE_CTX_open(
            try self.raw(),
            output.ptr,
            &out_len,
            out_len,
            ciphertext.ptr,
            ciphertext.len,
            aad.ptr,
            aad.len,
        ));

        if (out_len > output.len) return error.Overflow;

        return out_len;
    }

    pub fn exportSecret(self: *HpkeContext, output: []u8, context: []const u8) BoringError!void {
        try internal.require_one(sys.EVP_HPKE_CTX_export(
            try self.raw(),
            output.ptr,
            output.len,
            context.ptr,
            context.len,
        ));
    }
};

pub const EncapsulatedKey = fixed_bytes.BoundedBytes(
    "hpke-encapsulated-key",
    MaxEncapsulatedKeyBytes,
    BoringError,
);

comptime {
    std.debug.assert(MaxPublicKeyBytes >= 32);
    std.debug.assert(MaxPrivateKeyBytes >= 32);
    std.debug.assert(MaxSharedSecretBytes >= 32);
}
