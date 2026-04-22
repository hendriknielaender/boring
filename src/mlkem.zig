const std = @import("std");
const fixed_bytes = @import("fixed_bytes");
const sys = @import("boringssl");

const BoringError = error{
    BoringSSL,
    InvalidArgument,
    Overflow,
};

pub const PublicKeyBytes768: usize = sys.KYBER_PUBLIC_KEY_BYTES;
pub const CiphertextBytes768: usize = sys.KYBER_CIPHERTEXT_BYTES;
pub const SharedSecretBytes: usize = sys.KYBER_SHARED_SECRET_BYTES;

pub const Kyber768PublicKey = struct {
    raw: sys.KYBER_public_key,

    pub fn fromBytes(bytes: []const u8) BoringError!Kyber768PublicKey {
        if (bytes.len != PublicKeyBytes768) return error.InvalidArgument;

        var cbs = sys.CBS{
            .data = bytes.ptr,
            .len = bytes.len,
        };
        var self: Kyber768PublicKey = undefined;
        try require_one(sys.KYBER_parse_public_key(&self.raw, &cbs));
        if (cbs.len != 0) return error.BoringSSL;

        return self;
    }

    pub fn toBytes(self: *const Kyber768PublicKey, output: []u8) BoringError!usize {
        if (output.len < PublicKeyBytes768) return error.Overflow;

        var cbb: sys.CBB = undefined;
        try require_one(sys.CBB_init_fixed(&cbb, output.ptr, PublicKeyBytes768));
        try require_one(sys.KYBER_marshal_public_key(&cbb, &self.raw));

        const finished_len = sys.CBB_len(&cbb);
        if (finished_len > PublicKeyBytes768) return error.Overflow;

        return finished_len;
    }

    pub fn encapsulate(self: *const Kyber768PublicKey) struct { Ciphertext768, SharedSecret } {
        var ciphertext: [CiphertextBytes768]u8 = undefined;
        var shared_secret: [SharedSecretBytes]u8 = undefined;

        sys.KYBER_encap(&ciphertext, &shared_secret, &self.raw);

        return .{
            .{ .data = ciphertext },
            .{ .data = shared_secret },
        };
    }
};

pub const Ciphertext768 = fixed_bytes.FixedBytes(
    "kyber768-ciphertext",
    CiphertextBytes768,
    BoringError,
);
pub const SharedSecret = fixed_bytes.FixedBytes(
    "kyber-shared-secret",
    SharedSecretBytes,
    BoringError,
);

pub const Kyber768PrivateKey = struct {
    raw: sys.KYBER_private_key,

    pub fn generate() struct { Kyber768PublicKey, Kyber768PrivateKey } {
        var public_bytes: [PublicKeyBytes768]u8 = undefined;
        var private_key: Kyber768PrivateKey = undefined;

        sys.KYBER_generate_key(&public_bytes, &private_key.raw);

        var public_key: Kyber768PublicKey = undefined;
        sys.KYBER_public_from_private(&public_key.raw, &private_key.raw);

        return .{ public_key, private_key };
    }

    pub fn decapsulate(
        self: *const Kyber768PrivateKey,
        ciphertext: *const Ciphertext768,
    ) SharedSecret {
        var shared_secret: [SharedSecretBytes]u8 = undefined;

        sys.KYBER_decap(&shared_secret, &ciphertext.data, &self.raw);

        return .{ .data = shared_secret };
    }

    pub fn cleanse(self: *Kyber768PrivateKey) void {
        sys.OPENSSL_cleanse(&self.raw, @sizeOf(sys.KYBER_private_key));
    }
};

fn require_one(result: c_int) BoringError!void {
    if (result == 1) return;

    return error.BoringSSL;
}

comptime {
    std.debug.assert(PublicKeyBytes768 == 1184);
    std.debug.assert(CiphertextBytes768 == 1088);
    std.debug.assert(SharedSecretBytes == 32);
}
