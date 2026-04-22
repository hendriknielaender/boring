const std = @import("std");
const fixed_bytes = @import("fixed_bytes");
const sys = @import("boringssl");

const BoringError = error{
    BoringSSL,
    InvalidArgument,
    Overflow,
};

pub const PrivateKeySeedBytes: usize = sys.MLKEM_SEED_BYTES;
pub const SharedSecretBytes: usize = sys.MLKEM_SHARED_SECRET_BYTES;
pub const PublicKeyBytes768: usize = sys.MLKEM768_PUBLIC_KEY_BYTES;
pub const PublicKeyBytes1024: usize = sys.MLKEM1024_PUBLIC_KEY_BYTES;
pub const CiphertextBytes768: usize = sys.MLKEM768_CIPHERTEXT_BYTES;
pub const CiphertextBytes1024: usize = sys.MLKEM1024_CIPHERTEXT_BYTES;

pub const PrivateKeySeed = [PrivateKeySeedBytes]u8;

pub const Algorithm = enum {
    mlKem768,
    mlKem1024,

    pub fn publicKeyBytes(self: Algorithm) usize {
        return switch (self) {
            .mlKem768 => PublicKeyBytes768,
            .mlKem1024 => PublicKeyBytes1024,
        };
    }

    pub fn ciphertextBytes(self: Algorithm) usize {
        return switch (self) {
            .mlKem768 => CiphertextBytes768,
            .mlKem1024 => CiphertextBytes1024,
        };
    }
};

pub const SharedSecret = fixed_bytes.FixedBytes(
    "mlkem-shared-secret",
    SharedSecretBytes,
    BoringError,
);
pub const MlKem768Ciphertext = fixed_bytes.FixedBytes(
    "mlkem768-ciphertext",
    CiphertextBytes768,
    BoringError,
);
pub const MlKem1024Ciphertext = fixed_bytes.FixedBytes(
    "mlkem1024-ciphertext",
    CiphertextBytes1024,
    BoringError,
);

pub const MlKem768PublicKey = struct {
    data: [PublicKeyBytes768]u8,
    raw: sys.MLKEM768_public_key,

    pub fn fromBytes(input: []const u8) BoringError!MlKem768PublicKey {
        if (input.len != PublicKeyBytes768) return error.InvalidArgument;

        var cbs = cbsFromBytes(input);
        var self: MlKem768PublicKey = undefined;
        try requireOne(sys.MLKEM768_parse_public_key(&self.raw, &cbs));
        try requireEmptyCbs(&cbs);
        @memcpy(self.data[0..], input);

        return self;
    }

    pub fn bytes(self: *const MlKem768PublicKey) []const u8 {
        return &self.data;
    }

    pub fn toBytes(self: *const MlKem768PublicKey, output: []u8) BoringError!usize {
        if (output.len < PublicKeyBytes768) return error.Overflow;

        @memcpy(output[0..PublicKeyBytes768], self.bytes());
        return PublicKeyBytes768;
    }

    pub fn encapsulate(self: *const MlKem768PublicKey) struct {
        MlKem768Ciphertext,
        SharedSecret,
    } {
        var ciphertext: MlKem768Ciphertext = undefined;
        var shared_secret: SharedSecret = undefined;

        sys.MLKEM768_encap(
            ciphertext.data[0..].ptr,
            shared_secret.data[0..].ptr,
            &self.raw,
        );

        return .{ ciphertext, shared_secret };
    }
};

pub const MlKem1024PublicKey = struct {
    data: [PublicKeyBytes1024]u8,
    raw: sys.MLKEM1024_public_key,

    pub fn fromBytes(input: []const u8) BoringError!MlKem1024PublicKey {
        if (input.len != PublicKeyBytes1024) return error.InvalidArgument;

        var cbs = cbsFromBytes(input);
        var self: MlKem1024PublicKey = undefined;
        try requireOne(sys.MLKEM1024_parse_public_key(&self.raw, &cbs));
        try requireEmptyCbs(&cbs);
        @memcpy(self.data[0..], input);

        return self;
    }

    pub fn bytes(self: *const MlKem1024PublicKey) []const u8 {
        return &self.data;
    }

    pub fn toBytes(self: *const MlKem1024PublicKey, output: []u8) BoringError!usize {
        if (output.len < PublicKeyBytes1024) return error.Overflow;

        @memcpy(output[0..PublicKeyBytes1024], self.bytes());
        return PublicKeyBytes1024;
    }

    pub fn encapsulate(self: *const MlKem1024PublicKey) struct {
        MlKem1024Ciphertext,
        SharedSecret,
    } {
        var ciphertext: MlKem1024Ciphertext = undefined;
        var shared_secret: SharedSecret = undefined;

        sys.MLKEM1024_encap(
            ciphertext.data[0..].ptr,
            shared_secret.data[0..].ptr,
            &self.raw,
        );

        return .{ ciphertext, shared_secret };
    }
};

pub const MlKem768PrivateKey = struct {
    seed: PrivateKeySeed,
    raw: sys.MLKEM768_private_key,

    pub fn generate() BoringError!struct { MlKem768PublicKey, MlKem768PrivateKey } {
        var public_bytes: [PublicKeyBytes768]u8 = undefined;
        var private_key: MlKem768PrivateKey = undefined;

        sys.MLKEM768_generate_key(
            public_bytes[0..].ptr,
            private_key.seed[0..].ptr,
            &private_key.raw,
        );

        const public_key = try MlKem768PublicKey.fromBytes(&public_bytes);
        return .{ public_key, private_key };
    }

    pub fn fromSeed(seed: *const PrivateKeySeed) BoringError!MlKem768PrivateKey {
        var self = MlKem768PrivateKey{
            .seed = seed.*,
            .raw = undefined,
        };
        try requireOne(sys.MLKEM768_private_key_from_seed(
            &self.raw,
            seed[0..].ptr,
            seed.len,
        ));

        return self;
    }

    pub fn seedBytes(self: *const MlKem768PrivateKey) *const PrivateKeySeed {
        return &self.seed;
    }

    pub fn publicKey(self: *const MlKem768PrivateKey) BoringError!MlKem768PublicKey {
        var raw: sys.MLKEM768_public_key = undefined;
        sys.MLKEM768_public_from_private(&raw, &self.raw);

        var output: [PublicKeyBytes768]u8 = undefined;
        try marshalPublicKey768(&raw, &output);

        return MlKem768PublicKey.fromBytes(&output);
    }

    pub fn decapsulate(
        self: *const MlKem768PrivateKey,
        ciphertext: *const MlKem768Ciphertext,
    ) SharedSecret {
        var shared_secret: SharedSecret = undefined;
        sys.MLKEM768_decap(
            shared_secret.data[0..].ptr,
            ciphertext.data[0..].ptr,
            ciphertext.data.len,
            &self.raw,
        );

        return shared_secret;
    }

    pub fn cleanse(self: *MlKem768PrivateKey) void {
        sys.OPENSSL_cleanse(&self.seed, self.seed.len);
        sys.OPENSSL_cleanse(&self.raw, @sizeOf(sys.MLKEM768_private_key));
    }
};

pub const MlKem1024PrivateKey = struct {
    seed: PrivateKeySeed,
    raw: sys.MLKEM1024_private_key,

    pub fn generate() BoringError!struct { MlKem1024PublicKey, MlKem1024PrivateKey } {
        var public_bytes: [PublicKeyBytes1024]u8 = undefined;
        var private_key: MlKem1024PrivateKey = undefined;

        sys.MLKEM1024_generate_key(
            public_bytes[0..].ptr,
            private_key.seed[0..].ptr,
            &private_key.raw,
        );

        const public_key = try MlKem1024PublicKey.fromBytes(&public_bytes);
        return .{ public_key, private_key };
    }

    pub fn fromSeed(seed: *const PrivateKeySeed) BoringError!MlKem1024PrivateKey {
        var self = MlKem1024PrivateKey{
            .seed = seed.*,
            .raw = undefined,
        };
        try requireOne(sys.MLKEM1024_private_key_from_seed(
            &self.raw,
            seed[0..].ptr,
            seed.len,
        ));

        return self;
    }

    pub fn seedBytes(self: *const MlKem1024PrivateKey) *const PrivateKeySeed {
        return &self.seed;
    }

    pub fn publicKey(self: *const MlKem1024PrivateKey) BoringError!MlKem1024PublicKey {
        var raw: sys.MLKEM1024_public_key = undefined;
        sys.MLKEM1024_public_from_private(&raw, &self.raw);

        var output: [PublicKeyBytes1024]u8 = undefined;
        try marshalPublicKey1024(&raw, &output);

        return MlKem1024PublicKey.fromBytes(&output);
    }

    pub fn decapsulate(
        self: *const MlKem1024PrivateKey,
        ciphertext: *const MlKem1024Ciphertext,
    ) SharedSecret {
        var shared_secret: SharedSecret = undefined;
        sys.MLKEM1024_decap(
            shared_secret.data[0..].ptr,
            ciphertext.data[0..].ptr,
            ciphertext.data.len,
            &self.raw,
        );

        return shared_secret;
    }

    pub fn cleanse(self: *MlKem1024PrivateKey) void {
        sys.OPENSSL_cleanse(&self.seed, self.seed.len);
        sys.OPENSSL_cleanse(&self.raw, @sizeOf(sys.MLKEM1024_private_key));
    }
};

fn cbsFromBytes(bytes: []const u8) sys.CBS {
    return .{
        .data = bytes.ptr,
        .len = bytes.len,
    };
}

fn requireEmptyCbs(cbs: *const sys.CBS) BoringError!void {
    if (cbs.len == 0) return;

    return error.BoringSSL;
}

fn requireOne(result: c_int) BoringError!void {
    if (result == 1) return;

    return error.BoringSSL;
}

fn marshalPublicKey768(
    raw: *const sys.MLKEM768_public_key,
    output: *[PublicKeyBytes768]u8,
) BoringError!void {
    var cbb: sys.CBB = undefined;
    try requireOne(sys.CBB_init_fixed(&cbb, output, output.len));
    try requireOne(sys.MLKEM768_marshal_public_key(&cbb, raw));
    if (sys.CBB_len(&cbb) != output.len) return error.BoringSSL;
}

fn marshalPublicKey1024(
    raw: *const sys.MLKEM1024_public_key,
    output: *[PublicKeyBytes1024]u8,
) BoringError!void {
    var cbb: sys.CBB = undefined;
    try requireOne(sys.CBB_init_fixed(&cbb, output, output.len));
    try requireOne(sys.MLKEM1024_marshal_public_key(&cbb, raw));
    if (sys.CBB_len(&cbb) != output.len) return error.BoringSSL;
}

comptime {
    std.debug.assert(PrivateKeySeedBytes == 64);
    std.debug.assert(SharedSecretBytes == 32);
    std.debug.assert(PublicKeyBytes768 == 1184);
    std.debug.assert(PublicKeyBytes1024 == 1568);
    std.debug.assert(CiphertextBytes768 == 1088);
    std.debug.assert(CiphertextBytes1024 == 1568);
}
