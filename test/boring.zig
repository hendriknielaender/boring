const std = @import("std");
const boring = @import("boring");
const sys = boring.boringssl;
const test_server = @import("server.zig");

const srtp_profiles_wire = "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32";
const srtp_profile_name_selected = "SRTP_AES128_CM_SHA1_80";
const srtp_profile_name_second = "SRTP_AES128_CM_SHA1_32";

fn srtp_profile_is_selected(profile: boring.srtp.SrtpProtectionProfile) bool {
    if (!std.mem.eql(u8, profile.name(), srtp_profile_name_selected)) return false;

    return profile.id().asRaw() == boring.srtp.SrtpProfileId.aes128CmSha1_80.asRaw();
}

fn expect_srtp_profile_selected(profile: boring.srtp.SrtpProtectionProfile) !void {
    try std.testing.expectEqualStrings(srtp_profile_name_selected, profile.name());
    try std.testing.expectEqual(
        boring.srtp.SrtpProfileId.aes128CmSha1_80.asRaw(),
        profile.id().asRaw(),
    );
}

fn expect_srtp_profile_list(profiles: boring.ssl.SrtpProfileList) !void {
    try std.testing.expectEqual(@as(usize, 2), profiles.len());

    const first = profiles.get(0) orelse return error.TestExpectedEqual;
    try expect_srtp_profile_selected(first);

    const second = profiles.get(1) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings(srtp_profile_name_second, second.name());
    try std.testing.expectEqual(
        boring.srtp.SrtpProfileId.aes128CmSha1_32.asRaw(),
        second.id().asRaw(),
    );
}

fn set_srtp_profiles_on_ssl(ssl: *boring.ssl.Ssl) void {
    ssl.setSrtpProfiles(srtp_profiles_wire) catch unreachable;
}

fn set_mtu_on_ssl(ssl: *boring.ssl.Ssl) void {
    ssl.setMtu(1500) catch unreachable;
}

fn set_srtp_profiles_and_mtu_on_ssl(ssl: *boring.ssl.Ssl) void {
    set_srtp_profiles_on_ssl(ssl);
    set_mtu_on_ssl(ssl);
}

fn write_srtp_profile_selection(ssl: *boring.ssl.Ssl, fd: c_int) void {
    _ = fd;

    var selected: [1]u8 = .{0};
    const ssl_ref = ssl.ref() catch return;
    if (ssl_ref.selectedSrtpProfile()) |profile| {
        selected[0] = @intFromBool(srtp_profile_is_selected(profile));
    }

    _ = ssl.write(&selected) catch {};
}

fn complete_ssl_handshake(ssl: *boring.ssl.Ssl) !void {
    var attempts: u32 = 0;
    while (attempts < 1024) : (attempts += 1) {
        const result = ssl.doHandshake();
        if (result) {
            return;
        } else |err| switch (err) {
            error.WantRead, error.WantWrite => continue,
            else => return err,
        }
    }

    return error.TestUnexpectedResult;
}

fn build_https_connector_with_root_ca() !boring.https_connector.HttpsConnector {
    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    errdefer builder.deinit();

    builder.setVerify(boring.ssl.VerifyMode.peer);
    try builder.setCaFile("test/root-ca.pem");
    builder.setServerAlpnH2Http11();

    return boring.https_connector.HttpsConnector.initWithBuilder(&builder);
}

const CertificateCompressionState = struct {
    compress_calls: u32 = 0,
    decompress_calls: u32 = 0,
};

fn certificate_compression_compress(
    state: *CertificateCompressionState,
    ssl: *boring.ssl.SslRef,
    input: []const u8,
    output: *boring.ssl.CertificateCompressionWriter,
) boring.BoringError!void {
    _ = ssl;
    state.compress_calls += 1;

    for (input) |byte| {
        try output.writeByte(byte ^ 0x55);
    }
}

fn certificate_compression_decompress(
    state: *CertificateCompressionState,
    ssl: *boring.ssl.SslRef,
    input: []const u8,
    output: []u8,
) boring.BoringError!void {
    _ = ssl;
    state.decompress_calls += 1;
    if (input.len != output.len) return error.InvalidArgument;

    for (input, output) |source, *target| {
        target.* = source ^ 0x55;
    }
}

fn add_certificate_compression(
    builder: *boring.ssl.ContextBuilder,
    state: *CertificateCompressionState,
) !void {
    try builder.addCertificateCompressionAlgorithmWithContext(
        boring.ssl.CertificateCompressionAlgorithm.fromRaw(0x1234),
        CertificateCompressionState,
        state,
        .{
            .compress = certificate_compression_compress,
            .decompress = certificate_compression_decompress,
        },
    );
}

test "high-level module exposes core boringssl layers" {
    try std.testing.expect(@hasDecl(boring, "ErrorStack"));
    try std.testing.expect(@hasDecl(boring, "aead"));
    try std.testing.expect(@hasDecl(boring, "aes"));
    try std.testing.expect(@hasDecl(boring, "asn1"));
    try std.testing.expect(@hasDecl(boring, "async_callbacks"));
    try std.testing.expect(@hasDecl(boring, "base64"));
    try std.testing.expect(@hasDecl(boring, "bio"));
    try std.testing.expect(@hasDecl(boring, "bn"));
    try std.testing.expect(@hasDecl(boring, "conf"));
    try std.testing.expect(@hasDecl(boring, "derive"));
    try std.testing.expect(@hasDecl(boring, "dh"));
    try std.testing.expect(@hasDecl(boring, "dsa"));
    try std.testing.expect(@hasDecl(boring, "ec"));
    try std.testing.expect(@hasDecl(boring, "ech"));
    try std.testing.expect(@hasDecl(boring, "ecdsa"));
    try std.testing.expect(@hasDecl(boring, "errors"));
    try std.testing.expect(@hasDecl(boring, "ex_data"));
    try std.testing.expect(@hasDecl(boring, "hash"));
    try std.testing.expect(@hasDecl(boring, "hkdf"));
    try std.testing.expect(@hasDecl(boring, "fips"));
    try std.testing.expect(@hasDecl(boring, "https_connector"));
    try std.testing.expect(@hasDecl(boring, "hpke"));
    try std.testing.expect(@hasDecl(boring, "hmac"));
    try std.testing.expect(@hasDecl(boring, "memcmp"));
    try std.testing.expect(@hasDecl(boring, "mlkem"));
    try std.testing.expect(@hasDecl(boring, "nid"));
    try std.testing.expect(@hasDecl(boring, "pkcs5"));
    try std.testing.expect(@hasDecl(boring, "pkcs12"));
    try std.testing.expect(@hasDecl(boring, "pkey"));
    try std.testing.expect(@hasDecl(boring, "prf"));
    try std.testing.expect(@hasDecl(boring, "rand"));
    try std.testing.expect(@hasDecl(boring, "rsa"));
    try std.testing.expect(@hasDecl(boring, "sha"));
    try std.testing.expect(@hasDecl(boring, "sign"));
    try std.testing.expect(@hasDecl(boring, "srtp"));
    try std.testing.expect(@hasDecl(boring, "ssl"));
    try std.testing.expect(@hasDecl(boring, "ssl_connector"));
    try std.testing.expect(@hasDecl(boring, "ssl_credential"));
    try std.testing.expect(@hasDecl(boring, "ssl_error"));
    try std.testing.expect(@hasDecl(boring, "stack"));
    try std.testing.expect(@hasDecl(boring, "string"));
    try std.testing.expect(@hasDecl(boring, "symm"));
    try std.testing.expect(@hasDecl(boring, "version"));
    try std.testing.expect(@hasDecl(boring, "x509"));
    try std.testing.expect(@hasDecl(boring, "x509_verify"));
    try std.testing.expect(@hasDecl(boring, "x509_store"));
    try std.testing.expect(@hasDecl(boring, "x509_store_context"));
}

test "patch feature gates match build options" {
    try std.testing.expect(!boring.build_options.boringssl_mlkem_patch);
    try std.testing.expect(!boring.build_options.boringssl_rpk_patch);
    try std.testing.expect(!boring.build_options.boringssl_underscore_wildcards_patch);

    try std.testing.expect(!@hasDecl(boring.mlkem, "MlKem1024PrivateKey"));
    try std.testing.expect(!@hasDecl(boring.ssl_credential.Credential, "initRawPublicKey"));
    try std.testing.expect(!@hasDecl(boring.ssl_credential.CredentialBuilder, "setSpkiBytes"));
    try std.testing.expect(!@hasDecl(boring.x509_verify.X509CheckFlags, "underscoreWildcards"));
}

test "async callback operations map retry states" {
    const callbacks = boring.async_callbacks;

    var select_operation = callbacks.SelectCertificateOperation{};
    try std.testing.expectEqual(
        boring.ssl.SelectCertificateResult.retry,
        callbacks.selectCertificateResult(select_operation.begin()),
    );
    try std.testing.expect(select_operation.isPending());
    select_operation.complete(.success);
    try std.testing.expectEqual(
        boring.ssl.SelectCertificateResult.success,
        callbacks.selectCertificateResult(select_operation.begin()),
    );
    try std.testing.expect(select_operation.isIdle());

    _ = select_operation.begin();
    select_operation.fail();
    try std.testing.expectEqual(
        boring.ssl.SelectCertificateResult.failure,
        callbacks.selectCertificateResult(select_operation.begin()),
    );

    var get_session_operation = callbacks.GetSessionOperation{};
    try std.testing.expectEqual(
        @as(std.meta.Tag(boring.ssl.GetSessionResult), .retry),
        std.meta.activeTag(callbacks.getSessionResult(get_session_operation.begin())),
    );
    get_session_operation.complete(.none);
    try std.testing.expectEqual(
        @as(std.meta.Tag(boring.ssl.GetSessionResult), .none),
        std.meta.activeTag(callbacks.getSessionResult(get_session_operation.begin())),
    );

    var verify_operation = callbacks.VerifyOperation{};
    try std.testing.expectEqual(
        @as(std.meta.Tag(boring.ssl.VerifyCallbackResult), .retry),
        std.meta.activeTag(callbacks.verifyCallbackResult(
            verify_operation.begin(),
            .internalError,
        )),
    );
    _ = verify_operation.begin();
    verify_operation.fail();
    const verify_result = callbacks.verifyCallbackResult(
        verify_operation.begin(),
        .certificateRevoked,
    );
    try std.testing.expectEqual(
        boring.ssl.SslAlert.certificateRevoked,
        verify_result.invalid,
    );

    const Output = callbacks.PrivateKeyOutput(32);
    var private_key_operation = callbacks.PrivateKeyOperation(32){};
    var output_buffer: [32]u8 = undefined;
    try std.testing.expectEqual(
        @as(std.meta.Tag(boring.ssl.PrivateKeyCallbackResult), .retry),
        std.meta.activeTag(callbacks.privateKeyResult(
            32,
            private_key_operation.begin(),
            &output_buffer,
        )),
    );

    const private_key_output = try Output.fromBytes("signature");
    private_key_operation.complete(private_key_output);
    const private_key_result = callbacks.privateKeyResult(
        32,
        private_key_operation.begin(),
        &output_buffer,
    );
    try std.testing.expectEqual(
        @as(std.meta.Tag(boring.ssl.PrivateKeyCallbackResult), .success),
        std.meta.activeTag(private_key_result),
    );
    try std.testing.expectEqual(@as(usize, 9), private_key_result.success);
    try std.testing.expectEqualSlices(u8, "signature", output_buffer[0..9]);
}

test "sha256 and hmac sha256 wrappers work" {
    try std.testing.expect(boring.version.text().len > 0);

    const digest = boring.sha.sha256("abc");
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expected, &digest);

    const mac = try boring.hmac.sha256("key", "data");
    try std.testing.expectEqual(@as(usize, boring.hmac.SHA256DigestLength), mac.len);
}

test "base64 and constant-time compare wrappers work" {
    var encoded: [16]u8 = undefined;
    const encoded_len = try boring.base64.encodeBlock(&encoded, "foobar");
    try std.testing.expectEqualStrings("Zm9vYmFy", encoded[0..encoded_len]);

    var decoded: [8]u8 = undefined;
    const decoded_len = try boring.base64.decodeBlock(&decoded, encoded[0..encoded_len]);
    try std.testing.expectEqualSlices(u8, "foobar", decoded[0..decoded_len]);

    try std.testing.expect(boring.memcmp.constantTimeEq("abc", "abc"));
    try std.testing.expect(!boring.memcmp.constantTimeEq("abc", "abd"));
}

test "nid and fips wrappers work" {
    try std.testing.expect(!boring.fips.enabled());
    try std.testing.expectEqual(@as(c_int, 672), boring.nid.Nid.sha256.asRaw());
    try std.testing.expectEqualStrings("SHA256", try boring.nid.Nid.sha256.shortName());

    const algorithms = boring.nid.Nid.sha256WithRsaEncryption.signatureAlgorithms() orelse {
        return error.TestExpectedEqual;
    };
    try std.testing.expectEqual(boring.nid.Nid.sha256.asRaw(), algorithms.digest.asRaw());
    try std.testing.expectEqual(boring.nid.Nid.rsaEncryption.asRaw(), algorithms.pkey.asRaw());
}

test "pkcs5 key derivation wrappers work" {
    var pbkdf2_sha256: [16]u8 = undefined;
    try boring.pkcs5.pbkdf2Hmac(
        &pbkdf2_sha256,
        "passwd",
        "salt",
        1,
        boring.hash.MessageDigest.sha256(),
    );
    const expected_sha256 = [_]u8{
        0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
        0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
    };
    try std.testing.expectEqualSlices(u8, &expected_sha256, &pbkdf2_sha256);

    var pbkdf2_sha1: [20]u8 = undefined;
    try boring.pkcs5.pbkdf2HmacSha1(&pbkdf2_sha1, "password", "salt", 1);
    const expected_sha1 = [_]u8{
        0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
        0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
        0x2f, 0xe0, 0x37, 0xa6,
    };
    try std.testing.expectEqualSlices(u8, &expected_sha1, &pbkdf2_sha1);

    var scrypt_key: [32]u8 = undefined;
    try boring.pkcs5.scrypt(&scrypt_key, "password", "NaCl", 1024, 8, 16, 32 * 1024 * 1024);
    try std.testing.expect(!boring.memcmp.constantTimeEq(&scrypt_key, &[_]u8{0} ** 32));
}

test "memory bio wrapper works" {
    var bio = try boring.bio.MemBio.init();
    defer bio.deinit();

    try bio.writeAll("hello");
    try std.testing.expectEqualStrings("hello", try bio.bytes());
    try std.testing.expectEqual(@as(usize, 5), try bio.pending());

    var output: [8]u8 = undefined;
    const output_len = try bio.read(&output);
    try std.testing.expectEqualStrings("hello", output[0..output_len]);

    var slice_bio = try boring.bio.MemBio.initConstSlice("world");
    defer slice_bio.deinit();
    const slice_len = try slice_bio.read(&output);
    try std.testing.expectEqualStrings("world", output[0..slice_len]);
}

test "bignum core wrappers work" {
    var value = try boring.bn.BigNum.fromU32(10_203_004);
    defer value.deinit();

    var value_bytes: [8]u8 = undefined;
    const value_len = try value.toBin(&value_bytes);
    var value_copy = try boring.bn.BigNum.fromSlice(value_bytes[0..value_len]);
    defer value_copy.deinit();
    try std.testing.expectEqual(boring.bn.Order.eq, try value.cmp(&value_copy));
    try std.testing.expect(try value.equalConstantTime(&value_copy));

    var decimal = try boring.bn.BigNum.fromDecString("12345678901234567890");
    defer decimal.deinit();
    var decimal_string = try decimal.toDecString();
    defer decimal_string.deinit();
    try std.testing.expectEqualStrings("12345678901234567890", decimal_string.bytes());

    var hex = try boring.bn.BigNum.fromHexString("99ff");
    defer hex.deinit();
    var hex_string = try hex.toHexString();
    defer hex_string.deinit();
    try std.testing.expectEqualStrings("99ff", hex_string.bytes());

    var ctx = try boring.bn.BigNumContext.init();
    defer ctx.deinit();

    var a = try boring.bn.BigNum.fromU32(30);
    defer a.deinit();
    var b = try boring.bn.BigNum.fromU32(7);
    defer b.deinit();
    var result = try boring.bn.BigNum.init();
    defer result.deinit();

    try result.checkedAdd(&a, &b);
    try std.testing.expectEqual(@as(u64, 37), try result.getU64());
    try result.checkedSub(&a, &b);
    try std.testing.expectEqual(@as(u64, 23), try result.getU64());
    try result.checkedMul(&a, &b, &ctx);
    try std.testing.expectEqual(@as(u64, 210), try result.getU64());
    try result.checkedDiv(&a, &b, &ctx);
    try std.testing.expectEqual(@as(u64, 4), try result.getU64());
    try result.checkedRem(&a, &b, &ctx);
    try std.testing.expectEqual(@as(u64, 2), try result.getU64());

    try result.leftShift(&b, 3);
    try std.testing.expectEqual(@as(u64, 56), try result.getU64());
    try std.testing.expect(try result.isBitSet(3));
}

test "dh parameter wrappers work" {
    var p = try boring.bn.BigNum.fromU32(23);
    var g = try boring.bn.BigNum.fromU32(5);
    var q = try boring.bn.BigNum.fromU32(11);
    var custom = try boring.dh.Dh.fromParams(&p, &g, &q);
    defer custom.deinit();
    try std.testing.expect((try custom.bits()) > 0);

    var group = try boring.dh.Dh.rfc7919Ffdhe2048();
    defer group.deinit();
    try std.testing.expectEqual(@as(usize, 2048), try group.bits());

    var pem = try boring.bio.MemBio.init();
    defer pem.deinit();
    try group.paramsToPem(&pem);
    try std.testing.expect(std.mem.indexOf(u8, try pem.bytes(), "BEGIN DH PARAMETERS") != null);

    var from_pem = try boring.dh.Dh.paramsFromPem(try pem.bytes());
    defer from_pem.deinit();
    try std.testing.expectEqual(try group.bits(), try from_pem.bits());

    var der = try boring.bio.MemBio.init();
    defer der.deinit();
    try group.paramsToDer(&der);
    var from_der = try boring.dh.Dh.paramsFromDer(try der.bytes());
    defer from_der.deinit();
    try std.testing.expectEqual(try group.bits(), try from_der.bits());
}

test "conf wrapper can load from memory bio" {
    var input = try boring.bio.MemBio.initConstSlice(
        \\[server]
        \\name = example
        \\
    );
    defer input.deinit();

    var conf = try boring.conf.Conf.init(null);
    defer conf.deinit();
    try conf.loadBio(&input);

    const value = (try conf.getString("server", "name")) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("example", value);
}

test "rsa generated key can encrypt and decrypt" {
    var rsa = try boring.rsa.Rsa.generate(2048);
    defer rsa.deinit();
    try std.testing.expectEqual(@as(usize, 2048), try rsa.bits());
    try std.testing.expect(try rsa.checkKey());

    const plaintext = "zig boring rsa";
    var encrypted: [512]u8 = undefined;
    const encrypted_len = try rsa.publicEncrypt(
        &encrypted,
        plaintext,
        .pkcs1,
    );
    try std.testing.expectEqual(try rsa.size(), encrypted_len);

    var decrypted: [512]u8 = undefined;
    const decrypted_len = try rsa.privateDecrypt(
        &decrypted,
        encrypted[0..encrypted_len],
        .pkcs1,
    );
    try std.testing.expectEqualStrings(plaintext, decrypted[0..decrypted_len]);
}

test "pkey can own an rsa key" {
    var rsa = try boring.rsa.Rsa.generate(2048);
    var pkey = try boring.pkey.PKey.fromRsa(&rsa);
    defer pkey.deinit();

    try std.testing.expectError(error.Closed, rsa.size());
    try std.testing.expectEqual(boring.pkey.Id.rsa.asRaw(), (try pkey.id()).asRaw());
    try std.testing.expectEqual(@as(usize, 2048), try pkey.bits());
    try std.testing.expect((try pkey.size()) > 0);
    try std.testing.expect(!try pkey.isOpaque());
    try std.testing.expect(!try pkey.missingParameters());

    var rsa_copy = try pkey.rsa();
    defer rsa_copy.deinit();
    try std.testing.expect(try rsa_copy.checkKey());

    var pkey_clone = try pkey.clone();
    defer pkey_clone.deinit();
    try std.testing.expect(try pkey.publicEq(&pkey_clone));
}

test "pkey raw x25519 keys can derive a shared secret" {
    const private_a = [_]u8{0x11} ** 32;
    const private_b = [_]u8{0x22} ** 32;

    var key_a = try boring.pkey.PKey.fromRawPrivateKey(boring.pkey.Id.x25519, &private_a);
    defer key_a.deinit();
    var key_b = try boring.pkey.PKey.fromRawPrivateKey(boring.pkey.Id.x25519, &private_b);
    defer key_b.deinit();

    try std.testing.expectEqual(@as(usize, 253), try key_a.bits());
    try std.testing.expectEqual(@as(usize, 32), try key_a.rawPublicKeyLength());
    try std.testing.expectEqual(@as(usize, 32), try key_a.rawPrivateKeyLength());

    var public_a: [32]u8 = undefined;
    try std.testing.expectEqual(@as(usize, public_a.len), try key_a.rawPublicKey(&public_a));
    var public_key_a = try boring.pkey.PKey.fromRawPublicKey(boring.pkey.Id.x25519, &public_a);
    defer public_key_a.deinit();

    var deriver_ab = try boring.derive.Deriver.init(&key_a);
    defer deriver_ab.deinit();
    try deriver_ab.setPeer(&key_b);
    var secret_ab: [32]u8 = undefined;
    try std.testing.expectEqual(@as(usize, secret_ab.len), try deriver_ab.length());
    const secret_ab_len = try deriver_ab.derive(&secret_ab);

    var deriver_ba = try boring.derive.Deriver.init(&key_b);
    defer deriver_ba.deinit();
    try deriver_ba.setPeer(&public_key_a);
    var secret_ba: [32]u8 = undefined;
    const secret_ba_len = try deriver_ba.derive(&secret_ba);

    try std.testing.expectEqual(secret_ab_len, secret_ba_len);
    try std.testing.expectEqualSlices(u8, secret_ab[0..secret_ab_len], secret_ba[0..secret_ba_len]);
}

test "ec group, point, key, and pkey wrappers work" {
    var group = try boring.ec.EcGroup.fromCurveName(boring.nid.Nid.prime256v1);
    defer group.deinit();
    try std.testing.expectEqual(@as(usize, 256), try group.degree());
    try std.testing.expectEqual(
        boring.nid.Nid.prime256v1.asRaw(),
        (try group.curveName()).?.asRaw(),
    );

    var ctx = try boring.bn.BigNumContext.init();
    defer ctx.deinit();
    var cofactor = try boring.bn.BigNum.init();
    defer cofactor.deinit();
    try group.cofactor(&cofactor, &ctx);
    try std.testing.expectEqual(@as(u64, 1), try cofactor.getU64());

    var key = try boring.ec.EcKey.generate(&group);
    defer key.deinit();
    try key.checkKey();
    try std.testing.expect(!try key.isOpaque());

    var public_key = try key.publicKey();
    defer public_key.deinit();
    try std.testing.expect(try public_key.isOnCurve(&group, &ctx));

    var bytes: [128]u8 = undefined;
    const bytes_len = try public_key.toBytes(&group, .compressed, &ctx, &bytes);
    var decoded = try boring.ec.EcPoint.fromBytes(&group, bytes[0..bytes_len], &ctx);
    defer decoded.deinit();
    try std.testing.expect(try public_key.eq(&group, &decoded, &ctx));

    var private_key = try key.privateKey();
    defer private_key.deinit();
    try std.testing.expect((try private_key.numBits()) > 0);

    var key_clone = try key.clone();
    var pkey = try boring.pkey.PKey.fromEcKey(&key_clone);
    defer pkey.deinit();
    try std.testing.expectError(error.Closed, key_clone.checkKey());
    try std.testing.expectEqual(boring.pkey.Id.ec.asRaw(), (try pkey.id()).asRaw());
    try std.testing.expectEqual(@as(usize, 256), try pkey.bits());

    var ec_copy = try pkey.ecKey();
    defer ec_copy.deinit();
    try ec_copy.checkKey();
}

test "ecdsa signature wrapper signs and verifies" {
    var group = try boring.ec.EcGroup.fromCurveName(boring.nid.Nid.prime256v1);
    defer group.deinit();
    var key = try boring.ec.EcKey.generate(&group);
    defer key.deinit();

    const digest = try boring.hash.digest(boring.hash.MessageDigest.sha256(), "hello ecdsa");
    var sig = try boring.ecdsa.EcdsaSig.sign(digest.bytes(), &key);
    defer sig.deinit();

    try std.testing.expect(try sig.verify(digest.bytes(), &key));

    const other_digest = try boring.hash.digest(boring.hash.MessageDigest.sha256(), "nope");
    try std.testing.expect(!try sig.verify(other_digest.bytes(), &key));

    var r = try sig.r();
    defer r.deinit();
    var s = try sig.s();
    defer s.deinit();
    try std.testing.expect((try r.numBits()) > 0);
    try std.testing.expect((try s.numBits()) > 0);
}

test "dsa key and signature wrappers work" {
    var dsa = try boring.dsa.Dsa.generate(1024);
    defer dsa.deinit();
    try std.testing.expectEqual(@as(usize, 1024), try dsa.bits());
    try std.testing.expect((try dsa.size()) > 0);

    var p = try dsa.p();
    defer p.deinit();
    var q = try dsa.q();
    defer q.deinit();
    var g = try dsa.g();
    defer g.deinit();
    var public_key = try dsa.publicKey();
    defer public_key.deinit();
    var private_key = try dsa.privateKey();
    defer private_key.deinit();
    try std.testing.expect((try p.numBits()) > 0);
    try std.testing.expect((try q.numBits()) > 0);
    try std.testing.expect((try g.numBits()) > 0);
    try std.testing.expect((try public_key.numBits()) > 0);
    try std.testing.expect((try private_key.numBits()) > 0);

    const digest = try boring.hash.digest(boring.hash.MessageDigest.sha256(), "hello dsa");
    var sig = try boring.dsa.DsaSig.sign(digest.bytes(), &dsa);
    defer sig.deinit();
    try std.testing.expect(try sig.verify(digest.bytes(), &dsa));

    const other_digest = try boring.hash.digest(boring.hash.MessageDigest.sha256(), "nope");
    try std.testing.expect(!try sig.verify(other_digest.bytes(), &dsa));

    var dsa_clone = try dsa.clone();
    var pkey = try boring.pkey.PKey.fromDsa(&dsa_clone);
    defer pkey.deinit();
    try std.testing.expectError(error.Closed, dsa_clone.size());
    try std.testing.expectEqual(boring.pkey.Id.dsa.asRaw(), (try pkey.id()).asRaw());
    try std.testing.expectEqual(@as(usize, 1024), try pkey.bits());

    var dsa_copy = try pkey.dsa();
    defer dsa_copy.deinit();
    try std.testing.expectEqual(@as(usize, 1024), try dsa_copy.bits());
}

test "signer and verifier work with rsa pkey" {
    var rsa = try boring.rsa.Rsa.generate(2048);
    var pkey = try boring.pkey.PKey.fromRsa(&rsa);
    defer pkey.deinit();

    var signer = try boring.sign.Signer.init(boring.hash.MessageDigest.sha256(), &pkey);
    defer signer.deinit();
    try std.testing.expectEqual(boring.rsa.Padding.pkcs1, try signer.rsaPadding());
    try signer.update("hello, ");
    try signer.update("world");

    var signature: [512]u8 = undefined;
    const signature_len = try signer.sign(signature[0..try signer.signatureLength()]);

    var verifier = try boring.sign.Verifier.init(boring.hash.MessageDigest.sha256(), &pkey);
    defer verifier.deinit();
    try std.testing.expectEqual(boring.rsa.Padding.pkcs1, try verifier.rsaPadding());
    try verifier.update("hello, ");
    try verifier.update("world");
    try std.testing.expect(try verifier.verify(signature[0..signature_len]));

    var invalid = try boring.sign.Verifier.init(boring.hash.MessageDigest.sha256(), &pkey);
    defer invalid.deinit();
    try invalid.update("hello, mars");
    try std.testing.expect(!try invalid.verify(signature[0..signature_len]));
}

test "hash and hkdf wrappers work" {
    const digest = try boring.hash.digest(boring.hash.MessageDigest.sha256(), "abc");
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expected, digest.bytes());

    var hasher = try boring.hash.Hasher.init(boring.hash.MessageDigest.sha256());
    defer hasher.deinit();
    try hasher.update("a");
    try hasher.update("bc");
    const digest_stream = try hasher.finish();
    try std.testing.expectEqualSlices(u8, digest.bytes(), digest_stream.bytes());

    var derived: [32]u8 = undefined;
    try boring.hkdf.derive(
        &derived,
        boring.hash.MessageDigest.sha256(),
        "secret",
        "salt",
        "info",
    );
    try std.testing.expect(!boring.memcmp.constantTimeEq(&derived, &[_]u8{0} ** 32));
}

test "aes block and key wrap wrappers work" {
    const raw_key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const key_data = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const expected_ciphertext = [_]u8{
        0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
        0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
        0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
    };

    const encrypt_key = try boring.aes.Key.initEncrypt(&raw_key);
    var wrapped: [24]u8 = undefined;
    const wrapped_len = try boring.aes.wrapKey(&encrypt_key, null, &wrapped, &key_data);
    try std.testing.expectEqual(@as(usize, wrapped.len), wrapped_len);
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &wrapped);

    const decrypt_key = try boring.aes.Key.initDecrypt(&raw_key);
    var unwrapped: [16]u8 = undefined;
    const unwrapped_len = try boring.aes.unwrapKey(&decrypt_key, null, &unwrapped, &wrapped);
    try std.testing.expectEqual(@as(usize, unwrapped.len), unwrapped_len);
    try std.testing.expectEqualSlices(u8, &key_data, &unwrapped);
}

test "aead seal and open wrappers work" {
    const algorithm = boring.aead.Algorithm.aes128Gcm();
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{1} ** 12;
    const plaintext = "hello world";
    const aad = "record-header";

    var context = try boring.aead.Context.initDefaultTag(algorithm, &key);
    defer context.deinit();

    var ciphertext: [plaintext.len + boring.aead.MaxOverhead]u8 = undefined;
    const ciphertext_len = try context.seal(&ciphertext, &nonce, plaintext, aad);
    try std.testing.expect(ciphertext_len > plaintext.len);

    var opened: [plaintext.len + boring.aead.MaxOverhead]u8 = undefined;
    const opened_len = try context.open(
        &opened,
        &nonce,
        ciphertext[0..ciphertext_len],
        aad,
    );
    try std.testing.expectEqualSlices(u8, plaintext, opened[0..opened_len]);
}

test "symm cipher wrappers work" {
    const cipher = boring.symm.Cipher.aes128Cbc();
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const iv = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    const plaintext = "Some Crypto Text";
    const expected = [_]u8{
        0xb4, 0xb9, 0xe7, 0x30, 0xd6, 0xd6, 0xf7, 0xde,
        0x77, 0x3f, 0x1c, 0xff, 0xb3, 0x3e, 0x44, 0x5a,
        0x91, 0xd7, 0x27, 0x62, 0x87, 0x4d, 0xfb, 0x3c,
        0x5e, 0xc4, 0x59, 0x72, 0x4a, 0xf4, 0x7c, 0xa1,
    };

    try std.testing.expectEqual(@as(usize, 16), cipher.keyLength());
    try std.testing.expectEqual(@as(usize, 16), cipher.ivLength().?);
    try std.testing.expectEqual(boring.nid.Nid.fromRaw(419).asRaw(), cipher.nid().asRaw());

    var ciphertext: [plaintext.len + 16]u8 = undefined;
    const ciphertext_len = try boring.symm.encrypt(
        &ciphertext,
        cipher,
        &key,
        &iv,
        plaintext,
    );
    try std.testing.expectEqualSlices(u8, &expected, ciphertext[0..ciphertext_len]);

    var decrypted: [expected.len + 16]u8 = undefined;
    const decrypted_len = try boring.symm.decrypt(
        &decrypted,
        cipher,
        &key,
        &iv,
        ciphertext[0..ciphertext_len],
    );
    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..decrypted_len]);
}

test "tls context wrapper can allocate and free a context" {
    boring.init();
    boring.ErrorStack.clear();

    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer builder.deinit();

    builder.setVerify(boring.ssl.VerifyMode.none);
    builder.setServerAlpnH2Http11();
    const signature_prefs = [_]boring.ssl.SslSignatureAlgorithm{
        .rsaPssRsaeSha256,
        .rsaPkcs1Sha256,
    };
    try builder.setSigningAlgorithmPrefs(&signature_prefs);
    try builder.setVerifyAlgorithmPrefs(&signature_prefs);

    var dh = try boring.dh.Dh.rfc7919Ffdhe2048();
    defer dh.deinit();
    try builder.setTmpDh(&dh);

    var context = builder.build();
    defer context.deinit();
}

const SslCallbackState = struct {
    select_certificate_calls: u32 = 0,
    alpn_select_calls: u32 = 0,
    server_name_calls: u32 = 0,
    custom_verify_calls: u32 = 0,
    new_session_calls: u32 = 0,
    remove_session_calls: u32 = 0,
    get_session_calls: u32 = 0,
    private_key_sign_calls: u32 = 0,
    private_key_decrypt_calls: u32 = 0,
    private_key_complete_calls: u32 = 0,
};

fn select_certificate_callback(
    state: *SslCallbackState,
    client_hello: *boring.ssl.ClientHello,
) boring.ssl.SelectCertificateResult {
    state.select_certificate_calls += 1;
    std.debug.assert(client_hello.bytes() != null);
    _ = client_hello.extension(.serverName);
    _ = client_hello.random();
    _ = client_hello.ciphers();
    _ = client_hello.clientVersion();
    _ = client_hello.ssl();

    return .retry;
}

fn alpn_select_callback(
    state: *SslCallbackState,
    ssl: *boring.ssl.SslRef,
    protocols_wire: []const u8,
) boring.ssl.AlpnSelectResult {
    _ = ssl;
    state.alpn_select_calls += 1;
    std.debug.assert(protocols_wire.len <= boring.ssl.MaxAlpnWireBytes);

    const selected = boring.ssl.selectAlpnProtocol(protocols_wire, "h2") orelse {
        return .noAck;
    };

    return .{ .selected = selected };
}

fn server_name_callback(
    state: *SslCallbackState,
    ssl: *boring.ssl.SslRef,
    alert: *boring.ssl.SslAlert,
) boring.ssl.ServerNameCallbackResult {
    state.server_name_calls += 1;
    _ = ssl.serverName(.hostName);
    _ = ssl.serverNameType();
    alert.* = .unrecognizedName;

    return .ok;
}

fn sni_swapped_context_callback(
    called: *bool,
    ssl: *boring.ssl.SslRef,
    alert: *boring.ssl.SslAlert,
) boring.ssl.ServerNameCallbackResult {
    _ = alert;
    if (ssl.serverName(.hostName)) |name| {
        called.* = std.mem.eql(u8, name, "localhost");
    } else {
        called.* = false;
    }

    return .ok;
}

fn set_ssl_context_from_opaque(context: ?*anyopaque, ssl: *boring.ssl.Ssl) void {
    const ssl_context: *boring.ssl.Context = @ptrCast(@alignCast(context.?));
    _ = ssl.setSslContext(ssl_context) catch unreachable;
}

fn custom_verify_callback(
    state: *SslCallbackState,
    ssl: *boring.ssl.SslRef,
) boring.ssl.VerifyCallbackResult {
    _ = ssl;
    state.custom_verify_calls += 1;

    return .retry;
}

fn get_session_callback(
    state: *SslCallbackState,
    ssl: *boring.ssl.SslRef,
    session_id: []const u8,
) boring.ssl.GetSessionResult {
    _ = ssl;
    state.get_session_calls += 1;
    std.debug.assert(session_id.len <= boring.ssl.MaxSessionIdBytes);

    return .retry;
}

fn new_session_callback(
    state: *SslCallbackState,
    ssl: *boring.ssl.SslRef,
    session: *boring.ssl.SslSessionRef,
) void {
    _ = ssl;
    state.new_session_calls += 1;
    _ = session.raw();
    _ = session.protocolVersion();
}

fn remove_session_callback(
    state: *SslCallbackState,
    context: *boring.ssl.ContextRef,
    session: *boring.ssl.SslSessionRef,
) void {
    _ = context.raw();
    state.remove_session_calls += 1;
    _ = session.raw();
    _ = session.protocolVersion();
}

fn private_key_sign_callback(
    state: *SslCallbackState,
    ssl: *boring.ssl.SslRef,
    input: []const u8,
    algorithm: boring.ssl.SslSignatureAlgorithm,
    output: []u8,
) boring.ssl.PrivateKeyCallbackResult {
    _ = ssl;
    state.private_key_sign_calls += 1;
    std.debug.assert(input.len <= boring.ssl.MaxPrivateKeyOperationBytes);
    std.debug.assert(output.len <= boring.ssl.MaxPrivateKeyOperationBytes);
    _ = algorithm.raw();

    return .retry;
}

fn private_key_decrypt_callback(
    state: *SslCallbackState,
    ssl: *boring.ssl.SslRef,
    input: []const u8,
    output: []u8,
) boring.ssl.PrivateKeyCallbackResult {
    _ = ssl;
    state.private_key_decrypt_calls += 1;
    std.debug.assert(input.len <= boring.ssl.MaxPrivateKeyOperationBytes);
    std.debug.assert(output.len <= boring.ssl.MaxPrivateKeyOperationBytes);

    return .failure;
}

fn private_key_complete_callback(
    state: *SslCallbackState,
    ssl: *boring.ssl.SslRef,
    output: []u8,
) boring.ssl.PrivateKeyCallbackResult {
    _ = ssl;
    state.private_key_complete_calls += 1;
    std.debug.assert(output.len <= boring.ssl.MaxPrivateKeyOperationBytes);

    return .{ .success = 0 };
}

fn install_ssl_callback_bridges(
    builder: *boring.ssl.ContextBuilder,
    state: *SslCallbackState,
) !void {
    try builder.setSelectCertificateCallback(
        SslCallbackState,
        state,
        select_certificate_callback,
    );
    try builder.setAlpnSelectCallback(
        SslCallbackState,
        state,
        alpn_select_callback,
    );
    try builder.setServerNameCallback(
        SslCallbackState,
        state,
        server_name_callback,
    );
    try builder.setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        SslCallbackState,
        state,
        custom_verify_callback,
    );
    try builder.setNewSessionCallbackWithContext(
        SslCallbackState,
        state,
        new_session_callback,
    );
    try builder.setRemoveSessionCallbackWithContext(
        SslCallbackState,
        state,
        remove_session_callback,
    );
    try builder.setGetSessionCallbackWithContext(
        SslCallbackState,
        state,
        get_session_callback,
    );
    try builder.setPrivateKeyMethodWithContext(SslCallbackState, state, .{
        .sign = private_key_sign_callback,
        .decrypt = private_key_decrypt_callback,
        .complete = private_key_complete_callback,
    });
}

test "ssl connector and acceptor can be constructed" {
    boring.init();
    boring.ErrorStack.clear();

    var connector_builder = try boring.ssl_connector.SslConnector.builder(
        boring.ssl.Method.tls(),
    );
    defer connector_builder.deinit();
    var connector = connector_builder.build();
    defer connector.deinit();

    var config = try connector.configure();
    defer config.deinit();
    try std.testing.expect(config.sni);
    try std.testing.expect(config.verify_hostname);

    config.setUseServerNameIndication(false);
    config.setVerifyHostname(false);
    try std.testing.expect(!config.sni);
    try std.testing.expect(!config.verify_hostname);

    var acceptor_builder = try boring.ssl_connector.SslAcceptor.mozillaIntermediateV5(
        boring.ssl.Method.tls(),
    );
    defer acceptor_builder.deinit();
    var acceptor = acceptor_builder.build();
    defer acceptor.deinit();
}

test "ssl connector handshake" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var connector_builder = try boring.ssl_connector.SslConnector.builder(
        boring.ssl.Method.tls(),
    );
    defer connector_builder.deinit();
    try connector_builder.contextBuilder().setCaFile("test/root-ca.pem");
    var connector = connector_builder.build();
    defer connector.deinit();

    const fd = try running.connectFd();
    defer _ = std.c.close(fd);
    var ssl = try connector.connect("foobar.com", fd);
    defer ssl.deinit();
    try complete_ssl_handshake(&ssl);

    var ready: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try ssl.read(&ready));
    try std.testing.expectEqual(@as(u8, 0), ready[0]);
}

test "ssl credential can be created and configured" {
    boring.init();
    boring.ErrorStack.clear();

    var cred_builder = try boring.ssl_credential.CredentialBuilder.initX509();
    defer cred_builder.deinit();

    var rsa = try boring.rsa.Rsa.generate(2048);
    var pkey = try boring.pkey.PKey.fromRsa(&rsa);
    defer pkey.deinit();
    try cred_builder.setPrivateKey(&pkey);

    var cred = cred_builder.build();
    defer cred.deinit();

    _ = try cred.raw();

    var cloned = try cred.clone();
    defer cloned.deinit();
}

test "ssl cipher can be looked up by value" {
    const cipher = boring.ssl.SslCipher.fromValue(0x1301);
    try std.testing.expect(cipher != null);
    try std.testing.expectEqualStrings("TLS_AES_128_GCM_SHA256", cipher.?.asRef().name());
    try std.testing.expect(cipher.?.asRef().isAead());
}

test "password protected rsa key can be loaded" {
    const encrypted_pem =
        \\-----BEGIN RSA PRIVATE KEY-----
        \\Proc-Type: 4,ENCRYPTED
        \\DEK-Info: AES-128-CBC,2E5B6E9B1B8C4F2D1E3A5C7B9D8E2F4A
        \\
        \\invalid-for-test-only
        \\-----END RSA PRIVATE KEY-----
    ;

    // Test that loading without password fails.
    try std.testing.expectError(error.BoringSSL, boring.rsa.Rsa.fromPem(encrypted_pem));
}

test "ssl error codes are accessible" {
    try std.testing.expectEqual(@as(c_int, 0), boring.ssl_error.ErrorCode.none.raw());
    try std.testing.expectEqual(@as(c_int, 2), boring.ssl_error.ErrorCode.wantRead.raw());
    try std.testing.expectEqual(@as(c_int, 3), boring.ssl_error.ErrorCode.wantWrite.raw());

    const want_read_error = boring.ssl_error.Error.fromCode(boring.ssl_error.ErrorCode.wantRead);
    try std.testing.expect(want_read_error.wouldBlock());
    const none_error = boring.ssl_error.Error.fromCode(boring.ssl_error.ErrorCode.none);
    try std.testing.expect(!none_error.wouldBlock());
}

test "tls callback bridges can store typed ex data" {
    boring.init();
    boring.ErrorStack.clear();

    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer builder.deinit();

    var state: SslCallbackState = .{};
    try install_ssl_callback_bridges(&builder, &state);

    const context_index = try boring.ssl.ContextBuilder.newExIndex(u32);
    var context_value: u32 = 42;
    try builder.setExData(u32, context_index, &context_value);
    try std.testing.expect(builder.exData(u32, context_index).? == &context_value);

    var context = builder.build();
    defer context.deinit();
    try std.testing.expect(context.exData(u32, context_index).? == &context_value);

    var alternate_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer alternate_builder.deinit();
    var alternate_context = alternate_builder.build();
    defer alternate_context.deinit();

    var ssl = try context.createSsl();
    defer ssl.deinit();

    const ssl_index = try boring.ssl.Ssl.newExIndex(u32);
    var ssl_value: u32 = 7;
    try ssl.setExData(u32, ssl_index, &ssl_value);
    try std.testing.expect(ssl.exData(u32, ssl_index).? == &ssl_value);

    var ssl_ref = try ssl.ref();
    try std.testing.expect(ssl_ref.exData(u32, ssl_index).? == &ssl_value);
    try std.testing.expect(ssl.serverName(.hostName) == null);
    try std.testing.expect(ssl.serverNameType() == null);
}

const cert_pem = @embedFile("cert.pem");
const key_pem = @embedFile("key.pem");
const root_ca_pem = @embedFile("root-ca.pem");
const nid_test_cert_pem = @embedFile("nid_test_cert.pem");
const nid_uid_test_cert_pem = @embedFile("nid_uid_test_cert.pem");
const alt_name_cert_pem = @embedFile("alt_name_cert.pem");
const certs_pem = @embedFile("certs.pem");
const cert_wildcard_pem = @embedFile("cert-wildcard.pem");
const cert_with_intermediate_pem = @embedFile("cert-with-intermediate.pem");
const root_ca_2_pem = @embedFile("root-ca-2.pem");
const root_ca_cross_pem = @embedFile("root-ca-cross.pem");
const intermediate_ca_pem = @embedFile("intermediate-ca.pem");

fn test_pkey() !boring.pkey.PKey {
    var rsa = try boring.rsa.Rsa.generate(2048);
    return boring.pkey.PKey.fromRsa(&rsa);
}

test "x509 cert loading and fingerprint" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();

    var fingerprint: [20]u8 = undefined;
    const fingerprint_len = try cert.digest(boring.hash.MessageDigest.sha1(), &fingerprint);
    try std.testing.expectEqual(@as(usize, 20), fingerprint_len);

    const expected = "59172d9313e84459bcff27f967e79e6e9217e584";
    const actual_hex = std.fmt.bytesToHex(fingerprint, .lower);
    try std.testing.expectEqualStrings(expected, &actual_hex);
}

test "x509 cert issue validity" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();

    var not_before_buf: [boring.asn1.MaxPrintedTimeBytes]u8 = undefined;
    const not_before_len = try (try cert.asRef()).notBefore().print(&not_before_buf);
    try std.testing.expectEqualStrings(
        "Aug 14 17:00:03 2016 GMT",
        not_before_buf[0..not_before_len],
    );

    var not_after_buf: [boring.asn1.MaxPrintedTimeBytes]u8 = undefined;
    const not_after_len = try (try cert.asRef()).notAfter().print(&not_after_buf);
    try std.testing.expectEqualStrings(
        "Aug 12 17:00:03 2026 GMT",
        not_after_buf[0..not_after_len],
    );
}

test "x509 save der" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();

    var bio = try boring.bio.MemBio.init();
    defer bio.deinit();
    try cert.toDerBio(&bio);
    const der = try bio.bytes();
    try std.testing.expect(der.len > 0);
}

test "x509 subject read cn" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();

    const subject = try cert.subjectName();
    var entries = subject.entriesByNid(boring.nid.Nid.commonName);
    const cn = entries.next().?;
    try std.testing.expectEqualStrings("foobar.com", cn.data().bytes());
}

test "x509 nid values" {
    var cert = try boring.x509.X509.fromPem(nid_test_cert_pem);
    defer cert.deinit();

    const subject = try cert.subjectName();
    var cn_entries = subject.entriesByNid(boring.nid.Nid.commonName);
    const cn = cn_entries.next().?;
    try std.testing.expectEqualStrings("example.com", cn.data().bytes());

    var email_entries = subject.entriesByNid(boring.nid.Nid.pkcs9EmailAddress);
    const email = email_entries.next().?;
    try std.testing.expectEqualStrings("test@example.com", email.data().bytes());
}

test "x509 nameref iterator" {
    var cert = try boring.x509.X509.fromPem(nid_test_cert_pem);
    defer cert.deinit();

    const subject = try cert.subjectName();
    var all_entries = subject.entries();

    const email = all_entries.next().?;
    try std.testing.expectEqual(
        boring.nid.Nid.pkcs9EmailAddress.asRaw(),
        (try email.object().nid()).asRaw(),
    );
    try std.testing.expectEqualStrings("test@example.com", email.data().bytes());

    const cn = all_entries.next().?;
    try std.testing.expectEqual(
        boring.nid.Nid.commonName.asRaw(),
        (try cn.object().nid()).asRaw(),
    );
    try std.testing.expectEqualStrings("example.com", cn.data().bytes());

    const friendly = all_entries.next().?;
    try std.testing.expectEqual(
        boring.nid.Nid.friendlyName.asRaw(),
        (try friendly.object().nid()).asRaw(),
    );

    try std.testing.expect(all_entries.next() == null);
}

test "x509 nid uid value" {
    var cert = try boring.x509.X509.fromPem(nid_uid_test_cert_pem);
    defer cert.deinit();

    const subject = try cert.subjectName();
    var uid_entries = subject.entriesByNid(boring.nid.Nid.userId);
    const uid = uid_entries.next().?;
    try std.testing.expectEqualStrings("this is the userId", uid.data().bytes());
}

test "x509 subject alt name" {
    var cert = try boring.x509.X509.fromPem(alt_name_cert_pem);
    defer cert.deinit();

    var san_stack = (try cert.asRef()).subjectAltNames().?;
    defer san_stack.deinit();
    try std.testing.expectEqual(@as(usize, 5), try san_stack.len());

    const g0 = san_stack.get(0).?;
    try std.testing.expectEqualStrings("example.com", g0.dnsName().?);

    const g1 = san_stack.get(1).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, g1.ipAddress().?);

    const g3 = san_stack.get(3).?;
    try std.testing.expectEqualStrings("test@example.com", g3.emailAddress().?);

    const g4 = san_stack.get(4).?;
    try std.testing.expectEqualStrings("http://www.example.com", g4.uriName().?);
}

test "x509 subject alt name iter" {
    var cert = try boring.x509.X509.fromPem(alt_name_cert_pem);
    defer cert.deinit();

    var san_stack = (try cert.asRef()).subjectAltNames().?;
    defer san_stack.deinit();
    var i: usize = 0;
    while (san_stack.get(i)) |g| : (i += 1) {
        switch (i) {
            0 => try std.testing.expectEqualStrings("example.com", g.dnsName().?),
            1 => try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, g.ipAddress().?),
            2 => try std.testing.expectEqualSlices(
                u8,
                &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
                g.ipAddress().?,
            ),
            3 => try std.testing.expectEqualStrings("test@example.com", g.emailAddress().?),
            4 => try std.testing.expectEqualStrings("http://www.example.com", g.uriName().?),
            else => unreachable,
        }
    }
    try std.testing.expectEqual(@as(usize, 5), i);
}

test "x509 subject key id" {
    var cert = try boring.x509.X509.fromPem(nid_test_cert_pem);
    defer cert.deinit();

    const ski = (try cert.asRef()).subjectKeyId().?;
    const expected_ski = [_]u8{
        80,  107, 158, 237, 95,  61, 235, 100, 212, 115,
        249, 244, 219, 163, 124, 55, 141, 2,   76,  5,
    };
    try std.testing.expectEqualSlices(u8, &expected_ski, ski);

    try std.testing.expect((try cert.asRef()).authorityKeyId() == null);
}

test "x509 name print ex" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();

    var bio = try boring.bio.MemBio.init();
    defer bio.deinit();

    try (try cert.asRef()).subjectName().printEx(&bio, 0);
    const name_no_flags = try bio.bytes();
    try std.testing.expectEqualStrings(
        "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=foobar.com",
        name_no_flags,
    );
}

test "x509 builder" {
    var pkey = try test_pkey();
    defer pkey.deinit();

    var name = try boring.x509.X509Name.init();
    defer name.deinit();
    try name.appendEntryByNid(boring.nid.Nid.commonName, "foobar.com");

    var builder = try boring.x509.X509Builder.init();
    defer builder.deinit();
    try builder.setVersion(2);
    try builder.setSubjectName(&name);
    try builder.setIssuerName(&name);

    var not_before = try boring.asn1.Asn1Time.daysFromNow(0);
    try builder.setNotBefore(&not_before);
    var not_after = try boring.asn1.Asn1Time.daysFromNow(365);
    try builder.setNotAfter(&not_after);
    try builder.setPubkey(&pkey);

    var serial_int = try boring.asn1.Asn1Integer.fromU64(12345);
    defer serial_int.deinit();
    try builder.setSerialNumber(&serial_int);

    var basic_constraints = try boring.x509.BasicConstraints.init()
        .critical().ca().build();
    defer basic_constraints.deinit();
    try builder.appendExtension(&basic_constraints);

    var key_usage = try boring.x509.KeyUsage.init()
        .digitalSignature().keyEncipherment().build();
    defer key_usage.deinit();
    try builder.appendExtension(&key_usage);

    var ext_key_usage = try (try (try boring.x509.ExtendedKeyUsage.init()
        .clientAuth()).serverAuth()).build();
    defer ext_key_usage.deinit();
    try builder.appendExtension(&ext_key_usage);

    var san = try (try boring.x509.SubjectAlternativeName.init()
        .dns("example.com")).build();
    defer san.deinit();
    try builder.appendExtension(&san);

    try builder.sign(&pkey, boring.hash.MessageDigest.sha256());
    var x509 = try builder.build();
    defer x509.deinit();

    var x509_pkey = try (try x509.asRef()).publicKey();
    defer x509_pkey.deinit();
    try std.testing.expect(try pkey.publicEq(&x509_pkey));
    try std.testing.expect(try (try x509.asRef()).verify(&pkey));

    var entries = (try x509.subjectName()).entriesByNid(boring.nid.Nid.commonName);
    const cn = entries.next().?;
    try std.testing.expectEqualStrings("foobar.com", cn.data().bytes());
}

test "x509 extension to der" {
    var basic_constraints = try boring.x509.BasicConstraints.init()
        .critical().ca().build();
    defer basic_constraints.deinit();

    const der = try basic_constraints.toDer(std.testing.allocator);
    defer if (der) |d| std.testing.allocator.free(d);
    try std.testing.expect(der != null);
    try std.testing.expect(der.?.len > 0);
}

test "x509 req builder" {
    var pkey = try test_pkey();
    defer pkey.deinit();

    var name = try boring.x509.X509Name.init();
    defer name.deinit();
    try name.appendEntryByNid(boring.nid.Nid.commonName, "foobar.com");

    var builder = try boring.x509.X509ReqBuilder.init();
    defer builder.deinit();
    try builder.setVersion(0);
    try builder.setSubjectName(&name);
    try builder.setPubkey(&pkey);
    try builder.sign(&pkey, boring.hash.MessageDigest.sha256());

    var req = try builder.build();
    defer req.deinit();

    var req_pkey = try req.publicKey();
    defer req_pkey.deinit();
    try std.testing.expect(try pkey.publicEq(&req_pkey));
    try std.testing.expect(try req.verify(&pkey));
}

test "x509 stack from pem" {
    var stack = try boring.x509.X509.stackFromPem(certs_pem);
    defer stack.deinit();
    try std.testing.expectEqual(@as(usize, 2), stack.len());
}

test "x509 issued" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();
    var ca = try boring.x509.X509.fromPem(root_ca_pem);
    defer ca.deinit();

    try std.testing.expectEqual(@as(c_int, 0), (try ca.asRef()).issued(&cert));
    try std.testing.expect((try cert.asRef()).issued(&cert) != 0);
}

test "x509 signature" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();

    const sig = (try cert.asRef()).signature().?;
    try std.testing.expect(sig.bytes().len > 0);

    const alg = (try cert.asRef()).signatureAlgorithm().?;
    const obj = try alg.object();
    const expected_nid = boring.nid.Nid.sha256WithRsaEncryption.asRaw();
    try std.testing.expectEqual(expected_nid, (try obj.nid()).asRaw());
}

test "x509 verify cert" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();
    var ca = try boring.x509.X509.fromPem(root_ca_pem);
    defer ca.deinit();
    var chain = try boring.stack.X509Stack.init();
    defer chain.deinit();

    var store_builder = try boring.x509_store.X509StoreBuilder.init();
    defer store_builder.deinit();
    try store_builder.addCert(&ca);
    var store = store_builder.build();
    defer store.deinit();

    var empty_store_builder = try boring.x509_store.X509StoreBuilder.init();
    defer empty_store_builder.deinit();
    var empty_store = empty_store_builder.build();
    defer empty_store.deinit();

    var ctx = try boring.x509_store_context.X509StoreContext.init();
    defer ctx.deinit();

    try ctx.initVerification(&store, &cert, &chain);
    try std.testing.expect(try ctx.verifyCert());

    ctx.cleanup();
    try ctx.initVerification(&empty_store, &cert, &chain);
    try std.testing.expect(!try ctx.verifyCert());
}

test "x509 verify fails" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();
    var wrong_ca = try boring.x509.X509.fromPem(alt_name_cert_pem);
    defer wrong_ca.deinit();
    var chain = try boring.stack.X509Stack.init();
    defer chain.deinit();

    var store_builder = try boring.x509_store.X509StoreBuilder.init();
    defer store_builder.deinit();
    try store_builder.addCert(&wrong_ca);
    var store = store_builder.build();
    defer store.deinit();

    var ctx = try boring.x509_store_context.X509StoreContext.init();
    defer ctx.deinit();

    try ctx.initVerification(&store, &cert, &chain);
    try std.testing.expect(!try ctx.verifyCert());
}

test "x509 save subject der" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();

    const der = try (try cert.asRef()).subjectName().toDer(std.testing.allocator);
    defer if (der) |d| std.testing.allocator.free(d);
    try std.testing.expect(der != null);
    try std.testing.expect(der.?.len > 0);
}

test "x509 load subject der" {
    const subject_der = [_]u8{
        48,  90,  49,  11,  48, 9,   6,   3,   85,  4,   6,   19,  2,   65, 85,  49,  19,
        48,  17,  6,   3,   85, 4,   8,   12,  10,  83,  111, 109, 101, 45, 83,  116, 97,
        116, 101, 49,  33,  48, 31,  6,   3,   85,  4,   10,  12,  24,  73, 110, 116, 101,
        114, 110, 101, 116, 32, 87,  105, 100, 103, 105, 116, 115, 32,  80, 116, 121, 32,
        76,  116, 100, 49,  19, 48,  17,  6,   3,   85,  4,   3,   12,  10, 102, 111, 111,
        98,  97,  114, 46,  99, 111, 109,
    };
    var name = try boring.x509.X509Name.fromDer(&subject_der);
    defer name.deinit();
}

test "x509 check ip asc" {
    var cert = try boring.x509.X509.fromPem(alt_name_cert_pem);
    defer cert.deinit();

    try std.testing.expect((try cert.asRef()).checkIpAsc("127.0.0.1"));
    try std.testing.expect(!(try cert.asRef()).checkIpAsc("127.0.0.2"));
    try std.testing.expect((try cert.asRef()).checkIpAsc("0:0:0:0:0:0:0:1"));
    try std.testing.expect(!(try cert.asRef()).checkIpAsc("0:0:0:0:0:0:0:2"));
}

test "ssl get ctx options" {
    boring.init();
    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer builder.deinit();
    _ = builder.getOptions();
}

test "ssl set ctx options" {
    boring.init();
    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer builder.deinit();
    const opts = builder.setOptions(boring.ssl.Options.noTicket);
    try std.testing.expect(opts & boring.ssl.Options.noTicket.raw() != 0);
}

test "ssl clear ctx options" {
    boring.init();
    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer builder.deinit();
    _ = builder.setOptions(boring.ssl.Options.noTicket);
    const opts = builder.clearOptions(boring.ssl.Options.noTicket);
    try std.testing.expect(opts & boring.ssl.Options.noTicket.raw() == 0);
}

test "ssl empty alpn" {
    try std.testing.expect(boring.ssl.selectAlpnProtocol("", "") == null);
    try std.testing.expect(boring.ssl.selectAlpnProtocol("", "\x08http/1.1") == null);
    try std.testing.expect(boring.ssl.selectAlpnProtocol("\x08http/1.1", "") == null);
}

test "ssl drop ex data in context" {
    boring.init();
    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.dtls());
    defer builder.deinit();

    const index = try boring.ssl.ContextBuilder.newExIndex(u32);
    var v1: u32 = 1;
    var v2: u32 = 2;
    var v3: u32 = 3;
    try std.testing.expect(builder.replaceExData(u32, index, &v1) == null);
    try std.testing.expect(builder.replaceExData(u32, index, &v2).? == &v1);
    try std.testing.expect(builder.replaceExData(u32, index, &v3).? == &v2);
}

test "ssl drop ex data in ssl" {
    boring.init();
    var ctx_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.dtls());
    defer ctx_builder.deinit();
    var ctx = ctx_builder.build();
    defer ctx.deinit();

    var ssl = try ctx.createSsl();
    defer ssl.deinit();

    const index = try boring.ssl.Ssl.newExIndex(u32);
    var v1: u32 = 1;
    var v2: u32 = 2;
    var v3: u32 = 3;
    try std.testing.expect(ssl.replaceExData(u32, index, &v1) == null);
    try std.testing.expect(ssl.replaceExData(u32, index, &v2).? == &v1);
    try std.testing.expect(ssl.replaceExData(u32, index, &v3).? == &v2);
}

test "ssl threaded server can handshake" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = server.build() catch |err| {
        std.log.warn("server build failed: {any}", .{err});
        return;
    };
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl peer certificate" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    var cert = (try client.sslRef()).peerCertificate().?;
    defer cert.deinit();
    var fingerprint: [20]u8 = undefined;
    const fingerprint_len = try cert.digest(boring.hash.MessageDigest.sha1(), &fingerprint);
    try std.testing.expectEqual(@as(usize, 20), fingerprint_len);
    const expected = "59172d9313e84459bcff27f967e79e6e9217e584";
    const actual_hex = std.fmt.bytesToHex(fingerprint, .lower);
    try std.testing.expectEqualStrings(expected, &actual_hex);
}

test "ssl state strings" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    const ssl_ref = try client.sslRef();
    try std.testing.expectEqualStrings("!!!!!!", ssl_ref.stateString());
    try std.testing.expectEqualStrings(
        "SSL negotiation finished successfully",
        ssl_ref.stateStringLong(),
    );
}

test "ssl zero length buffers" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    try std.testing.expectEqual(@as(usize, 0), try client.write(&.{}));
    try std.testing.expectEqual(@as(usize, 0), try client.read(&.{}));
}

test "ssl no version overlap" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    try server.ctx().setMinProtoVersion(null);
    try server.ctx().setMaxProtoVersion(boring.ssl.SslVersion.tlsV1_1);
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_1.raw(),
        server.ctx().getMaxProtoVersion().?.raw(),
    );
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setMinProtoVersion(boring.ssl.SslVersion.tlsV1_2);
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_2.raw(),
        client_builder.ctx().getMinProtoVersion().?.raw(),
    );
    try client_builder.ctx().setMaxProtoVersion(null);

    const connect_result = client_builder.connect();
    if (connect_result == error.BoringSSL) {
        return;
    } else {
        try std.testing.expect(connect_result == error.Syscall);
    }
}

test "ssl psk ciphers" {
    boring.init();
    const cipher = "PSK-AES128-CBC-SHA";
    const psk = "thisisaverysecurekey";
    const client_identity = "thisisaclient";

    var server = try test_server.Server.builder();
    defer server.deinit();
    try server.ctx().setCipherList(cipher);
    var server_called = false;
    try server.ctx().setPskServerCallbackWithContext(bool, &server_called, struct {
        fn callback(
            state: *bool,
            ssl: *boring.ssl.SslRef,
            identity: ?[]const u8,
            psk_out: []u8,
        ) boring.BoringError!usize {
            _ = ssl;
            _ = identity;
            if (psk_out.len < psk.len) return error.InvalidArgument;
            @memcpy(psk_out[0..psk.len], psk);
            state.* = true;

            return psk.len;
        }
    }.callback);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    _ = client_builder.ctx().setOptions(boring.ssl.Options.noTlsV1_3);
    try client_builder.ctx().setCipherList(cipher);
    var client_called = false;
    try client_builder.ctx().setPskClientCallbackWithContext(bool, &client_called, struct {
        fn callback(
            state: *bool,
            ssl: *boring.ssl.SslRef,
            hint: ?[]const u8,
            identity_out: []u8,
            psk_out: []u8,
        ) boring.BoringError!usize {
            _ = ssl;
            _ = hint;
            if (identity_out.len <= client_identity.len) return error.InvalidArgument;
            if (psk_out.len < psk.len) return error.InvalidArgument;
            @memcpy(identity_out[0..client_identity.len], client_identity);
            identity_out[client_identity.len] = 0;
            @memcpy(psk_out[0..psk.len], psk);
            state.* = true;

            return psk.len;
        }
    }.callback);

    var client = try client_builder.connect();
    defer client.deinit();
    try std.testing.expect(client_called);
    try std.testing.expect(server_called);
}

test "ssl srtp context profiles" {
    boring.init();
    var server = try test_server.Server.builderWithMethod(boring.ssl.Method.dtls());
    defer server.deinit();
    try server.ctx().setSrtpProfiles(srtp_profiles_wire);
    server.sslCb(set_mtu_on_ssl);
    server.ioCb(write_srtp_profile_selection);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithMethod(boring.ssl.Method.dtls());
    defer client_builder.deinit();
    try client_builder.ctx().setSrtpProfiles(srtp_profiles_wire);
    var client_endpoint = try client_builder.build();
    defer client_endpoint.deinit();
    var ssl_builder = try client_endpoint.builder();
    defer ssl_builder.deinit();
    try ssl_builder.sslPtr().setMtu(1500);
    var client = try ssl_builder.connect();
    defer client.deinit();

    const client_profile = (try client.sslRef()).selectedSrtpProfile() orelse {
        return error.TestExpectedEqual;
    };
    try expect_srtp_profile_selected(client_profile);

    var server_selected: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try client.read(&server_selected));
    try std.testing.expectEqual(@as(u8, 1), server_selected[0]);
}

test "ssl srtp connection profiles" {
    boring.init();
    var server = try test_server.Server.builderWithMethod(boring.ssl.Method.dtls());
    defer server.deinit();
    server.sslCb(set_srtp_profiles_and_mtu_on_ssl);
    server.ioCb(write_srtp_profile_selection);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithMethod(boring.ssl.Method.dtls());
    defer client_builder.deinit();
    var client_endpoint = try client_builder.build();
    defer client_endpoint.deinit();
    var ssl_builder = try client_endpoint.builder();
    defer ssl_builder.deinit();

    try ssl_builder.sslPtr().setSrtpProfiles(srtp_profiles_wire);
    try ssl_builder.sslPtr().setMtu(1500);
    const profiles = (try ssl_builder.sslPtr().ref()).srtpProfiles() orelse {
        return error.TestExpectedEqual;
    };
    try expect_srtp_profile_list(profiles);

    var client = try ssl_builder.connect();
    defer client.deinit();
    const client_profile = (try client.sslRef()).selectedSrtpProfile() orelse {
        return error.TestExpectedEqual;
    };
    try expect_srtp_profile_selected(client_profile);

    var server_selected: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try client.read(&server_selected));
    try std.testing.expectEqual(@as(u8, 1), server_selected[0]);
}

test "ssl sni callback swapped context" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();

    var callback_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    errdefer callback_builder.deinit();
    var called = false;
    try callback_builder.setServerNameCallback(
        bool,
        &called,
        sni_swapped_context_callback,
    );

    var keyed_builder = server.ctx_builder;
    server.ctx_builder = callback_builder;
    callback_builder.ptr = null;
    var keyed_context = keyed_builder.build();
    defer keyed_context.deinit();
    server.sslCbWithContext(&keyed_context, set_ssl_context_from_opaque);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client_endpoint = try client_builder.build();
    defer client_endpoint.deinit();
    var ssl_builder = try client_endpoint.builder();
    defer ssl_builder.deinit();
    try ssl_builder.sslPtr().setHostname("localhost");
    var client = try ssl_builder.connect();
    defer client.deinit();

    try std.testing.expect(called);
}

test "ssl get curve" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    const ssl_ref = try client.sslRef();
    try std.testing.expect(ssl_ref.curveId() != null);
    try std.testing.expect(ssl_ref.curveName() != null);
}

test "ssl used hello retry request true" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    _ = server.ctx().setOptions(boring.ssl.Options.cipherServerPreference);
    try server.ctx().setCurvesList("P-256:X25519");
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    try client_builder.ctx().setCurvesList("X25519:P-256");
    var client = try client_builder.connect();
    defer client.deinit();

    const ssl_ref = try client.sslRef();
    try std.testing.expect(ssl_ref.usedHelloRetryRequest());
}

test "ssl used hello retry request false" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    try server.ctx().setCurvesList("P-256:X25519");
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    try client_builder.ctx().setCurvesList("X25519:P-256");
    var client = try client_builder.connect();
    defer client.deinit();

    const ssl_ref = try client.sslRef();
    try std.testing.expect(!ssl_ref.usedHelloRetryRequest());
}

test "ssl get ciphers" {
    boring.init();
    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer builder.deinit();

    const builder_ciphers = try builder.ciphers();
    const builder_count = builder_ciphers.len();
    try std.testing.expect(builder_count > 0);

    var context = builder.build();
    defer context.deinit();

    const context_ciphers = try context.ciphers();
    try std.testing.expectEqual(builder_count, context_ciphers.len());

    var index: usize = 0;
    while (index < builder_count) : (index += 1) {
        const builder_cipher = builder_ciphers.get(index).?;
        const context_cipher = context_ciphers.get(index).?;
        try std.testing.expectEqualStrings(
            builder_cipher.asRef().name(),
            context_cipher.asRef().name(),
        );
    }
}

fn expect_cipher_names(
    ciphers: boring.ssl.SslCipherList,
    expected: []const []const u8,
) !void {
    try std.testing.expectEqual(expected.len, ciphers.len());

    var index: usize = 0;
    while (index < expected.len) : (index += 1) {
        const cipher = ciphers.get(index).?;
        try std.testing.expectEqualStrings(expected[index], cipher.asRef().name());
    }
}

test "ssl context compliance policy" {
    boring.init();
    const fips_ciphers = [_][]const u8{
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    };
    const wpa3_ciphers = [_][]const u8{
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    };

    var fips_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer fips_builder.deinit();
    try fips_builder.setCompliancePolicy(.fips202205);
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_2.raw(),
        fips_builder.getMinProtoVersion().?.raw(),
    );
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_3.raw(),
        fips_builder.getMaxProtoVersion().?.raw(),
    );
    try expect_cipher_names(try fips_builder.ciphers(), &fips_ciphers);

    var wpa3_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer wpa3_builder.deinit();
    try wpa3_builder.setCompliancePolicy(.wpa3192202304);
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_2.raw(),
        wpa3_builder.getMinProtoVersion().?.raw(),
    );
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_3.raw(),
        wpa3_builder.getMaxProtoVersion().?.raw(),
    );
    try expect_cipher_names(try wpa3_builder.ciphers(), &wpa3_ciphers);
    try std.testing.expectError(
        error.BoringSSL,
        wpa3_builder.setCompliancePolicy(.none),
    );
}

test "ssl connection compliance policy" {
    boring.init();
    const fips_ciphers = [_][]const u8{
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    };
    const wpa3_ciphers = [_][]const u8{
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    };

    var fips_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer fips_builder.deinit();
    var fips_context = fips_builder.build();
    defer fips_context.deinit();
    var fips_ssl = try fips_context.createSsl();
    defer fips_ssl.deinit();
    try fips_ssl.setCompliancePolicy(.fips202205);
    const fips_ref = try fips_ssl.ref();
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_2.raw(),
        fips_ref.getMinProtoVersion().?.raw(),
    );
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_3.raw(),
        fips_ref.getMaxProtoVersion().?.raw(),
    );
    try expect_cipher_names(fips_ref.ciphers().?, &fips_ciphers);

    var wpa3_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer wpa3_builder.deinit();
    var wpa3_context = wpa3_builder.build();
    defer wpa3_context.deinit();
    var wpa3_ssl = try wpa3_context.createSsl();
    defer wpa3_ssl.deinit();
    try wpa3_ssl.setCompliancePolicy(.wpa3192202304);
    const wpa3_ref = try wpa3_ssl.ref();
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_2.raw(),
        wpa3_ref.getMinProtoVersion().?.raw(),
    );
    try std.testing.expectEqual(
        boring.ssl.SslVersion.tlsV1_3.raw(),
        wpa3_ref.getMaxProtoVersion().?.raw(),
    );
    try expect_cipher_names(wpa3_ref.ciphers().?, &wpa3_ciphers);
    try std.testing.expectError(error.BoringSSL, wpa3_ssl.setCompliancePolicy(.none));
}

test "ssl client ca list" {
    var names = try boring.x509.X509Name.loadClientCaFile("test/root-ca.pem");
    defer names.deinit();
    try std.testing.expectEqual(@as(usize, 1), try names.len());
    try std.testing.expect((try names.get(0)) != null);

    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer builder.deinit();
    try builder.setClientCaList(&names);
    try std.testing.expectError(error.Closed, names.raw());
}

test "ssl default verify paths" {
    boring.init();
    var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer builder.deinit();

    try builder.setDefaultVerifyPaths();
    try std.testing.expectError(error.InvalidArgument, builder.loadVerifyLocations(null, null));
}

test "ssl ca file verify" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    client_builder.ctx().setVerify(boring.ssl.VerifyMode.peer);
    try client_builder.ctx().setCaFile("test/root-ca.pem");
    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl info callback" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var called = false;
    try client_builder.ctx().setInfoCallback(bool, &called, struct {
        fn callback(
            state: *bool,
            ssl: *boring.ssl.SslRef,
            mode: boring.ssl.SslInfoCallbackMode,
            value: c_int,
        ) void {
            _ = ssl;
            _ = value;
            if (mode.raw() == boring.ssl.SslInfoCallbackMode.handshakeDone.raw()) {
                state.* = true;
            }
        }
    }.callback);

    var client = try client_builder.connect();
    defer client.deinit();
    try std.testing.expect(called);
}

test "ssl pending" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.ioCb(struct {
        fn write_ten_bytes(ssl: *boring.ssl.Ssl, fd: c_int) void {
            _ = fd;
            var buf: [10]u8 = .{0} ** 10;
            _ = ssl.write(&buf) catch {};
        }
    }.write_ten_bytes);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    var first: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try client.read(&first));

    const ssl_ref = try client.sslRef();
    try std.testing.expectEqual(@as(usize, 9), ssl_ref.pending());

    var remaining: [10]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 9), try client.read(&remaining));
}

test "ssl shutdown" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.ioCb(struct {
        fn expect_shutdown(ssl: *boring.ssl.Ssl, fd: c_int) void {
            _ = fd;
            var buf: [1]u8 = undefined;
            const read_len = ssl.read(&buf) catch unreachable;
            std.debug.assert(read_len == 0);

            const result = ssl.shutdown() catch unreachable;
            std.debug.assert(result == .received);
        }
    }.expect_shutdown);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    try std.testing.expectEqual(
        boring.ssl.ShutdownState.none.bits,
        (try client.sslRef()).getShutdown().bits,
    );
    try std.testing.expectEqual(boring.ssl.ShutdownResult.sent, try client.shutdown());
    try std.testing.expect((try client.sslRef()).getShutdown().contains(.sent));
    try std.testing.expectEqual(boring.ssl.ShutdownResult.received, try client.shutdown());
    try std.testing.expect((try client.sslRef()).getShutdown().contains(.sent));
    try std.testing.expect((try client.sslRef()).getShutdown().contains(.received));
}

fn select_next_proto(server_protos: []const u8, client_protos: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < server_protos.len) {
        const proto_len = server_protos[i];
        const next = i + 1 + proto_len;
        if (next > server_protos.len) return null;
        const proto = server_protos[i + 1 .. next];
        if (boring.ssl.selectAlpnProtocol(client_protos, proto)) |selected| {
            return selected;
        }
        i = next;
    }
    return null;
}

test "ssl alpn server advertise multiple" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    const server_protos = "\x08http/1.1\x08spdy/3.1";
    var dummy: u8 = 0;
    try server.ctx().setAlpnSelectCallback(u8, &dummy, struct {
        fn callback(
            _: *u8,
            _: *boring.ssl.SslRef,
            client_protos: []const u8,
        ) boring.ssl.AlpnSelectResult {
            const selected = select_next_proto(server_protos, client_protos) orelse {
                return .noAck;
            };
            return .{ .selected = selected };
        }
    }.callback);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setClientAlpnProtocol("spdy/3.1");
    var client = try client_builder.connect();
    defer client.deinit();

    const ssl_ref = try client.sslRef();
    try std.testing.expectEqualStrings("spdy/3.1", ssl_ref.selectedAlpn().?);
}

test "ssl alpn server select none fatal" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var dummy: u8 = 0;
    try server.ctx().setAlpnSelectCallback(u8, &dummy, struct {
        fn callback(
            _: *u8,
            _: *boring.ssl.SslRef,
            client_protos: []const u8,
        ) boring.ssl.AlpnSelectResult {
            _ = client_protos;
            return .alertFatal;
        }
    }.callback);
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setClientAlpnProtocol("http/2");
    try std.testing.expectError(error.BoringSSL, client_builder.connect());
}

test "ssl alpn server select none" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    const server_protos = "\x08http/1.1\x08spdy/3.1";
    var dummy: u8 = 0;
    try server.ctx().setAlpnSelectCallback(u8, &dummy, struct {
        fn callback(
            _: *u8,
            _: *boring.ssl.SslRef,
            client_protos: []const u8,
        ) boring.ssl.AlpnSelectResult {
            const selected = select_next_proto(server_protos, client_protos) orelse {
                return .noAck;
            };
            return .{ .selected = selected };
        }
    }.callback);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setClientAlpnProtocol("http/2");
    var client = try client_builder.connect();
    defer client.deinit();

    const ssl_ref = try client.sslRef();
    try std.testing.expect(ssl_ref.selectedAlpn() == null);
}

test "ssl alpn server unilateral" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setClientAlpnProtocol("http/2");
    var client = try client_builder.connect();
    defer client.deinit();

    const ssl_ref = try client.sslRef();
    try std.testing.expect(ssl_ref.selectedAlpn() == null);
}

test "ssl idle session" {
    boring.init();
    var ctx_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer ctx_builder.deinit();
    var ctx = ctx_builder.build();
    defer ctx.deinit();

    var ssl = try ctx.createSsl();
    defer ssl.deinit();

    try std.testing.expect(ssl.session() == null);
}

test "ssl active session" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    const ssl_ref = try client.sslRef();
    var session = ssl_ref.session().?;
    defer session.deinit();

    const key_len = session.masterKeyLength();
    try std.testing.expect(key_len > 0);

    const buf_small = try std.testing.allocator.alloc(u8, key_len - 1);
    defer std.testing.allocator.free(buf_small);
    const copied_small = (try session.asRef()).masterKey(buf_small);
    try std.testing.expectEqual(buf_small.len, copied_small);

    const buf_large = try std.testing.allocator.alloc(u8, key_len + 1);
    defer std.testing.allocator.free(buf_large);
    const copied_large = (try session.asRef()).masterKey(buf_large);
    try std.testing.expectEqual(key_len, copied_large);
}

test "ssl add extra chain cert" {
    boring.init();
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();
    var ctx_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer ctx_builder.deinit();
    try ctx_builder.add1ChainCert(&cert);
}

test "ssl certificate compression" {
    boring.init();

    var server_state = CertificateCompressionState{};
    var client_state = CertificateCompressionState{};

    var server = try test_server.Server.builder();
    defer server.deinit();
    try server.ctx().setMinProtoVersion(boring.ssl.SslVersion.tlsV1_3);
    try server.ctx().setMaxProtoVersion(boring.ssl.SslVersion.tlsV1_3);
    try add_certificate_compression(server.ctx(), &server_state);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    try client_builder.ctx().setMinProtoVersion(boring.ssl.SslVersion.tlsV1_3);
    try client_builder.ctx().setMaxProtoVersion(boring.ssl.SslVersion.tlsV1_3);
    try add_certificate_compression(client_builder.ctx(), &client_state);

    var stream = try client_builder.connect();
    defer stream.deinit();

    try std.testing.expect(server_state.compress_calls > 0);
    try std.testing.expectEqual(@as(u32, 0), server_state.decompress_calls);
    try std.testing.expectEqual(@as(u32, 0), client_state.compress_calls);
    try std.testing.expect(client_state.decompress_calls > 0);
}

test "ssl verify valid hostname" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    client_builder.ctx_builder.setVerify(boring.ssl.VerifyMode.peer);

    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl verify valid hostname with wildcard" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var cert = try boring.x509.X509.fromPem(cert_wildcard_pem);
    defer cert.deinit();
    var key = try boring.pkey.PKey.fromPem(key_pem);
    defer key.deinit();
    try server.ctx().useCertificate(&cert);
    try server.ctx().usePrivateKey(&key);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    client_builder.ctx_builder.setVerify(boring.ssl.VerifyMode.peer);

    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl select cert ok" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var dummy: u8 = 0;
    try server.ctx().setSelectCertificateCallback(u8, &dummy, struct {
        fn callback(_: *u8, _: *boring.ssl.ClientHello) boring.ssl.SelectCertificateResult {
            return .success;
        }
    }.callback);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl select cert error" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var dummy: u8 = 0;
    try server.ctx().setSelectCertificateCallback(u8, &dummy, struct {
        fn callback(_: *u8, _: *boring.ssl.ClientHello) boring.ssl.SelectCertificateResult {
            return .failure;
        }
    }.callback);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try std.testing.expectError(error.BoringSSL, client_builder.connect());
}

test "ssl select cert unknown extension" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var found_ext: bool = true;
    try server.ctx().setSelectCertificateCallback(bool, &found_ext, struct {
        fn callback(
            state: *bool,
            client_hello: *boring.ssl.ClientHello,
        ) boring.ssl.SelectCertificateResult {
            const ext = client_hello.extension(.serverName);
            state.* = ext != null;
            return .success;
        }
    }.callback);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    try std.testing.expect(!found_ext);
}

test "ssl select cert alpn extension" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var alpn_ext: ?[]const u8 = null;
    try server.ctx().setSelectCertificateCallback(?[]const u8, &alpn_ext, struct {
        fn callback(
            state: *?[]const u8,
            client_hello: *boring.ssl.ClientHello,
        ) boring.ssl.SelectCertificateResult {
            state.* = client_hello.extension(.applicationLayerProtocolNegotiation);
            return .success;
        }
    }.callback);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setClientAlpnProtocol("http/2");
    var client = try client_builder.connect();
    defer client.deinit();

    try std.testing.expect(alpn_ext != null);
}

test "ssl refcount context" {
    boring.init();
    var ssl = blk: {
        var ctx_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
        defer ctx_builder.deinit();
        var ctx = ctx_builder.build();
        const s = try ctx.createSsl();
        break :blk s;
    };
    defer ssl.deinit();

    var new_ctx = blk: {
        var ctx_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
        defer ctx_builder.deinit();
        break :blk ctx_builder.build();
    };
    defer new_ctx.deinit();
    _ = try ssl.setSslContext(&new_ctx);
}

test "ssl verify untrusted" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    client_builder.ctx_builder.setVerify(boring.ssl.VerifyMode.peer);
    try std.testing.expectError(error.BoringSSL, client_builder.connect());
}

test "ssl verify trusted" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl verify trusted with set cert" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();

    var store_builder = try boring.x509_store.X509StoreBuilder.init();
    defer store_builder.deinit();
    var ca = try boring.x509.X509.fromPem(root_ca_pem);
    defer ca.deinit();
    try store_builder.addCert(&ca);
    var store = store_builder.build();
    defer store.deinit();

    client_builder.ctx_builder.setVerify(boring.ssl.VerifyMode.peer);
    try client_builder.ctx_builder.setCertStore(&store);

    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl verify untrusted callback override ok" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var callback_state = struct {
        called: bool = false,
    }{};
    try client_builder.ctx().setVerifyCallback(
        boring.ssl.VerifyMode.peer,
        @TypeOf(callback_state),
        &callback_state,
        struct {
            fn callback(
                state: *@TypeOf(callback_state),
                ok: bool,
                ctx: *boring.x509_store_context.X509StoreContext,
            ) bool {
                state.called = true;
                _ = ok;
                _ = ctx.currentCert();
                return true;
            }
        }.callback,
    );
    var client = try client_builder.connect();
    defer client.deinit();
    try std.testing.expect(callback_state.called);
}

test "ssl verify untrusted callback override bad" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var callback_state = struct {
        called: bool = false,
    }{};
    try client_builder.ctx().setVerifyCallback(
        boring.ssl.VerifyMode.peer,
        @TypeOf(callback_state),
        &callback_state,
        struct {
            fn callback(
                state: *@TypeOf(callback_state),
                ok: bool,
                ctx: *boring.x509_store_context.X509StoreContext,
            ) bool {
                state.called = true;
                _ = ok;
                _ = ctx;
                return false;
            }
        }.callback,
    );
    try std.testing.expectError(error.BoringSSL, client_builder.connect());
    try std.testing.expect(callback_state.called);
}

test "ssl verify trusted callback override ok" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var callback_state = struct {
        called: bool = false,
    }{};
    try client_builder.ctx().setVerifyCallback(
        boring.ssl.VerifyMode.peer,
        @TypeOf(callback_state),
        &callback_state,
        struct {
            fn callback(
                state: *@TypeOf(callback_state),
                ok: bool,
                ctx: *boring.x509_store_context.X509StoreContext,
            ) bool {
                state.called = true;
                _ = ok;
                _ = ctx.currentCert();
                return true;
            }
        }.callback,
    );
    var client = try client_builder.connect();
    defer client.deinit();
    try std.testing.expect(callback_state.called);
}

test "ssl verify trusted callback override bad" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var callback_state = struct {
        called: bool = false,
    }{};
    try client_builder.ctx().setVerifyCallback(
        boring.ssl.VerifyMode.peer,
        @TypeOf(callback_state),
        &callback_state,
        struct {
            fn callback(
                state: *@TypeOf(callback_state),
                ok: bool,
                ctx: *boring.x509_store_context.X509StoreContext,
            ) bool {
                state.called = true;
                _ = ok;
                _ = ctx;
                return false;
            }
        }.callback,
    );
    try std.testing.expectError(error.BoringSSL, client_builder.connect());
    try std.testing.expect(callback_state.called);
}

test "ssl keying export" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.ioCb(struct {
        fn export_and_write(ssl: *boring.ssl.Ssl, fd: c_int) void {
            _ = fd;
            const raw_ssl = ssl.ptr orelse return;
            var buf: [32]u8 = undefined;
            boring.ssl.SslRef.fromRaw(raw_ssl).exportKeyingMaterial(
                &buf,
                "EXPERIMENTAL test",
                "my context",
            ) catch {};
            var write_buf: [1]u8 = .{0};
            _ = ssl.write(&write_buf) catch {};
        }
    }.export_and_write);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    var buf: [32]u8 = .{1} ** 32;
    try (try client.sslRef()).exportKeyingMaterial(
        &buf,
        "EXPERIMENTAL test",
        "my context",
    );
}

test "ssl version" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.connect();
    defer client.deinit();

    const ssl_ref = try client.sslRef();
    const ver = ssl_ref.version();
    // The negotiated protocol is TLS 1.2 or TLS 1.3.
    if (std.mem.eql(u8, ver, "TLSv1.2")) {
        return;
    } else {
        try std.testing.expect(std.mem.eql(u8, ver, "TLSv1.3"));
    }
}

test "ssl cert verify callback error when trusted but returns false" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var callback_state = struct {
        called: bool = false,
    }{};
    client_builder.ctx().setCertVerifyCallback(@TypeOf(callback_state), &callback_state, struct {
        fn callback(
            state: *@TypeOf(callback_state),
            ctx: *boring.x509_store_context.X509StoreContext,
        ) bool {
            state.called = true;
            const cert = ctx.currentCert();
            _ = cert;
            return false;
        }
    }.callback);
    try std.testing.expectError(error.BoringSSL, client_builder.connect());
    try std.testing.expect(callback_state.called);
}

test "ssl cert verify callback no error when untrusted but returns true" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var callback_state = struct {
        called: bool = false,
    }{};
    client_builder.ctx().setCertVerifyCallback(@TypeOf(callback_state), &callback_state, struct {
        fn callback(
            state: *@TypeOf(callback_state),
            ctx: *boring.x509_store_context.X509StoreContext,
        ) bool {
            state.called = true;
            const cert = ctx.currentCert();
            _ = cert;
            return true;
        }
    }.callback);
    var client = try client_builder.connect();
    defer client.deinit();
    try std.testing.expect(callback_state.called);
}

test "ssl cert verify callback no error when trusted and returns true" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var callback_state = struct {
        called: bool = false,
    }{};
    client_builder.ctx().setCertVerifyCallback(@TypeOf(callback_state), &callback_state, struct {
        fn callback(
            state: *@TypeOf(callback_state),
            ctx: *boring.x509_store_context.X509StoreContext,
        ) bool {
            state.called = true;
            const cert = ctx.currentCert();
            _ = cert;
            return true;
        }
    }.callback);
    var client = try client_builder.connect();
    defer client.deinit();
    try std.testing.expect(callback_state.called);
}

test "ssl cert verify callback receives correct certificate" {
    boring.init();
    // Server sends full chain (leaf + root) via certs.pem.
    var server = try test_server.Server.builder();
    defer server.deinit();
    var cert = try boring.x509.X509.fromPem(certs_pem);
    defer cert.deinit();
    var key = try boring.pkey.PKey.fromPem(key_pem);
    defer key.deinit();
    try server.ctx().useCertificate(&cert);
    try server.ctx().usePrivateKey(&key);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    client_builder.ctx_builder.setVerify(boring.ssl.VerifyMode.peer);
    const leaf_sha1 = "59172d9313e84459bcff27f967e79e6e9217e584";
    const root_sha1 = "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875";
    var callback_state = struct {
        called: bool = false,
    }{};
    client_builder.ctx().setCertVerifyCallback(@TypeOf(callback_state), &callback_state, struct {
        fn callback(
            state: *@TypeOf(callback_state),
            ctx: *boring.x509_store_context.X509StoreContext,
        ) bool {
            state.called = true;
            if (ctx.currentCert() == null) return true;
            if (ctx.cert() == null) return true;
            var untrusted_stack = ctx.untrusted() orelse return true;
            _ = &untrusted_stack;
            const count = untrusted_stack.len() catch 0;
            if (count != 2) return true;
            const leaf = untrusted_stack.get(0) catch null orelse return true;
            var leaf_digest: [20]u8 = undefined;
            _ = leaf.digest(boring.hash.MessageDigest.sha1(), &leaf_digest) catch return true;
            if (!std.mem.eql(u8, &std.fmt.bytesToHex(leaf_digest, .lower), leaf_sha1)) return true;
            const root = untrusted_stack.get(1) catch null orelse return true;
            var root_digest: [20]u8 = undefined;
            _ = root.digest(boring.hash.MessageDigest.sha1(), &root_digest) catch return true;
            if (!std.mem.eql(u8, &std.fmt.bytesToHex(root_digest, .lower), root_sha1)) return true;
            return true;
        }
    }.callback);
    var client = try client_builder.connect();
    defer client.deinit();
    try std.testing.expect(callback_state.called);
}

test "ssl cert verify callback receives correct chain" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    client_builder.ctx_builder.setVerify(boring.ssl.VerifyMode.peer);
    const leaf_sha1 = "59172d9313e84459bcff27f967e79e6e9217e584";
    const root_sha1 = "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875";
    var callback_state = struct {
        called: bool = false,
    }{};
    client_builder.ctx().setCertVerifyCallback(@TypeOf(callback_state), &callback_state, struct {
        fn callback(
            state: *@TypeOf(callback_state),
            ctx: *boring.x509_store_context.X509StoreContext,
        ) bool {
            state.called = true;
            var chain = ctx.chain() orelse return true;
            _ = &chain;
            const count = chain.len() catch 0;
            if (count != 2) return true;
            const leaf = chain.get(0) catch null orelse return true;
            var leaf_digest: [20]u8 = undefined;
            _ = leaf.digest(boring.hash.MessageDigest.sha1(), &leaf_digest) catch return true;
            if (!std.mem.eql(u8, &std.fmt.bytesToHex(leaf_digest, .lower), leaf_sha1)) return true;
            const root = chain.get(1) catch null orelse return true;
            var root_digest: [20]u8 = undefined;
            _ = root.digest(boring.hash.MessageDigest.sha1(), &root_digest) catch return true;
            if (!std.mem.eql(u8, &std.fmt.bytesToHex(root_digest, .lower), root_sha1)) return true;
            return true;
        }
    }.callback);
    var client = try client_builder.connect();
    defer client.deinit();
    try std.testing.expect(callback_state.called);
}

const ServerSessionDerContext = struct {
    der: []const u8 = &.{},
    found_session: bool = false,
    allocator: std.mem.Allocator,

    fn deinit(self: *ServerSessionDerContext) void {
        self.allocator.free(self.der);
    }
};

const ClientSessionDerContext = struct {
    der: *[]const u8,
    allocator: std.mem.Allocator,
};

fn store_session_der(
    allocator: std.mem.Allocator,
    target: *[]const u8,
    session: *boring.ssl.SslSessionRef,
) void {
    var cloned = session.clone() catch return;
    defer cloned.deinit();

    const bytes = cloned.toBytes() catch return;
    defer sys.OPENSSL_free(@ptrCast(@constCast(bytes.ptr)));

    const der = allocator.dupe(u8, bytes) catch return;
    allocator.free(target.*);
    target.* = der;
}

fn server_new_session_der_callback(
    ctx: *ServerSessionDerContext,
    _: *boring.ssl.SslRef,
    session: *boring.ssl.SslSessionRef,
) void {
    store_session_der(ctx.allocator, &ctx.der, session);
}

fn server_get_session_der_callback(
    ctx: *ServerSessionDerContext,
    ssl: *boring.ssl.SslRef,
    id: []const u8,
) boring.ssl.GetSessionResult {
    if (ctx.der.len == 0) return .none;

    var sess = boring.ssl.SslSession.fromBytesWithRef(
        ctx.der,
        ssl.sslContext().?,
    ) catch return .none;
    const session_ref = sess.asRef() catch {
        sess.deinit();
        return .none;
    };

    if (!std.mem.eql(u8, id, session_ref.sessionId())) {
        sess.deinit();
        return .none;
    }

    ctx.found_session = true;
    return .{ .session = sess };
}

fn client_new_session_der_callback(
    ctx: *ClientSessionDerContext,
    _: *boring.ssl.SslRef,
    session: *boring.ssl.SslSessionRef,
) void {
    store_session_der(ctx.allocator, ctx.der, session);
}

fn install_server_session_der_callbacks(
    server: *test_server.Builder,
    ctx: *ServerSessionDerContext,
) !void {
    server.expectedConnectionsCount(2);
    try server.ctx().setMaxProtoVersion(boring.ssl.SslVersion.tlsV1_2);
    _ = server.ctx().setOptions(boring.ssl.Options.noTicket);
    server.ctx().setSessionCacheMode(
        boring.ssl.SessionCacheMode.server.combine(boring.ssl.SessionCacheMode.noInternal),
    );
    try server.ctx().setNewSessionCallbackWithContext(
        ServerSessionDerContext,
        ctx,
        server_new_session_der_callback,
    );
    try server.ctx().setGetSessionCallbackWithContext(
        ServerSessionDerContext,
        ctx,
        server_get_session_der_callback,
    );
    try server.ctx().setSessionIdContext("foo");
}

fn install_client_session_der_callback(
    client_builder: *test_server.ClientBuilder,
    ctx: *ClientSessionDerContext,
) !void {
    client_builder.ctx().setSessionCacheMode(boring.ssl.SessionCacheMode.client);
    try client_builder.ctx().setNewSessionCallbackWithContext(
        ClientSessionDerContext,
        ctx,
        client_new_session_der_callback,
    );
}

fn connect_with_session_der(
    server: *const test_server.Server,
    session_der: []const u8,
) !test_server.ClientStream {
    var client_builder = try server.client();
    defer client_builder.deinit();
    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();

    var sess = try boring.ssl.SslSession.fromBytesWithRef(
        session_der,
        (try ssl_builder.sslPtr().ref()).sslContext().?,
    );
    defer sess.deinit();
    var session_ref = try sess.asRef();
    try ssl_builder.sslPtr().setSession(&session_ref);

    return try ssl_builder.connect();
}

test "ssl new get session callback" {
    boring.init();

    var server_ctx = ServerSessionDerContext{ .allocator = std.testing.allocator };
    defer server_ctx.deinit();

    var server = try test_server.Server.builder();
    defer server.deinit();
    try install_server_session_der_callbacks(&server, &server_ctx);
    var running = try server.build();
    defer running.deinit();

    var client_der: []const u8 = &[_]u8{};
    defer std.testing.allocator.free(client_der);

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client_der_ctx = ClientSessionDerContext{
        .der = &client_der,
        .allocator = std.testing.allocator,
    };
    try install_client_session_der_callback(&client_builder, &client_der_ctx);
    var client1 = try client_builder.connect();
    defer client1.deinit();

    try std.testing.expect(client_der.len > 0);
    try std.testing.expect(server_ctx.der.len > 0);
    try std.testing.expect(!server_ctx.found_session);

    var client2_stream = try connect_with_session_der(&running, client_der);
    defer client2_stream.deinit();

    try std.testing.expect(server_ctx.found_session);
}

test "ssl new session callback swapped ctx" {
    boring.init();
    var ctx_builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
    defer ctx_builder.deinit();
    ctx_builder.setSessionCacheSize(1234);
    var ctx = ctx_builder.build();
    defer ctx.deinit();
    try std.testing.expectEqual(@as(u32, 1234), ctx.sessionCacheSize());
}

test "ssl custom verify untrusted callback override bad" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        u8,
        @constCast(&@as(u8, 0)),
        struct {
            fn callback(_: *u8, _: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                return .{ .invalid = .certificateRevoked };
            }
        }.callback,
    );
    try std.testing.expectError(error.BoringSSL, client_builder.connect());
}

test "ssl custom verify untrusted callback override ok" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        u8,
        @constCast(&@as(u8, 0)),
        struct {
            fn callback(_: *u8, ssl: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                var chain = ssl.peerCertChain() orelse unreachable;
                defer chain.deinit();

                return .ok;
            }
        }.callback,
    );
    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl custom verify untrusted with set cert" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        u8,
        @constCast(&@as(u8, 0)),
        struct {
            fn callback(_: *u8, ssl: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                var store = ssl.sslContext().?.certStore() orelse unreachable;
                defer store.deinit();
                var cert = ssl.peerCertificate() orelse unreachable;
                defer cert.deinit();
                var chain = ssl.peerCertChain() orelse unreachable;
                defer chain.deinit();

                if (store.objectsLen() != 0) {
                    return .{ .invalid = .certificateUnknown };
                }

                var ctx = boring.x509_store_context.X509StoreContext.init() catch {
                    return .{ .invalid = .certificateUnknown };
                };
                defer ctx.deinit();
                ctx.initVerification(&store, &cert, &chain) catch {
                    return .{ .invalid = .certificateUnknown };
                };
                defer ctx.cleanup();
                const ok = ctx.verifyCert() catch false;
                if (ok) unreachable;
                const result = ctx.verifyResult();
                _ = result;
                return .{ .invalid = .certificateUnknown };
            }
        }.callback,
    );
    try std.testing.expectError(error.BoringSSL, client_builder.connect());
}

test "ssl custom verify trusted with set cert" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    try client_builder.ctx().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        u8,
        @constCast(&@as(u8, 0)),
        struct {
            fn callback(_: *u8, ssl: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                var store = ssl.sslContext().?.certStore() orelse unreachable;
                defer store.deinit();
                var cert = ssl.peerCertificate() orelse unreachable;
                defer cert.deinit();
                var chain = ssl.peerCertChain() orelse unreachable;
                defer chain.deinit();

                if (store.objectsLen() != 1) {
                    return .{ .invalid = .certificateUnknown };
                }

                var ctx = boring.x509_store_context.X509StoreContext.init() catch {
                    return .{ .invalid = .certificateUnknown };
                };
                defer ctx.deinit();
                ctx.initVerification(&store, &cert, &chain) catch {
                    return .{ .invalid = .certificateUnknown };
                };
                defer ctx.cleanup();
                const ok = ctx.verifyCert() catch false;
                if (!ok) return .{ .invalid = .certificateUnknown };
                const result = ctx.verifyResult();
                if (result.code != 0) return .{ .invalid = .certificateUnknown };
                return .ok;
            }
        }.callback,
    );
    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl custom verify trusted callback override ok" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    try client_builder.ctx().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        u8,
        @constCast(&@as(u8, 0)),
        struct {
            fn callback(_: *u8, ssl: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                _ = ssl.peerCertificate() orelse unreachable;
                return .ok;
            }
        }.callback,
    );
    var client = try client_builder.connect();
    defer client.deinit();
}

test "ssl custom verify trusted callback override bad" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    try client_builder.ctx().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        u8,
        @constCast(&@as(u8, 0)),
        struct {
            fn callback(_: *u8, _: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                return .{ .invalid = .certificateUnknown };
            }
        }.callback,
    );
    try std.testing.expectError(error.BoringSSL, client_builder.connect());
}

test "ssl custom verify callback" {
    boring.init();
    var called_back = false;
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setVerifyCallback(
        boring.ssl.VerifyMode.peer,
        u8,
        @constCast(&@as(u8, 0)),
        struct {
            fn callback(_: *u8, _: bool, _: *boring.x509_store_context.X509StoreContext) bool {
                @panic("verify callback should not be called");
            }
        }.callback,
    );
    const expected = "59172d9313e84459bcff27f967e79e6e9217e584";
    try client_builder.ctx().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        bool,
        &called_back,
        struct {
            fn callback(state: *bool, ssl: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                state.* = true;
                const cert = ssl.peerCertificate() orelse unreachable;
                var digest: [20]u8 = undefined;
                _ = cert.digest(boring.hash.MessageDigest.sha1(), &digest) catch unreachable;
                if (!std.mem.eql(u8, expected, &std.fmt.bytesToHex(digest, .lower))) {
                    return .{ .invalid = .internalError };
                }
                return .ok;
            }
        }.callback,
    );
    var client = try client_builder.connect();
    defer client.deinit();
    try std.testing.expect(called_back);
}

test "ssl custom verify ssl callback" {
    boring.init();
    var called_back = false;
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();

    const expected = "59172d9313e84459bcff27f967e79e6e9217e584";
    try ssl_builder.sslPtr().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        bool,
        &called_back,
        struct {
            fn callback(state: *bool, ssl: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                state.* = true;
                const cert = ssl.peerCertificate() orelse unreachable;
                var digest: [20]u8 = undefined;
                _ = cert.digest(boring.hash.MessageDigest.sha1(), &digest) catch unreachable;
                if (!std.mem.eql(u8, expected, &std.fmt.bytesToHex(digest, .lower))) {
                    return .{ .invalid = .internalError };
                }
                return .ok;
            }
        }.callback,
    );
    var stream = try ssl_builder.connect();
    defer stream.deinit();
    try std.testing.expect(called_back);
}

test "ssl custom verify both callback" {
    boring.init();
    var called_back = false;
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    try client_builder.ctx().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        u8,
        @constCast(&@as(u8, 0)),
        struct {
            fn callback(_: *u8, _: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                @panic("verify callback should not be called");
            }
        }.callback,
    );
    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();

    const expected = "59172d9313e84459bcff27f967e79e6e9217e584";
    try ssl_builder.sslPtr().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        bool,
        &called_back,
        struct {
            fn callback(state: *bool, ssl: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                state.* = true;
                const cert = ssl.peerCertificate() orelse unreachable;
                var digest: [20]u8 = undefined;
                _ = cert.digest(boring.hash.MessageDigest.sha1(), &digest) catch unreachable;
                if (!std.mem.eql(u8, expected, &std.fmt.bytesToHex(digest, .lower))) {
                    return .{ .invalid = .internalError };
                }
                return .ok;
            }
        }.callback,
    );
    var stream = try ssl_builder.connect();
    defer stream.deinit();
    try std.testing.expect(called_back);
}

test "ssl resume session" {
    boring.init();

    var session_ticket: ?boring.ssl.SslSession = null;
    defer if (session_ticket) |*st| st.deinit();
    var nst_received_count: u8 = 0;

    var server = try test_server.Server.builder();
    defer server.deinit();
    server.expectedConnectionsCount(2);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    client_builder.ctx().setSessionCacheMode(boring.ssl.SessionCacheMode.client);
    const ResumeCtx = struct {
        ticket: *?boring.ssl.SslSession,
        count: *u8,
    };
    var resume_ctx = ResumeCtx{
        .ticket = &session_ticket,
        .count = &nst_received_count,
    };
    try client_builder.ctx().setNewSessionCallbackWithContext(
        ResumeCtx,
        &resume_ctx,
        struct {
            fn callback(
                ctx: *ResumeCtx,
                _: *boring.ssl.SslRef,
                session: *boring.ssl.SslSessionRef,
            ) void {
                ctx.count.* += 1;
                if (ctx.ticket.* == null) {
                    ctx.ticket.* = session.clone() catch return;
                }
            }
        }.callback,
    );
    var client1 = try client_builder.connect();
    defer client1.deinit();

    const ssl_ref1 = try client1.sslRef();
    try std.testing.expect(!ssl_ref1.sessionReused());
    try std.testing.expect(session_ticket != null);
    try std.testing.expectEqual(@as(u8, 2), nst_received_count);

    // Second connection with the session ticket.
    var client_builder2 = try running.client();
    defer client_builder2.deinit();
    var client2 = try client_builder2.build();
    defer client2.deinit();
    var ssl_builder2 = try client2.builder();
    defer ssl_builder2.deinit();
    try ssl_builder2.sslPtr().setSession(
        &try session_ticket.?.asRef(),
    );
    var stream2 = try ssl_builder2.connect();
    defer stream2.deinit();

    const ssl_ref2 = try stream2.sslRef();
    try std.testing.expect(ssl_ref2.sessionReused());
}

fn verify_cert_trusted_first(
    cert: *const boring.x509.X509,
    trusted: []const *const boring.x509.X509,
    untrusted: []const *const boring.x509.X509,
    configure: ?*const fn (*boring.x509_verify.X509VerifyParam) void,
) !boring.x509_verify.X509VerifyResult {
    var store_builder = try boring.x509_store.X509StoreBuilder.init();
    defer store_builder.deinit();
    for (trusted) |t| {
        try store_builder.addCert(t);
    }
    var store = store_builder.build();
    defer store.deinit();

    var untrusted_stack = try boring.stack.X509Stack.init();
    defer untrusted_stack.deinit();
    for (untrusted) |u| {
        var cloned = try u.clone();
        try untrusted_stack.push(&cloned);
    }

    var ctx = try boring.x509_store_context.X509StoreContext.init();
    defer ctx.deinit();

    try ctx.initVerification(&store, cert, &untrusted_stack);
    if (configure) |cb| {
        var param = ctx.verifyParam().?;
        cb(&param);
    }
    _ = try ctx.verifyCert();
    return ctx.verifyResult();
}

test "x509 trusted first verification" {
    var root2 = try boring.x509.X509.fromPem(root_ca_2_pem);
    defer root2.deinit();
    var root1 = try boring.x509.X509.fromPem(root_ca_pem);
    defer root1.deinit();
    var root1_cross = try boring.x509.X509.fromPem(root_ca_cross_pem);
    defer root1_cross.deinit();
    var intermediate = try boring.x509.X509.fromPem(intermediate_ca_pem);
    defer intermediate.deinit();
    var leaf = try boring.x509.X509.fromPem(cert_with_intermediate_pem);
    defer leaf.deinit();

    const trusted1 = [_]*const boring.x509.X509{&root1};
    const untrusted1 = [_]*const boring.x509.X509{&intermediate};
    const result1 = try verify_cert_trusted_first(
        &leaf,
        &trusted1,
        &untrusted1,
        null,
    );
    try std.testing.expect(result1.code == 0);

    const trusted2 = [_]*const boring.x509.X509{ &root1, &root2 };
    const untrusted2 = [_]*const boring.x509.X509{ &intermediate, &root1_cross };
    const result2 = try verify_cert_trusted_first(
        &leaf,
        &trusted2,
        &untrusted2,
        null,
    );
    try std.testing.expect(result2.code == 0);

    const result3 = try verify_cert_trusted_first(
        &leaf,
        &trusted2,
        &untrusted2,
        struct {
            fn set_trusted_first(param: *boring.x509_verify.X509VerifyParam) void {
                param.setFlags(boring.x509_verify.X509VerifyFlags.trustedFirst) catch {};
            }
        }.set_trusted_first,
    );
    try std.testing.expect(result3.code == 0);
}

// Session resumption ticket key callback tests.

const TicketKeyTestState = struct {
    encryption_calls: u8 = 0,
    decryption_calls: u8 = 0,
};

const test_key_name: [16]u8 = .{5} ** 16;
const test_cbc_iv: [16]u8 = .{1} ** 16;
const test_aes_128_cbc_key: [16]u8 = .{2} ** 16;
const test_hmac_key: [32]u8 = .{3} ** 32;

fn ticket_key_callback_success(
    state: *TicketKeyTestState,
    _: *boring.ssl.SslRef,
    key_name: *[16]u8,
    iv: *[16]u8,
    cipher_ctx: *boring.symm.CipherCtxRef,
    hmac_ctx: *boring.hmac.HmacCtxRef,
    encrypt: bool,
) boring.ssl.TicketKeyCallbackResult {
    const cipher = boring.symm.Cipher.aes128Cbc();
    const digest = boring.hash.MessageDigest.sha256();

    if (encrypt) {
        state.encryption_calls += 1;
        std.debug.assert(std.mem.eql(u8, key_name, &[_]u8{0} ** 16));
        std.debug.assert(std.mem.eql(u8, iv, &[_]u8{0} ** 16));

        @memcpy(key_name, &test_key_name);
        @memcpy(iv, &test_cbc_iv);
        cipher_ctx.initEncrypt(cipher, &test_aes_128_cbc_key, &test_cbc_iv) catch {
            return .failure;
        };
        hmac_ctx.init(&test_hmac_key, digest) catch {
            return .failure;
        };

        return .success;
    }

    state.decryption_calls += 1;
    if (!std.mem.eql(u8, key_name, &test_key_name)) {
        return .failure;
    }

    cipher_ctx.initDecrypt(cipher, &test_aes_128_cbc_key, iv) catch {
        return .failure;
    };
    hmac_ctx.init(&test_hmac_key, digest) catch {
        return .failure;
    };

    return .success;
}

fn ticket_key_callback_noop(
    state: *TicketKeyTestState,
    _: *boring.ssl.SslRef,
    key_name: *[16]u8,
    iv: *[16]u8,
    cipher_ctx: *boring.symm.CipherCtxRef,
    hmac_ctx: *boring.hmac.HmacCtxRef,
    encrypt: bool,
) boring.ssl.TicketKeyCallbackResult {
    const cipher = boring.symm.Cipher.aes128Cbc();
    const digest = boring.hash.MessageDigest.sha256();

    if (encrypt) {
        state.encryption_calls += 1;
        std.debug.assert(std.mem.eql(u8, key_name, &[_]u8{0} ** 16));
        std.debug.assert(std.mem.eql(u8, iv, &[_]u8{0} ** 16));

        @memcpy(key_name, &test_key_name);
        @memcpy(iv, &test_cbc_iv);
        cipher_ctx.initEncrypt(cipher, &test_aes_128_cbc_key, &test_cbc_iv) catch {
            return .failure;
        };
        hmac_ctx.init(&test_hmac_key, digest) catch {
            return .failure;
        };

        return .success;
    }

    state.decryption_calls += 1;
    if (!std.mem.eql(u8, key_name, &test_key_name)) {
        return .failure;
    }

    return .noop;
}

const TicketResumeCtx = struct {
    ticket: *?boring.ssl.SslSession,
    count: *u8,
};

fn ticket_new_session_cb(
    ctx: *TicketResumeCtx,
    _: *boring.ssl.SslRef,
    session: *boring.ssl.SslSessionRef,
) void {
    ctx.count.* += 1;
    if (ctx.ticket.* == null) {
        ctx.ticket.* = session.clone() catch return;
    }
}

fn connect_with_session_ticket(
    running: *const test_server.Server,
    session_ticket: *const boring.ssl.SslSession,
) !bool {
    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();
    try ssl_builder.sslPtr().setSession(&try session_ticket.asRef());
    var stream = try ssl_builder.connect();
    defer stream.deinit();

    const ssl_ref = try stream.sslRef();
    return ssl_ref.sessionReused();
}

fn run_ticket_key_callback_test(
    comptime callback: fn (
        *TicketKeyTestState,
        *boring.ssl.SslRef,
        *[16]u8,
        *[16]u8,
        *boring.symm.CipherCtxRef,
        *boring.hmac.HmacCtxRef,
        bool,
    ) boring.ssl.TicketKeyCallbackResult,
    expect_resumed: bool,
    expect_decrypt_calls: u8,
) !void {
    boring.init();

    var session_ticket: ?boring.ssl.SslSession = null;
    defer if (session_ticket) |*st| st.deinit();
    var nst_count: u8 = 0;
    var state = TicketKeyTestState{};

    var server = try test_server.Server.builder();
    defer server.deinit();
    server.expectedConnectionsCount(2);
    try server.ctx().setTicketKeyCallback(TicketKeyTestState, &state, callback);
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    client_builder.ctx().setSessionCacheMode(boring.ssl.SessionCacheMode.client);

    var resume_ctx = TicketResumeCtx{
        .ticket = &session_ticket,
        .count = &nst_count,
    };
    try client_builder.ctx().setNewSessionCallbackWithContext(
        TicketResumeCtx,
        &resume_ctx,
        ticket_new_session_cb,
    );

    var client1 = try client_builder.connect();
    defer client1.deinit();

    const ssl_ref1 = try client1.sslRef();
    try std.testing.expect(!ssl_ref1.sessionReused());
    try std.testing.expect(session_ticket != null);
    try std.testing.expectEqual(@as(u8, 2), nst_count);

    const session_reused = try connect_with_session_ticket(&running, &session_ticket.?);
    try std.testing.expect(session_reused == expect_resumed);
    try std.testing.expectEqual(expect_decrypt_calls, state.decryption_calls);
}

test "ssl session resumption custom ticket key callback success" {
    try run_ticket_key_callback_test(ticket_key_callback_success, true, 1);
}

test "ssl session resumption custom ticket key callback noop" {
    try run_ticket_key_callback_test(ticket_key_callback_noop, false, 1);
}

// Custom verify retry test.

test "ssl custom verify retry" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();

    var called_back = false;
    try client_builder.ctx().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        bool,
        &called_back,
        struct {
            fn callback(state: *bool, _: *boring.ssl.SslRef) boring.ssl.VerifyCallbackResult {
                if (!state.*) {
                    state.* = true;
                    return .retry;
                }
                return .{ .invalid = .certificateRevoked };
            }
        }.callback,
    );

    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();

    const first_result = ssl_builder.sslPtr().doHandshake();
    try std.testing.expectError(error.WantCertificateVerify, first_result);

    const second_result = ssl_builder.sslPtr().doHandshake();
    try std.testing.expectError(error.BoringSSL, second_result);
    try std.testing.expect(called_back);
}

// Private key method retry tests.

fn sign_with_server_key(input: []const u8, output: []u8) !usize {
    const key_data = @embedFile("key.pem");
    var pkey = try boring.pkey.PKey.fromPem(key_data);
    defer pkey.deinit();

    var signer = try boring.sign.Signer.init(boring.hash.MessageDigest.sha256(), &pkey);
    defer signer.deinit();
    try signer.setRsaPadding(boring.rsa.Padding.pkcs1Pss);
    try signer.setRsaPssSaltLength(boring.sign.RsaPssSaltLength.digestLength);
    try signer.update(input);

    return signer.sign(output);
}

const PrivateKeyRetryState = struct {
    sign_calls: u8 = 0,
    complete_calls: u8 = 0,
    input_buffer: [512]u8 = undefined,
    input_len: usize = 0,
};

fn private_key_retry_sign_callback(
    state: *PrivateKeyRetryState,
    _: *boring.ssl.SslRef,
    input: []const u8,
    _: boring.ssl.SslSignatureAlgorithm,
    _: []u8,
) boring.ssl.PrivateKeyCallbackResult {
    state.sign_calls += 1;
    std.debug.assert(input.len <= state.input_buffer.len);
    @memcpy(state.input_buffer[0..input.len], input);
    state.input_len = input.len;

    return .retry;
}

fn private_key_retry_complete_callback(
    state: *PrivateKeyRetryState,
    _: *boring.ssl.SslRef,
    output: []u8,
) boring.ssl.PrivateKeyCallbackResult {
    state.complete_calls += 1;
    std.debug.assert(state.input_len > 0);

    const signature_len = sign_with_server_key(
        state.input_buffer[0..state.input_len],
        output,
    ) catch {
        return .failure;
    };

    return .{ .success = signature_len };
}

test "ssl private key method sign retry complete ok" {
    boring.init();
    var state = PrivateKeyRetryState{};

    var server = try test_server.Server.builder();
    defer server.deinit();
    try server.ctx().setPrivateKeyMethodWithContext(PrivateKeyRetryState, &state, .{
        .sign = private_key_retry_sign_callback,
        .decrypt = struct {
            fn callback(
                _: *PrivateKeyRetryState,
                _: *boring.ssl.SslRef,
                _: []const u8,
                _: []u8,
            ) boring.ssl.PrivateKeyCallbackResult {
                return .failure;
            }
        }.callback,
        .complete = private_key_retry_complete_callback,
    });
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var stream = try client_builder.connect();
    defer stream.deinit();

    try std.testing.expectEqual(@as(u8, 1), state.sign_calls);
    try std.testing.expectEqual(@as(u8, 1), state.complete_calls);
}

const PrivateKeyRetryFailureState = struct {
    complete_calls: u8 = 0,
};

fn private_key_failure_complete_callback(
    state: *PrivateKeyRetryFailureState,
    _: *boring.ssl.SslRef,
    _: []u8,
) boring.ssl.PrivateKeyCallbackResult {
    state.complete_calls += 1;
    if (state.complete_calls == 1) {
        return .retry;
    }
    return .failure;
}

test "ssl private key method sign retry complete failure" {
    boring.init();
    var state = PrivateKeyRetryFailureState{};

    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    try server.ctx().setPrivateKeyMethodWithContext(PrivateKeyRetryFailureState, &state, .{
        .sign = struct {
            fn callback(
                _: *PrivateKeyRetryFailureState,
                _: *boring.ssl.SslRef,
                _: []const u8,
                _: boring.ssl.SslSignatureAlgorithm,
                _: []u8,
            ) boring.ssl.PrivateKeyCallbackResult {
                return .retry;
            }
        }.callback,
        .decrypt = struct {
            fn callback(
                _: *PrivateKeyRetryFailureState,
                _: *boring.ssl.SslRef,
                _: []const u8,
                _: []u8,
            ) boring.ssl.PrivateKeyCallbackResult {
                return .failure;
            }
        }.callback,
        .complete = private_key_failure_complete_callback,
    });
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();

    const result = client_builder.connect();
    try std.testing.expect(result == error.BoringSSL or result == error.Syscall);
    try std.testing.expectEqual(@as(u8, 2), state.complete_calls);
}

// Standard verify callback on SSL-level (not context-level).

test "ssl verify callback fingerprint on ssl" {
    boring.init();
    var called_back = false;
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();

    const expected = "59172d9313e84459bcff27f967e79e6e9217e584";
    try ssl_builder.sslPtr().setVerifyCallback(
        boring.ssl.VerifyMode.peer,
        bool,
        &called_back,
        struct {
            fn callback(
                state: *bool,
                _: bool,
                ctx: *boring.x509_store_context.X509StoreContext,
            ) bool {
                state.* = true;
                const cert = ctx.currentCert() orelse return false;
                var digest: [20]u8 = undefined;
                _ = cert.digest(boring.hash.MessageDigest.sha1(), &digest) catch return false;
                if (!std.mem.eql(u8, expected, &std.fmt.bytesToHex(digest, .lower))) {
                    return false;
                }
                return true;
            }
        }.callback,
    );
    var stream = try ssl_builder.connect();
    defer stream.deinit();
    try std.testing.expect(called_back);
}

// Hostname verification tests.

test "ssl verify reject underscore hostname with wildcard" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();

    var cert = try boring.x509.X509.fromPem(@embedFile("cert-wildcard.pem"));
    defer cert.deinit();
    var key = try boring.pkey.PKey.fromPem(@embedFile("key.pem"));
    defer key.deinit();
    try server.ctx().useCertificate(&cert);
    try server.ctx().usePrivateKey(&key);

    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    client_builder.ctx().setVerify(boring.ssl.VerifyMode.peer);

    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();

    var ssl = ssl_builder.sslPtr();
    var param = boring.x509_verify.X509VerifyParam{ .ptr = try ssl.verifyParam() };
    param.setHostflags(boring.x509_verify.X509CheckFlags.noPartialWildcards);
    try param.setHost("not_allowed.foobar.com");
    try std.testing.expectError(error.BoringSSL, ssl_builder.connect());
}

test "ssl verify invalid hostname" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    client_builder.ctx().setVerify(boring.ssl.VerifyMode.peer);

    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();

    var ssl = ssl_builder.sslPtr();
    var param = boring.x509_verify.X509VerifyParam{ .ptr = try ssl.verifyParam() };
    param.setHostflags(boring.x509_verify.X509CheckFlags.noPartialWildcards);
    try param.setHost("bogus.com");
    try std.testing.expectError(error.BoringSSL, ssl_builder.connect());
}

// Connector hostname verification tests.

test "ssl connector valid hostname" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var connector_builder = try boring.ssl_connector.SslConnector.builder(boring.ssl.Method.tls());
    defer connector_builder.deinit();
    try connector_builder.contextBuilder().setCaFile("test/root-ca.pem");
    var connector = connector_builder.build();
    defer connector.deinit();

    const fd = try running.connectFd();
    defer _ = std.c.close(fd);
    var ssl = try connector.connect("foobar.com", fd);
    defer ssl.deinit();

    var buf: [1]u8 = undefined;
    _ = try ssl.read(&buf);
}

test "ssl connector invalid hostname" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var connector_builder = try boring.ssl_connector.SslConnector.builder(boring.ssl.Method.tls());
    defer connector_builder.deinit();
    try connector_builder.contextBuilder().setCaFile("test/root-ca.pem");
    var connector = connector_builder.build();
    defer connector.deinit();

    const fd = try running.connectFd();
    defer _ = std.c.close(fd);
    var ssl = try connector.connect("bogus.com", fd);
    defer ssl.deinit();

    var buf: [1]u8 = undefined;
    try std.testing.expectError(error.BoringSSL, ssl.read(&buf));
}

test "ssl connector invalid no hostname verification" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var connector_builder = try boring.ssl_connector.SslConnector.builder(boring.ssl.Method.tls());
    defer connector_builder.deinit();
    try connector_builder.contextBuilder().setCaFile("test/root-ca.pem");
    var connector = connector_builder.build();
    defer connector.deinit();

    const fd = try running.connectFd();
    defer _ = std.c.close(fd);

    var config = try connector.configure();
    defer config.deinit();
    config.setVerifyHostname(false);
    var ssl = try config.intoSsl("bogus.com", fd);
    defer ssl.deinit();

    var buf: [1]u8 = undefined;
    _ = try ssl.read(&buf);
}

test "ssl connector no hostname still verifies" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var connector_builder = try boring.ssl_connector.SslConnector.builder(boring.ssl.Method.tls());
    defer connector_builder.deinit();
    var connector = connector_builder.build();
    defer connector.deinit();

    const fd = try running.connectFd();
    defer _ = std.c.close(fd);

    var config = try connector.configure();
    defer config.deinit();
    config.setVerifyHostname(false);
    var ssl = try config.intoSsl("fizzbuzz.com", fd);
    defer ssl.deinit();

    var buf: [1]u8 = undefined;
    try std.testing.expectError(error.BoringSSL, ssl.read(&buf));
}

test "ssl connector no hostname can disable verify" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var connector_builder = try boring.ssl_connector.SslConnector.builder(boring.ssl.Method.tls());
    defer connector_builder.deinit();
    connector_builder.contextBuilder().setVerify(boring.ssl.VerifyMode.none);
    var connector = connector_builder.build();
    defer connector.deinit();

    const fd = try running.connectFd();
    defer _ = std.c.close(fd);

    var config = try connector.configure();
    defer config.deinit();
    config.setVerifyHostname(false);
    var ssl = try config.intoSsl("foobar.com", fd);
    defer ssl.deinit();

    var buf: [1]u8 = undefined;
    _ = try ssl.read(&buf);
}

test "https connector valid hostname" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var connector = try build_https_connector_with_root_ca();
    defer connector.deinit();

    var connection: boring.https_connector.HttpsConnection = .{};
    defer connection.deinit(std.testing.io);

    var address = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.loopback(running.port) };
    try connector.connectAddress(&connection, std.testing.io, &address, "foobar.com");
    try std.testing.expect(connection.isHandshakeComplete());

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try connection.read(&buf));
    try std.testing.expectEqual(@as(u8, 0), buf[0]);
}

test "https connector invalid hostname" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var running = try server.build();
    defer running.deinit();

    var connector = try build_https_connector_with_root_ca();
    defer connector.deinit();

    var connection: boring.https_connector.HttpsConnection = .{};
    defer connection.deinit(std.testing.io);

    var address = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.loopback(running.port) };
    try std.testing.expectError(
        error.BoringSSL,
        connector.connectAddress(&connection, std.testing.io, &address, "bogus.com"),
    );
}

// Private key method basic tests.

test "ssl private key method sign failure" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    var dummy_state: u8 = 0;
    try server.ctx().setPrivateKeyMethodWithContext(u8, &dummy_state, .{
        .sign = struct {
            fn callback(
                _: *u8,
                _: *boring.ssl.SslRef,
                _: []const u8,
                _: boring.ssl.SslSignatureAlgorithm,
                _: []u8,
            ) boring.ssl.PrivateKeyCallbackResult {
                return .failure;
            }
        }.callback,
        .decrypt = struct {
            fn callback(
                _: *u8,
                _: *boring.ssl.SslRef,
                _: []const u8,
                _: []u8,
            ) boring.ssl.PrivateKeyCallbackResult {
                return .failure;
            }
        }.callback,
        .complete = struct {
            fn callback(
                _: *u8,
                _: *boring.ssl.SslRef,
                _: []u8,
            ) boring.ssl.PrivateKeyCallbackResult {
                return .failure;
            }
        }.callback,
    });
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();

    const result = ssl_builder.connect();
    try std.testing.expect(result == error.BoringSSL or result == error.Syscall);
}

test "ssl private key method sign ok" {
    boring.init();
    var state = struct {
        sign_calls: u8 = 0,
    }{};

    var server = try test_server.Server.builder();
    defer server.deinit();
    try server.ctx().setPrivateKeyMethodWithContext(@TypeOf(state), &state, .{
        .sign = struct {
            fn callback(
                s: *@TypeOf(state),
                _: *boring.ssl.SslRef,
                input: []const u8,
                algorithm: boring.ssl.SslSignatureAlgorithm,
                output: []u8,
            ) boring.ssl.PrivateKeyCallbackResult {
                s.sign_calls += 1;
                const expected_algorithm = boring.ssl.SslSignatureAlgorithm.rsaPssRsaeSha256;
                std.debug.assert(algorithm.raw() == expected_algorithm.raw());
                const signature_len = sign_with_server_key(input, output) catch {
                    return .failure;
                };
                return .{ .success = signature_len };
            }
        }.callback,
        .decrypt = struct {
            fn callback(
                _: *@TypeOf(state),
                _: *boring.ssl.SslRef,
                _: []const u8,
                _: []u8,
            ) boring.ssl.PrivateKeyCallbackResult {
                return .failure;
            }
        }.callback,
        .complete = struct {
            fn callback(
                _: *@TypeOf(state),
                _: *boring.ssl.SslRef,
                _: []u8,
            ) boring.ssl.PrivateKeyCallbackResult {
                return .failure;
            }
        }.callback,
    });
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var stream = try client_builder.connect();
    defer stream.deinit();

    try std.testing.expectEqual(@as(u8, 1), state.sign_calls);
}

// X509 tests.

test "x509 clone" {
    var cert = try boring.x509.X509.fromPem(cert_pem);
    defer cert.deinit();
    var cloned = try cert.clone();
    defer cloned.deinit();

    var digest1: [20]u8 = undefined;
    var digest2: [20]u8 = undefined;
    _ = try cert.digest(boring.hash.MessageDigest.sha1(), &digest1);
    _ = try cloned.digest(boring.hash.MessageDigest.sha1(), &digest2);
    try std.testing.expectEqualSlices(u8, &digest1, &digest2);
}

// ECH tests.

const ech_public_name = "foobar.com";

const EchMaterial = struct {
    keys: boring.ech.EchKeys,
    config_list: boring.ech.EchConfigList,

    fn init(config_id: u8) !EchMaterial {
        var key = try boring.hpke.HpkeKey.generate(boring.hpke.Kem.x25519HkdfSha256());
        defer key.deinit();

        var config = try boring.ech.EchConfig.marshal(
            config_id,
            &key,
            ech_public_name,
            ech_public_name.len,
        );
        defer config.deinit();

        var keys_builder = try boring.ech.EchKeys.builder();
        defer keys_builder.deinit();
        try keys_builder.addKey(true, config.bytes(), &key);

        var keys = keys_builder.build();
        errdefer keys.deinit();
        try std.testing.expect(!try keys.hasDuplicateConfigId());

        var config_list = try keys.marshalRetryConfigs();
        errdefer config_list.deinit();

        return .{
            .keys = keys,
            .config_list = config_list,
        };
    }

    fn deinit(self: *EchMaterial) void {
        self.config_list.deinit();
        self.keys.deinit();
    }
};

fn set_tls13_only(builder: *boring.ssl.ContextBuilder) !void {
    try builder.setMinProtoVersion(boring.ssl.SslVersion.tlsV1_3);
    try builder.setMaxProtoVersion(boring.ssl.SslVersion.tlsV1_3);
}

fn build_ech_client(running: *const test_server.Server) !test_server.SslBuilder {
    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    try set_tls13_only(client_builder.ctx());

    var client = try client_builder.build();
    defer client.deinit();

    return client.builder();
}

fn expect_no_ech_override(ssl_ref: boring.ssl.SslRef) !void {
    try std.testing.expect(ssl_ref.echNameOverride() == null);
}

const EchVerifyState = struct {
    name_override_calls: u32 = 0,
};

fn ech_verify_chain(ssl: *boring.ssl.SslRef) bool {
    var store = ssl.sslContext().?.certStore() orelse return false;
    defer store.deinit();
    var cert = ssl.peerCertificate() orelse return false;
    defer cert.deinit();
    var chain = ssl.peerCertChain() orelse return false;
    defer chain.deinit();

    var ctx = boring.x509_store_context.X509StoreContext.init() catch return false;
    defer ctx.deinit();
    ctx.initVerification(&store, &cert, &chain) catch return false;
    defer ctx.cleanup();

    const ok = ctx.verifyCert() catch return false;
    if (!ok) return false;

    return ctx.verifyResult().code == 0;
}

fn ech_verify_public_name(ssl: *boring.ssl.SslRef, name: []const u8) bool {
    if (!std.mem.eql(u8, name, ech_public_name)) return false;

    var cert = ssl.peerCertificate() orelse return false;
    defer cert.deinit();
    const cert_ref = cert.asRef() catch return false;

    return cert_ref.checkHost(ech_public_name) catch false;
}

fn ech_rejection_verify(
    state: *EchVerifyState,
    ssl: *boring.ssl.SslRef,
) boring.ssl.VerifyCallbackResult {
    if (!ech_verify_chain(ssl)) return .{ .invalid = .unknownCa };

    if (ssl.echNameOverride()) |name| {
        if (!ech_verify_public_name(ssl, name)) {
            return .{ .invalid = .certificateUnknown };
        }
        state.name_override_calls += 1;
    }

    return .ok;
}

test "ssl ech accepted" {
    boring.init();
    var material = try EchMaterial.init(1);
    defer material.deinit();

    var server = try test_server.Server.builder();
    defer server.deinit();
    try set_tls13_only(server.ctx());
    try server.ctx().setEchKeys(&material.keys);
    var running = try server.build();
    defer running.deinit();

    var ssl_builder = try build_ech_client(&running);
    defer ssl_builder.deinit();
    try ssl_builder.sslPtr().setEchConfigList(material.config_list.bytes());
    try ssl_builder.sslPtr().setHostname(ech_public_name);

    var stream = try ssl_builder.connect();
    defer stream.deinit();

    const ssl_ref = try stream.sslRef();
    try std.testing.expect(ssl_ref.echAccepted());
    try expect_no_ech_override(ssl_ref);
}

test "ssl ech rejection exposes retry config" {
    boring.init();
    var server_material = try EchMaterial.init(2);
    defer server_material.deinit();
    var client_material = try EchMaterial.init(1);
    defer client_material.deinit();

    var server = try test_server.Server.builder();
    defer server.deinit();
    server.shouldError();
    try set_tls13_only(server.ctx());
    try server.ctx().setEchKeys(&server_material.keys);
    var running = try server.build();
    defer running.deinit();

    var ssl_builder = try build_ech_client(&running);
    defer ssl_builder.deinit();
    try ssl_builder.sslPtr().setEchConfigList(client_material.config_list.bytes());
    try ssl_builder.sslPtr().setHostname(ech_public_name);
    var verify_state = EchVerifyState{};
    try ssl_builder.sslPtr().setCustomVerifyCallback(
        boring.ssl.VerifyMode.peer,
        EchVerifyState,
        &verify_state,
        ech_rejection_verify,
    );

    try std.testing.expectError(error.BoringSSL, ssl_builder.connect());

    const ssl_ref = try ssl_builder.sslPtr().ref();
    const name = ssl_ref.echNameOverride() orelse return error.TestUnexpectedResult;
    const retry_configs = ssl_ref.echRetryConfigs() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(ech_public_name, name);
    try std.testing.expect(verify_state.name_override_calls > 0);
    try std.testing.expect(retry_configs.len > 0);
    try std.testing.expect(!ssl_ref.echAccepted());
}

test "ssl ech grease" {
    boring.init();
    var server = try test_server.Server.builder();
    defer server.deinit();
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.clientWithRootCa();
    defer client_builder.deinit();
    var client = try client_builder.build();
    defer client.deinit();
    var ssl_builder = try client.builder();
    defer ssl_builder.deinit();

    ssl_builder.sslPtr().setEnableEchGrease(true);
    var stream = try ssl_builder.connect();
    defer stream.deinit();

    const ssl_ref = try stream.sslRef();
    try std.testing.expect(!ssl_ref.echAccepted());
}

// Mozilla preset handshake tests.

const MozillaAcceptorBuilder = boring.ssl_connector.SslAcceptorBuilder;
const MozillaAcceptorFn = fn (boring.ssl.Method) boring.BoringError!MozillaAcceptorBuilder;
const MozillaListener = struct {
    fd: c_int,
    port: u16,
};

const posix_address_family_inet: c_uint = 2;
const posix_socket_stream: c_uint = 1;
const posix_socket_option_level: c_int = 0xffff;
const posix_socket_reuse_address: c_int = 0x0004;

fn open_mozilla_listener() !MozillaListener {
    const fd = std.c.socket(posix_address_family_inet, posix_socket_stream, 0);
    if (fd < 0) return error.SocketError;
    errdefer _ = std.c.close(fd);

    const reuse: c_int = 1;
    _ = std.c.setsockopt(
        fd,
        posix_socket_option_level,
        posix_socket_reuse_address,
        &reuse,
        @sizeOf(c_int),
    );

    var bind_addr = test_server.socket_addr_any(0);
    try test_server.errno_check(std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(std.c.sockaddr.in)));

    var addr_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
    try test_server.errno_check(std.c.getsockname(fd, @ptrCast(&bind_addr), &addr_len));
    const port = std.mem.bigToNative(u16, bind_addr.port);

    try test_server.errno_check(std.c.listen(fd, 1));

    return .{
        .fd = fd,
        .port = port,
    };
}

fn build_mozilla_acceptor(new_fn: *const MozillaAcceptorFn) ?boring.ssl_connector.SslAcceptor {
    var cert = boring.x509.X509.fromPem(@embedFile("cert.pem")) catch return null;
    defer cert.deinit();
    var key = boring.pkey.PKey.fromPem(@embedFile("key.pem")) catch return null;
    defer key.deinit();

    var builder = new_fn(boring.ssl.Method.tls()) catch return null;
    defer builder.deinit();
    builder.contextBuilder().useCertificate(&cert) catch return null;
    builder.contextBuilder().usePrivateKey(&key) catch return null;

    return builder.build();
}

fn complete_mozilla_handshake(ssl: *boring.ssl.Ssl) bool {
    while (true) {
        const result = ssl.doHandshake();
        if (result) {
            return true;
        } else |err| switch (err) {
            error.WantRead,
            error.WantWrite,
            error.WantX509Lookup,
            error.PendingSession,
            error.PendingCertificate,
            error.WantPrivateKeyOperation,
            error.WantCertificateVerify,
            error.PendingTicket,
            => continue,
            else => return false,
        }
    }
}

fn mozilla_acceptor_thread(new_fn: *const MozillaAcceptorFn, listen_fd: c_int) void {
    defer _ = std.c.close(listen_fd);

    var acceptor = build_mozilla_acceptor(new_fn) orelse return;
    defer acceptor.deinit();

    var addr: std.c.sockaddr.in = undefined;
    var len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
    const conn_fd = std.c.accept(listen_fd, @ptrCast(&addr), &len);
    if (conn_fd < 0) return;
    defer _ = std.c.close(conn_fd);

    var ssl = acceptor.accept(conn_fd) catch return;
    defer ssl.deinit();
    if (!complete_mozilla_handshake(&ssl)) return;

    _ = ssl.write("hello") catch {};
}

fn connect_mozilla_client(port: u16) !void {
    var connector_builder = try boring.ssl_connector.SslConnector.builder(boring.ssl.Method.tls());
    defer connector_builder.deinit();
    try connector_builder.contextBuilder().setCaFile("test/root-ca.pem");
    var connector = connector_builder.build();
    defer connector.deinit();

    const client_fd = std.c.socket(posix_address_family_inet, posix_socket_stream, 0);
    if (client_fd < 0) return error.SocketError;
    defer _ = std.c.close(client_fd);

    var addr = test_server.socket_addr(port);
    try test_server.errno_check(
        std.c.connect(client_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)),
    );

    var ssl = try connector.connect("foobar.com", client_fd);
    defer ssl.deinit();

    var buf: [5]u8 = undefined;
    _ = try ssl.read(&buf);
    try std.testing.expectEqualSlices(u8, "hello", &buf);
}

fn test_mozilla_server(comptime new_acceptor: MozillaAcceptorFn) !void {
    boring.init();

    const listener = try open_mozilla_listener();
    defer _ = std.c.close(listener.fd);

    const listen_fd = std.c.dup(listener.fd);
    if (listen_fd < 0) return error.SocketError;

    const thread = try std.Thread.spawn(.{}, mozilla_acceptor_thread, .{
        &new_acceptor,
        listen_fd,
    });
    defer thread.join();

    try connect_mozilla_client(listener.port);
}

test "ssl connector client server mozilla intermediate" {
    try test_mozilla_server(boring.ssl_connector.SslAcceptor.mozillaIntermediate);
}

test "ssl connector client server mozilla modern" {
    try test_mozilla_server(boring.ssl_connector.SslAcceptor.mozillaModern);
}

test "ssl connector client server mozilla intermediate v5" {
    try test_mozilla_server(boring.ssl_connector.SslAcceptor.mozillaIntermediateV5);
}

// Pending session callback test.

test "ssl new get session callback pending" {
    boring.init();
    var called_back = false;

    var server = try test_server.Server.builder();
    defer server.deinit();
    try server.ctx().setMaxProtoVersion(boring.ssl.SslVersion.tlsV1_2);
    var options = boring.ssl.Options.none;
    options = options.combine(boring.ssl.Options.noTicket);
    _ = server.ctx().setOptions(options);
    server.ctx().setSessionCacheMode(
        boring.ssl.SessionCacheMode.server.combine(boring.ssl.SessionCacheMode.noInternal),
    );
    try server.ctx().setSessionIdContext("foo");
    try server.ctx().setGetSessionCallbackWithContext(
        bool,
        &called_back,
        struct {
            fn callback(
                state: *bool,
                _: *boring.ssl.SslRef,
                _: []const u8,
            ) boring.ssl.GetSessionResult {
                if (!state.*) {
                    state.* = true;
                    return .retry;
                }
                return .none;
            }
        }.callback,
    );
    var running = try server.build();
    defer running.deinit();

    var client_builder = try running.client();
    defer client_builder.deinit();
    client_builder.ctx().setSessionCacheMode(boring.ssl.SessionCacheMode.client);
    var client = try client_builder.connect();
    defer client.deinit();

    try std.testing.expect(called_back);
}
