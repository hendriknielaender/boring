const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const SignatureAlgorithms = struct {
    digest: Nid,
    pkey: Nid,
};

pub const Nid = struct {
    raw_value: c_int,

    pub const undef = fromRaw(sys.NID_undef);
    pub const rsaEncryption = fromRaw(sys.NID_rsaEncryption);
    pub const ecPublicKey = fromRaw(sys.NID_X9_62_id_ecPublicKey);
    pub const sha256 = fromRaw(sys.NID_sha256);
    pub const sha512 = fromRaw(sys.NID_sha512);
    pub const sha512256 = fromRaw(sys.NID_sha512_256);
    pub const sha256WithRsaEncryption = fromRaw(sys.NID_sha256WithRSAEncryption);
    pub const sha512WithRsaEncryption = fromRaw(sys.NID_sha512WithRSAEncryption);
    pub const ecdsaWithSha256 = fromRaw(sys.NID_ecdsa_with_SHA256);
    pub const prime256v1 = fromRaw(sys.NID_X9_62_prime256v1);
    pub const secp384r1 = fromRaw(sys.NID_secp384r1);
    pub const secp521r1 = fromRaw(sys.NID_secp521r1);
    pub const commonName = fromRaw(sys.NID_commonName);
    pub const keyUsage = fromRaw(sys.NID_key_usage);
    pub const basicConstraints = fromRaw(sys.NID_basic_constraints);
    pub const extKeyUsage = fromRaw(sys.NID_ext_key_usage);
    pub const subjectAltName = fromRaw(sys.NID_subject_alt_name);
    pub const issuerAltName = fromRaw(sys.NID_issuer_alt_name);
    pub const subjectKeyIdentifier = fromRaw(sys.NID_subject_key_identifier);
    pub const authorityKeyIdentifier = fromRaw(sys.NID_authority_key_identifier);
    pub const pkcs9EmailAddress = fromRaw(sys.NID_pkcs9_emailAddress);
    pub const userId = fromRaw(sys.NID_userId);
    pub const friendlyName = fromRaw(sys.NID_friendlyName);

    pub fn fromRaw(raw_value: c_int) Nid {
        return .{ .raw_value = raw_value };
    }

    pub fn asRaw(self: Nid) c_int {
        return self.raw_value;
    }

    pub fn signatureAlgorithms(self: Nid) ?SignatureAlgorithms {
        var digest: c_int = 0;
        var pkey: c_int = 0;
        if (sys.OBJ_find_sigid_algs(self.raw_value, &digest, &pkey) != 1) {
            return null;
        }

        return .{
            .digest = fromRaw(digest),
            .pkey = fromRaw(pkey),
        };
    }

    pub fn shortName(self: Nid) BoringError![:0]const u8 {
        const name = sys.OBJ_nid2sn(self.raw_value);
        if (name == null) return error.BoringSSL;

        return std.mem.span(name);
    }

    pub fn longName(self: Nid) BoringError![:0]const u8 {
        const name = sys.OBJ_nid2ln(self.raw_value);
        if (name == null) return error.BoringSSL;

        return std.mem.span(name);
    }
};

comptime {
    std.debug.assert(@sizeOf(c_int) >= 4);
}
