const std = @import("std");
const sys = @import("boringssl");

const BoringError = @import("internal.zig").BoringError;

pub const SrtpProfileId = struct {
    value: c_ulong,

    pub const aes128CmSha1_80 = SrtpProfileId{ .value = sys.SRTP_AES128_CM_SHA1_80 };
    pub const aes128CmSha1_32 = SrtpProfileId{ .value = sys.SRTP_AES128_CM_SHA1_32 };
    pub const aes128F8Sha1_80 = SrtpProfileId{ .value = sys.SRTP_AES128_F8_SHA1_80 };
    pub const aes128F8Sha1_32 = SrtpProfileId{ .value = sys.SRTP_AES128_F8_SHA1_32 };
    pub const nullSha1_80 = SrtpProfileId{ .value = sys.SRTP_NULL_SHA1_80 };
    pub const nullSha1_32 = SrtpProfileId{ .value = sys.SRTP_NULL_SHA1_32 };
    pub const aeadAes128Gcm = SrtpProfileId{ .value = sys.SRTP_AEAD_AES_128_GCM };
    pub const aeadAes256Gcm = SrtpProfileId{ .value = sys.SRTP_AEAD_AES_256_GCM };

    pub fn fromRaw(value: c_ulong) SrtpProfileId {
        return .{ .value = value };
    }

    pub fn asRaw(self: SrtpProfileId) c_ulong {
        return self.value;
    }
};

pub const SrtpProtectionProfile = struct {
    ptr: *const sys.SRTP_PROTECTION_PROFILE,

    pub fn fromRaw(ptr: *const sys.SRTP_PROTECTION_PROFILE) SrtpProtectionProfile {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: SrtpProtectionProfile) *const sys.SRTP_PROTECTION_PROFILE {
        return self.ptr;
    }

    pub fn id(self: SrtpProtectionProfile) SrtpProfileId {
        return SrtpProfileId.fromRaw(self.ptr.id);
    }

    pub fn name(self: SrtpProtectionProfile) [:0]const u8 {
        return std.mem.span(self.ptr.name);
    }
};

comptime {
    std.debug.assert(@sizeOf(*const sys.SRTP_PROTECTION_PROFILE) > 0);
}
