const std = @import("std");
const sys = @import("boringssl");

const bn = @import("bn.zig");
const ec = @import("ec.zig");
const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const EcdsaSig = struct {
    ptr: ?*sys.ECDSA_SIG,

    pub fn init() BoringError!EcdsaSig {
        const sig = sys.ECDSA_SIG_new();
        if (sig == null) return error.BoringSSL;

        return .{ .ptr = sig };
    }

    pub fn sign(digest: []const u8, key: *const ec.EcKey) BoringError!EcdsaSig {
        const sig = sys.ECDSA_do_sign(digest.ptr, digest.len, try key.raw());
        if (sig == null) return error.BoringSSL;

        return .{ .ptr = sig };
    }

    pub fn fromComponents(r_value: *bn.BigNum, s_value: *bn.BigNum) BoringError!EcdsaSig {
        var sig = try init();
        errdefer sig.deinit();

        const raw_r = try r_value.intoRaw();
        errdefer sys.BN_free(raw_r);
        const raw_s = try s_value.intoRaw();
        errdefer sys.BN_free(raw_s);
        try internal.require_one(sys.ECDSA_SIG_set0(try sig.raw(), raw_r, raw_s));

        return sig;
    }

    pub fn deinit(self: *EcdsaSig) void {
        if (self.ptr) |sig| {
            sys.ECDSA_SIG_free(sig);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const EcdsaSig) BoringError!*sys.ECDSA_SIG {
        return self.ptr orelse error.Closed;
    }

    pub fn verify(
        self: *const EcdsaSig,
        digest: []const u8,
        key: *const ec.EcKey,
    ) BoringError!bool {
        const result = sys.ECDSA_do_verify(
            digest.ptr,
            digest.len,
            try self.raw(),
            try key.raw(),
        );
        if (result < 0) return error.BoringSSL;

        return result == 1;
    }

    pub fn r(self: *const EcdsaSig) BoringError!bn.BigNum {
        return bn.BigNum.cloneRaw(sys.ECDSA_SIG_get0_r(try self.raw()));
    }

    pub fn s(self: *const EcdsaSig) BoringError!bn.BigNum {
        return bn.BigNum.cloneRaw(sys.ECDSA_SIG_get0_s(try self.raw()));
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.ECDSA_SIG) > 0);
}
