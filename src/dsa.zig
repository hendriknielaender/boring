const std = @import("std");
const sys = @import("boringssl");

const bn = @import("bn.zig");
const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const Dsa = struct {
    ptr: ?*sys.DSA,

    pub fn init() BoringError!Dsa {
        const dsa = sys.DSA_new() orelse return error.BoringSSL;

        return .{ .ptr = dsa };
    }

    pub fn generate(bit_count: u31) BoringError!Dsa {
        var dsa = try init();
        errdefer dsa.deinit();

        try internal.require_one(sys.DSA_generate_parameters_ex(
            try dsa.raw(),
            bit_count,
            null,
            0,
            null,
            null,
            null,
        ));
        try internal.require_one(sys.DSA_generate_key(try dsa.raw()));

        return dsa;
    }

    pub fn fromPrivateComponents(
        p_value: *bn.BigNum,
        q_value: *bn.BigNum,
        g_value: *bn.BigNum,
        private_key: *bn.BigNum,
        public_key: *bn.BigNum,
    ) BoringError!Dsa {
        var dsa = try init();
        errdefer dsa.deinit();

        try set_pqg(&dsa, p_value, q_value, g_value);
        const raw_private_key = try private_key.intoRaw();
        errdefer sys.BN_free(raw_private_key);
        const raw_public_key = try public_key.intoRaw();
        errdefer sys.BN_free(raw_public_key);
        try internal.require_one(sys.DSA_set0_key(
            try dsa.raw(),
            raw_public_key,
            raw_private_key,
        ));

        return dsa;
    }

    pub fn fromRawOwned(ptr: *sys.DSA) Dsa {
        return .{ .ptr = ptr };
    }

    pub fn deinit(self: *Dsa) void {
        if (self.ptr) |dsa| {
            sys.DSA_free(dsa);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const Dsa) BoringError!*sys.DSA {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *Dsa) BoringError!*sys.DSA {
        const dsa = try self.raw();
        self.ptr = null;

        return dsa;
    }

    pub fn clone(self: *const Dsa) BoringError!Dsa {
        const dsa = try self.raw();
        try internal.require_one(sys.DSA_up_ref(dsa));

        return .{ .ptr = dsa };
    }

    pub fn bits(self: *const Dsa) BoringError!usize {
        return sys.DSA_bits(try self.raw());
    }

    pub fn size(self: *const Dsa) BoringError!usize {
        const result = sys.DSA_size(try self.raw());
        if (result < 0) return error.BoringSSL;

        return @intCast(result);
    }

    pub fn p(self: *const Dsa) BoringError!bn.BigNum {
        return bn.BigNum.cloneRaw(sys.DSA_get0_p(try self.raw()));
    }

    pub fn q(self: *const Dsa) BoringError!bn.BigNum {
        return bn.BigNum.cloneRaw(sys.DSA_get0_q(try self.raw()));
    }

    pub fn g(self: *const Dsa) BoringError!bn.BigNum {
        return bn.BigNum.cloneRaw(sys.DSA_get0_g(try self.raw()));
    }

    pub fn publicKey(self: *const Dsa) BoringError!bn.BigNum {
        return bn.BigNum.cloneRaw(sys.DSA_get0_pub_key(try self.raw()));
    }

    pub fn privateKey(self: *const Dsa) BoringError!bn.BigNum {
        return bn.BigNum.cloneRaw(sys.DSA_get0_priv_key(try self.raw()));
    }
};

pub const DsaSig = struct {
    ptr: ?*sys.DSA_SIG,

    pub fn init() BoringError!DsaSig {
        const sig = sys.DSA_SIG_new();
        if (sig == null) return error.BoringSSL;

        return .{ .ptr = sig };
    }

    pub fn sign(digest: []const u8, key: *const Dsa) BoringError!DsaSig {
        const sig = sys.DSA_do_sign(digest.ptr, digest.len, try key.raw());
        if (sig == null) return error.BoringSSL;

        return .{ .ptr = sig };
    }

    pub fn fromComponents(r_value: *bn.BigNum, s_value: *bn.BigNum) BoringError!DsaSig {
        var sig = try init();
        errdefer sig.deinit();

        const raw_r = try r_value.intoRaw();
        errdefer sys.BN_free(raw_r);
        const raw_s = try s_value.intoRaw();
        errdefer sys.BN_free(raw_s);
        try internal.require_one(sys.DSA_SIG_set0(try sig.raw(), raw_r, raw_s));

        return sig;
    }

    pub fn deinit(self: *DsaSig) void {
        if (self.ptr) |sig| {
            sys.DSA_SIG_free(sig);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const DsaSig) BoringError!*sys.DSA_SIG {
        return self.ptr orelse error.Closed;
    }

    pub fn verify(self: *const DsaSig, digest: []const u8, key: *const Dsa) BoringError!bool {
        const result = sys.DSA_do_verify(
            digest.ptr,
            digest.len,
            try self.raw(),
            try key.raw(),
        );
        if (result < 0) return error.BoringSSL;

        return result == 1;
    }

    pub fn r(self: *const DsaSig) BoringError!bn.BigNum {
        var r_value: [*c]const sys.BIGNUM = null;
        sys.DSA_SIG_get0(try self.raw(), &r_value, null);

        return bn.BigNum.cloneRaw(r_value);
    }

    pub fn s(self: *const DsaSig) BoringError!bn.BigNum {
        var s_value: [*c]const sys.BIGNUM = null;
        sys.DSA_SIG_get0(try self.raw(), null, &s_value);

        return bn.BigNum.cloneRaw(s_value);
    }
};

fn set_pqg(
    dsa: *const Dsa,
    p_value: *bn.BigNum,
    q_value: *bn.BigNum,
    g_value: *bn.BigNum,
) BoringError!void {
    const raw_p = try p_value.intoRaw();
    errdefer sys.BN_free(raw_p);
    const raw_q = try q_value.intoRaw();
    errdefer sys.BN_free(raw_q);
    const raw_g = try g_value.intoRaw();
    errdefer sys.BN_free(raw_g);

    try internal.require_one(sys.DSA_set0_pqg(try dsa.raw(), raw_p, raw_q, raw_g));
}

comptime {
    std.debug.assert(@sizeOf(c_int) >= 4);
}
