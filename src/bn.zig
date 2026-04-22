const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const string = @import("string.zig");
const BoringError = internal.BoringError;

pub const MsbOption = enum(c_int) {
    maybeZero = sys.BN_RAND_TOP_ANY,
    one = sys.BN_RAND_TOP_ONE,
    twoOnes = sys.BN_RAND_TOP_TWO,

    fn raw(self: MsbOption) c_int {
        return @intFromEnum(self);
    }
};

pub const Order = enum {
    lt,
    eq,
    gt,
};

pub const BigNumContext = struct {
    ptr: ?*sys.BN_CTX,

    pub fn init() BoringError!BigNumContext {
        const ctx = sys.BN_CTX_new() orelse return error.BoringSSL;

        return .{ .ptr = ctx };
    }

    pub fn deinit(self: *BigNumContext) void {
        if (self.ptr) |ctx| {
            sys.BN_CTX_free(ctx);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const BigNumContext) BoringError!*sys.BN_CTX {
        return self.ptr orelse error.Closed;
    }
};

pub const BigNum = struct {
    ptr: ?*sys.BIGNUM,

    pub fn init() BoringError!BigNum {
        const bn = sys.BN_new() orelse return error.BoringSSL;

        return .{ .ptr = bn };
    }

    pub fn fromU32(value: u32) BoringError!BigNum {
        var bn = try init();
        errdefer bn.deinit();
        try bn.setWord(value);

        return bn;
    }

    pub fn fromU64(value: u64) BoringError!BigNum {
        var bn = try init();
        errdefer bn.deinit();
        try internal.require_one(sys.BN_set_u64(try bn.raw(), value));

        return bn;
    }

    pub fn fromSlice(bytes: []const u8) BoringError!BigNum {
        const bn = sys.BN_bin2bn(bytes.ptr, bytes.len, null) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = bn };
    }

    pub fn fromHexString(value: [:0]const u8) BoringError!BigNum {
        return from_string(value, sys.BN_hex2bn);
    }

    pub fn fromDecString(value: [:0]const u8) BoringError!BigNum {
        return from_string(value, sys.BN_dec2bn);
    }

    pub fn fromRawOwned(ptr: *sys.BIGNUM) BigNum {
        return .{ .ptr = ptr };
    }

    pub fn cloneRaw(ptr: [*c]const sys.BIGNUM) BoringError!BigNum {
        if (ptr == null) return error.BoringSSL;
        const copy = sys.BN_dup(ptr) orelse return error.BoringSSL;

        return .{ .ptr = copy };
    }

    pub fn deinit(self: *BigNum) void {
        if (self.ptr) |bn| {
            sys.BN_free(bn);
            self.ptr = null;
        }
    }

    pub fn clearAndDeinit(self: *BigNum) void {
        if (self.ptr) |bn| {
            sys.BN_clear_free(bn);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const BigNum) BoringError!*sys.BIGNUM {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *BigNum) BoringError!*sys.BIGNUM {
        const bn = try self.raw();
        self.ptr = null;

        return bn;
    }

    pub fn clone(self: *const BigNum) BoringError!BigNum {
        const bn = sys.BN_dup(try self.raw()) orelse return error.BoringSSL;

        return .{ .ptr = bn };
    }

    pub fn clear(self: *BigNum) BoringError!void {
        sys.BN_clear(try self.raw());
    }

    pub fn setZero(self: *BigNum) BoringError!void {
        sys.BN_zero(try self.raw());
    }

    pub fn setOne(self: *BigNum) BoringError!void {
        try internal.require_one(sys.BN_one(try self.raw()));
    }

    pub fn setWord(self: *BigNum, value: u32) BoringError!void {
        try internal.require_one(sys.BN_set_word(try self.raw(), value));
    }

    pub fn setNegative(self: *BigNum, negative: bool) BoringError!void {
        sys.BN_set_negative(try self.raw(), @intFromBool(negative));
    }

    pub fn isNegative(self: *const BigNum) BoringError!bool {
        return sys.BN_is_negative(try self.raw()) == 1;
    }

    pub fn isZero(self: *const BigNum) BoringError!bool {
        return sys.BN_is_zero(try self.raw()) == 1;
    }

    pub fn isOne(self: *const BigNum) BoringError!bool {
        return sys.BN_is_one(try self.raw()) == 1;
    }

    pub fn isOdd(self: *const BigNum) BoringError!bool {
        return sys.BN_is_odd(try self.raw()) == 1;
    }

    pub fn isWord(self: *const BigNum, value: u64) BoringError!bool {
        return sys.BN_is_word(try self.raw(), value) == 1;
    }

    pub fn numBits(self: *const BigNum) BoringError!usize {
        return sys.BN_num_bits(try self.raw());
    }

    pub fn numBytes(self: *const BigNum) BoringError!usize {
        return sys.BN_num_bytes(try self.raw());
    }

    pub fn getU64(self: *const BigNum) BoringError!u64 {
        var value: u64 = 0;
        try internal.require_one(sys.BN_get_u64(try self.raw(), &value));

        return value;
    }

    pub fn cmp(self: *const BigNum, other: *const BigNum) BoringError!Order {
        return order_from_c_int(sys.BN_cmp(try self.raw(), try other.raw()));
    }

    pub fn unsignedCmp(self: *const BigNum, other: *const BigNum) BoringError!Order {
        return order_from_c_int(sys.BN_ucmp(try self.raw(), try other.raw()));
    }

    pub fn equalConstantTime(self: *const BigNum, other: *const BigNum) BoringError!bool {
        return sys.BN_equal_consttime(try self.raw(), try other.raw()) == 1;
    }

    pub fn addWord(self: *BigNum, value: u32) BoringError!void {
        try internal.require_one(sys.BN_add_word(try self.raw(), value));
    }

    pub fn subWord(self: *BigNum, value: u32) BoringError!void {
        try internal.require_one(sys.BN_sub_word(try self.raw(), value));
    }

    pub fn mulWord(self: *BigNum, value: u32) BoringError!void {
        try internal.require_one(sys.BN_mul_word(try self.raw(), value));
    }

    pub fn divWord(self: *BigNum, value: u32) BoringError!u64 {
        const result = sys.BN_div_word(try self.raw(), value);
        if (result == std.math.maxInt(sys.BN_ULONG)) return error.BoringSSL;

        return result;
    }

    pub fn modWord(self: *const BigNum, value: u32) BoringError!u64 {
        const result = sys.BN_mod_word(try self.raw(), value);
        if (result == std.math.maxInt(sys.BN_ULONG)) return error.BoringSSL;

        return result;
    }

    pub fn checkedAdd(self: *BigNum, a: *const BigNum, b: *const BigNum) BoringError!void {
        try internal.require_one(sys.BN_add(try self.raw(), try a.raw(), try b.raw()));
    }

    pub fn checkedSub(self: *BigNum, a: *const BigNum, b: *const BigNum) BoringError!void {
        try internal.require_one(sys.BN_sub(try self.raw(), try a.raw(), try b.raw()));
    }

    pub fn checkedMul(
        self: *BigNum,
        a: *const BigNum,
        b: *const BigNum,
        ctx: *const BigNumContext,
    ) BoringError!void {
        try internal.require_one(sys.BN_mul(
            try self.raw(),
            try a.raw(),
            try b.raw(),
            try ctx.raw(),
        ));
    }

    pub fn checkedDiv(
        self: *BigNum,
        a: *const BigNum,
        b: *const BigNum,
        ctx: *const BigNumContext,
    ) BoringError!void {
        try internal.require_one(sys.BN_div(
            try self.raw(),
            null,
            try a.raw(),
            try b.raw(),
            try ctx.raw(),
        ));
    }

    pub fn checkedRem(
        self: *BigNum,
        a: *const BigNum,
        b: *const BigNum,
        ctx: *const BigNumContext,
    ) BoringError!void {
        try internal.require_one(sys.BN_div(
            null,
            try self.raw(),
            try a.raw(),
            try b.raw(),
            try ctx.raw(),
        ));
    }

    pub fn divRem(
        self: *BigNum,
        rem: *BigNum,
        a: *const BigNum,
        b: *const BigNum,
        ctx: *const BigNumContext,
    ) BoringError!void {
        try internal.require_one(sys.BN_div(
            try self.raw(),
            try rem.raw(),
            try a.raw(),
            try b.raw(),
            try ctx.raw(),
        ));
    }

    pub fn leftShift(self: *BigNum, a: *const BigNum, bits: u31) BoringError!void {
        try internal.require_one(sys.BN_lshift(try self.raw(), try a.raw(), bits));
    }

    pub fn rightShift(self: *BigNum, a: *const BigNum, bits: u31) BoringError!void {
        try internal.require_one(sys.BN_rshift(try self.raw(), try a.raw(), bits));
    }

    pub fn setBit(self: *BigNum, bit: u31) BoringError!void {
        try internal.require_one(sys.BN_set_bit(try self.raw(), bit));
    }

    pub fn clearBit(self: *BigNum, bit: u31) BoringError!void {
        try internal.require_one(sys.BN_clear_bit(try self.raw(), bit));
    }

    pub fn isBitSet(self: *const BigNum, bit: u31) BoringError!bool {
        return sys.BN_is_bit_set(try self.raw(), bit) == 1;
    }

    pub fn rand(self: *BigNum, bits: u31, msb: MsbOption, odd: bool) BoringError!void {
        try internal.require_one(sys.BN_rand(
            try self.raw(),
            bits,
            msb.raw(),
            @intFromBool(odd),
        ));
    }

    pub fn pseudoRand(self: *BigNum, bits: u31, msb: MsbOption, odd: bool) BoringError!void {
        try internal.require_one(sys.BN_pseudo_rand(
            try self.raw(),
            bits,
            msb.raw(),
            @intFromBool(odd),
        ));
    }

    pub fn randRange(self: *const BigNum, output: *BigNum) BoringError!void {
        try internal.require_one(sys.BN_rand_range(try output.raw(), try self.raw()));
    }

    pub fn pseudoRandRange(self: *const BigNum, output: *BigNum) BoringError!void {
        try internal.require_one(sys.BN_pseudo_rand_range(try output.raw(), try self.raw()));
    }

    pub fn toBin(self: *const BigNum, output: []u8) BoringError!usize {
        const required_len = try self.numBytes();
        if (output.len < required_len) return error.InvalidArgument;

        return sys.BN_bn2bin(try self.raw(), output.ptr);
    }

    pub fn toBinPadded(self: *const BigNum, output: []u8) BoringError!void {
        try internal.require_one(sys.BN_bn2binpad(
            try self.raw(),
            output.ptr,
            try internal.c_int_len(output.len),
        ));
    }

    pub fn toLittleEndianPadded(self: *const BigNum, output: []u8) BoringError!void {
        try internal.require_one(sys.BN_bn2lebinpad(
            try self.raw(),
            output.ptr,
            try internal.c_int_len(output.len),
        ));
    }

    pub fn toHexString(self: *const BigNum) BoringError!string.OpenSslString {
        return string.OpenSslString.fromRaw(sys.BN_bn2hex(try self.raw()));
    }

    pub fn toDecString(self: *const BigNum) BoringError!string.OpenSslString {
        return string.OpenSslString.fromRaw(sys.BN_bn2dec(try self.raw()));
    }
};

fn from_string(
    value: [:0]const u8,
    comptime convert: fn ([*c][*c]sys.BIGNUM, [*c]const u8) callconv(.c) c_int,
) BoringError!BigNum {
    var raw_bn: [*c]sys.BIGNUM = null;
    const result = convert(&raw_bn, value.ptr);
    if (result <= 0) return error.BoringSSL;
    if (raw_bn == null) return error.BoringSSL;

    return .{ .ptr = raw_bn };
}

fn order_from_c_int(value: c_int) Order {
    if (value < 0) return .lt;
    if (value > 0) return .gt;

    return .eq;
}

comptime {
    std.debug.assert(@sizeOf(c_int) >= 4);
}
