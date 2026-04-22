const std = @import("std");
const sys = @import("boringssl");

const bio_mod = @import("bio.zig");
const bn = @import("bn.zig");
const internal = @import("internal.zig");
const nid_mod = @import("nid.zig");
const BoringError = internal.BoringError;

pub const PointConversionForm = enum(sys.point_conversion_form_t) {
    compressed = sys.POINT_CONVERSION_COMPRESSED,
    uncompressed = sys.POINT_CONVERSION_UNCOMPRESSED,
    hybrid = sys.POINT_CONVERSION_HYBRID,

    fn raw(self: PointConversionForm) sys.point_conversion_form_t {
        return @intFromEnum(self);
    }
};

pub const Asn1Flag = enum(c_int) {
    explicitCurve = 0,
    namedCurve = sys.OPENSSL_EC_NAMED_CURVE,

    fn raw(self: Asn1Flag) c_int {
        return @intFromEnum(self);
    }
};

pub const EcGroup = struct {
    ptr: ?*sys.EC_GROUP,

    pub fn fromCurveName(curve: nid_mod.Nid) BoringError!EcGroup {
        const group = sys.EC_GROUP_new_by_curve_name(curve.asRaw()) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = group };
    }

    pub fn deinit(self: *EcGroup) void {
        if (self.ptr) |group| {
            sys.EC_GROUP_free(group);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const EcGroup) BoringError!*sys.EC_GROUP {
        return self.ptr orelse error.Closed;
    }

    pub fn clone(self: *const EcGroup) BoringError!EcGroup {
        const group = sys.EC_GROUP_dup(try self.raw()) orelse return error.BoringSSL;

        return .{ .ptr = group };
    }

    pub fn degree(self: *const EcGroup) BoringError!usize {
        return sys.EC_GROUP_get_degree(try self.raw());
    }

    pub fn orderBits(self: *const EcGroup) BoringError!usize {
        const result = sys.EC_GROUP_order_bits(try self.raw());
        if (result < 0) return error.BoringSSL;

        return @intCast(result);
    }

    pub fn curveName(self: *const EcGroup) BoringError!?nid_mod.Nid {
        const raw_nid = sys.EC_GROUP_get_curve_name(try self.raw());
        if (raw_nid <= 0) return null;

        return nid_mod.Nid.fromRaw(raw_nid);
    }

    pub fn setAsn1Flag(self: *EcGroup, flag: Asn1Flag) BoringError!void {
        sys.EC_GROUP_set_asn1_flag(try self.raw(), flag.raw());
    }

    pub fn generator(self: *const EcGroup) BoringError!EcPoint {
        const point = sys.EC_GROUP_get0_generator(try self.raw()) orelse {
            return error.BoringSSL;
        };
        const copy = sys.EC_POINT_dup(point, try self.raw()) orelse return error.BoringSSL;

        return .{ .ptr = copy };
    }

    pub fn order(
        self: *const EcGroup,
        output: *bn.BigNum,
        ctx: *const bn.BigNumContext,
    ) BoringError!void {
        try internal.require_one(sys.EC_GROUP_get_order(
            try self.raw(),
            try output.raw(),
            try ctx.raw(),
        ));
    }

    pub fn cofactor(
        self: *const EcGroup,
        output: *bn.BigNum,
        ctx: *const bn.BigNumContext,
    ) BoringError!void {
        try internal.require_one(sys.EC_GROUP_get_cofactor(
            try self.raw(),
            try output.raw(),
            try ctx.raw(),
        ));
    }
};

pub const EcPoint = struct {
    ptr: ?*sys.EC_POINT,

    pub fn init(group: *const EcGroup) BoringError!EcPoint {
        const point = sys.EC_POINT_new(try group.raw()) orelse return error.BoringSSL;

        return .{ .ptr = point };
    }

    pub fn fromBytes(
        group: *const EcGroup,
        input: []const u8,
        ctx: *const bn.BigNumContext,
    ) BoringError!EcPoint {
        var point = try init(group);
        errdefer point.deinit();
        try internal.require_one(sys.EC_POINT_oct2point(
            try group.raw(),
            try point.raw(),
            input.ptr,
            input.len,
            try ctx.raw(),
        ));

        return point;
    }

    pub fn deinit(self: *EcPoint) void {
        if (self.ptr) |point| {
            sys.EC_POINT_free(point);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const EcPoint) BoringError!*sys.EC_POINT {
        return self.ptr orelse error.Closed;
    }

    pub fn clone(self: *const EcPoint, group: *const EcGroup) BoringError!EcPoint {
        const point = sys.EC_POINT_dup(try self.raw(), try group.raw()) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = point };
    }

    pub fn isOnCurve(
        self: *const EcPoint,
        group: *const EcGroup,
        ctx: *const bn.BigNumContext,
    ) BoringError!bool {
        const result = sys.EC_POINT_is_on_curve(try group.raw(), try self.raw(), try ctx.raw());
        if (result < 0) return error.BoringSSL;

        return result == 1;
    }

    pub fn eq(
        self: *const EcPoint,
        group: *const EcGroup,
        other: *const EcPoint,
        ctx: *const bn.BigNumContext,
    ) BoringError!bool {
        const result = sys.EC_POINT_cmp(
            try group.raw(),
            try self.raw(),
            try other.raw(),
            try ctx.raw(),
        );
        if (result < 0) return error.BoringSSL;

        return result == 0;
    }

    pub fn toBytes(
        self: *const EcPoint,
        group: *const EcGroup,
        form: PointConversionForm,
        ctx: *const bn.BigNumContext,
        output: []u8,
    ) BoringError!usize {
        const required_len = sys.EC_POINT_point2oct(
            try group.raw(),
            try self.raw(),
            form.raw(),
            null,
            0,
            try ctx.raw(),
        );
        if (required_len == 0) return error.BoringSSL;
        if (output.len < required_len) return error.InvalidArgument;

        const len = sys.EC_POINT_point2oct(
            try group.raw(),
            try self.raw(),
            form.raw(),
            output.ptr,
            output.len,
            try ctx.raw(),
        );
        if (len == 0) return error.BoringSSL;

        return len;
    }

    pub fn affineCoordinates(
        self: *const EcPoint,
        group: *const EcGroup,
        x: *bn.BigNum,
        y: *bn.BigNum,
        ctx: *const bn.BigNumContext,
    ) BoringError!void {
        try internal.require_one(sys.EC_POINT_get_affine_coordinates(
            try group.raw(),
            try self.raw(),
            try x.raw(),
            try y.raw(),
            try ctx.raw(),
        ));
    }
};

pub const EcKey = struct {
    ptr: ?*sys.EC_KEY,

    pub fn fromCurveName(curve: nid_mod.Nid) BoringError!EcKey {
        const key = sys.EC_KEY_new_by_curve_name(curve.asRaw()) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = key };
    }

    pub fn fromGroup(ec_group: *const EcGroup) BoringError!EcKey {
        var key = try init();
        errdefer key.deinit();
        try internal.require_one(sys.EC_KEY_set_group(try key.raw(), try ec_group.raw()));

        return key;
    }

    pub fn generate(ec_group: *const EcGroup) BoringError!EcKey {
        var key = try fromGroup(ec_group);
        errdefer key.deinit();
        try internal.require_one(sys.EC_KEY_generate_key(try key.raw()));

        return key;
    }

    pub fn fromPrivateComponents(
        ec_group: *const EcGroup,
        private_key: *const bn.BigNum,
        public_key: *const EcPoint,
    ) BoringError!EcKey {
        var key = try fromGroup(ec_group);
        errdefer key.deinit();
        try internal.require_one(sys.EC_KEY_set_private_key(try key.raw(), try private_key.raw()));
        try internal.require_one(sys.EC_KEY_set_public_key(try key.raw(), try public_key.raw()));

        return key;
    }

    pub fn fromPublicKey(ec_group: *const EcGroup, public_key: *const EcPoint) BoringError!EcKey {
        var key = try fromGroup(ec_group);
        errdefer key.deinit();
        try internal.require_one(sys.EC_KEY_set_public_key(try key.raw(), try public_key.raw()));

        return key;
    }

    pub fn fromRawOwned(ptr: *sys.EC_KEY) EcKey {
        return .{ .ptr = ptr };
    }

    pub fn fromPem(input: []const u8) BoringError!EcKey {
        var bio = try bio_mod.MemBio.initConstSlice(input);
        defer bio.deinit();

        const key = sys.PEM_read_bio_ECPrivateKey(
            try bio.raw(),
            null,
            null,
            null,
        ) orelse return error.BoringSSL;

        return .{ .ptr = key };
    }

    pub fn fromPemWithPassword(input: []const u8, password: []const u8) BoringError!EcKey {
        var bio = try bio_mod.MemBio.initConstSlice(input);
        defer bio.deinit();

        var state = internal.PasswordCallbackState{ .password = password };
        const key = sys.PEM_read_bio_ECPrivateKey(
            try bio.raw(),
            null,
            internal.password_callback,
            &state,
        ) orelse return error.BoringSSL;

        return .{ .ptr = key };
    }

    pub fn deinit(self: *EcKey) void {
        if (self.ptr) |key| {
            sys.EC_KEY_free(key);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const EcKey) BoringError!*sys.EC_KEY {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *EcKey) BoringError!*sys.EC_KEY {
        const key = try self.raw();
        self.ptr = null;

        return key;
    }

    pub fn clone(self: *const EcKey) BoringError!EcKey {
        const key = sys.EC_KEY_dup(try self.raw()) orelse return error.BoringSSL;

        return .{ .ptr = key };
    }

    pub fn group(self: *const EcKey) BoringError!EcGroup {
        const group_ptr = sys.EC_KEY_get0_group(try self.raw()) orelse return error.BoringSSL;
        const group_copy = sys.EC_GROUP_dup(group_ptr) orelse return error.BoringSSL;

        return .{ .ptr = group_copy };
    }

    pub fn publicKey(self: *const EcKey) BoringError!EcPoint {
        const group_ptr = sys.EC_KEY_get0_group(try self.raw()) orelse return error.BoringSSL;
        const point = sys.EC_KEY_get0_public_key(try self.raw()) orelse return error.BoringSSL;
        const point_copy = sys.EC_POINT_dup(point, group_ptr) orelse return error.BoringSSL;

        return .{ .ptr = point_copy };
    }

    pub fn privateKey(self: *const EcKey) BoringError!bn.BigNum {
        return bn.BigNum.cloneRaw(sys.EC_KEY_get0_private_key(try self.raw()));
    }

    pub fn checkKey(self: *const EcKey) BoringError!void {
        try internal.require_one(sys.EC_KEY_check_key(try self.raw()));
    }

    pub fn isOpaque(self: *const EcKey) BoringError!bool {
        return sys.EC_KEY_is_opaque(try self.raw()) == 1;
    }

    pub fn setConversionForm(self: *EcKey, form: PointConversionForm) BoringError!void {
        sys.EC_KEY_set_conv_form(try self.raw(), form.raw());
    }

    fn init() BoringError!EcKey {
        const key = sys.EC_KEY_new() orelse return error.BoringSSL;

        return .{ .ptr = key };
    }
};

comptime {
    std.debug.assert(@intFromEnum(PointConversionForm.compressed) != 0);
}
