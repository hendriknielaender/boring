const std = @import("std");
const sys = @import("boringssl");

const bio = @import("bio.zig");
const bn = @import("bn.zig");
const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const Dh = struct {
    ptr: ?*sys.DH,

    pub fn init() BoringError!Dh {
        const dh = sys.DH_new() orelse return error.BoringSSL;

        return .{ .ptr = dh };
    }

    pub fn rfc7919Ffdhe2048() BoringError!Dh {
        const dh = sys.DH_get_rfc7919_2048() orelse return error.BoringSSL;

        return .{ .ptr = dh };
    }

    pub fn fromParams(
        p: *bn.BigNum,
        g: *bn.BigNum,
        q: *bn.BigNum,
    ) BoringError!Dh {
        var dh = try init();
        errdefer dh.deinit();

        const raw_p = try p.intoRaw();
        errdefer sys.BN_free(raw_p);
        const raw_g = try g.intoRaw();
        errdefer sys.BN_free(raw_g);
        const raw_q = try q.intoRaw();
        errdefer sys.BN_free(raw_q);

        try internal.require_one(sys.DH_set0_pqg(
            try dh.raw(),
            raw_p,
            raw_q,
            raw_g,
        ));

        return dh;
    }

    pub fn paramsFromPem(input: []const u8) BoringError!Dh {
        var input_bio = try bio.MemBio.initConstSlice(input);
        defer input_bio.deinit();

        const dh = sys.PEM_read_bio_DHparams(
            try input_bio.raw(),
            null,
            null,
            null,
        ) orelse return error.BoringSSL;

        return .{ .ptr = dh };
    }

    pub fn paramsFromDer(input: []const u8) BoringError!Dh {
        const len = std.math.cast(c_long, input.len) orelse return error.Overflow;
        var cursor: [*c]const u8 = input.ptr;
        const dh = sys.d2i_DHparams(null, &cursor, len) orelse return error.BoringSSL;

        return .{ .ptr = dh };
    }

    pub fn deinit(self: *Dh) void {
        if (self.ptr) |dh| {
            sys.DH_free(dh);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const Dh) BoringError!*sys.DH {
        return self.ptr orelse error.Closed;
    }

    pub fn bits(self: *const Dh) BoringError!usize {
        return sys.DH_bits(try self.raw());
    }

    pub fn size(self: *const Dh) BoringError!usize {
        const result = sys.DH_size(try self.raw());
        if (result < 0) return error.BoringSSL;

        return @intCast(result);
    }

    pub fn paramsToPem(self: *const Dh, output: *bio.MemBio) BoringError!void {
        try internal.require_one(sys.PEM_write_bio_DHparams(
            try output.raw(),
            try self.raw(),
        ));
    }

    pub fn paramsToDer(self: *const Dh, output: *bio.MemBio) BoringError!void {
        try internal.require_one(sys.i2d_DHparams_bio(
            try output.raw(),
            try self.raw(),
        ));
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.DH) > 0);
}
