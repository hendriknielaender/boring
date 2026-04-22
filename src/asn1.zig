const std = @import("std");
const sys = @import("boringssl");

const bio_mod = @import("bio.zig");
const internal = @import("internal.zig");
const nid_mod = @import("nid.zig");
const BoringError = internal.BoringError;

/// Upper bound on a printed ASN.1 time. RFC 5280 limits UTCTime/GeneralizedTime
/// The value is bounded to 15 bytes plus the terminator.
pub const MaxPrintedTimeBytes = 64;

pub const Asn1Integer = struct {
    ptr: ?*sys.ASN1_INTEGER,

    pub fn init() BoringError!Asn1Integer {
        const raw_ptr = sys.ASN1_INTEGER_new() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn fromU64(value: u64) BoringError!Asn1Integer {
        var self = try init();
        errdefer self.deinit();
        try internal.require_one(sys.ASN1_INTEGER_set_uint64(try self.raw(), value));

        return self;
    }

    pub fn fromI64(value: i64) BoringError!Asn1Integer {
        var self = try init();
        errdefer self.deinit();
        try internal.require_one(sys.ASN1_INTEGER_set_int64(try self.raw(), value));

        return self;
    }

    pub fn deinit(self: *Asn1Integer) void {
        if (self.ptr) |raw_ptr| {
            sys.ASN1_INTEGER_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const Asn1Integer) BoringError!*sys.ASN1_INTEGER {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *Asn1Integer) BoringError!*sys.ASN1_INTEGER {
        const raw_ptr = try self.raw();
        self.ptr = null;

        return raw_ptr;
    }

    pub fn getU64(self: *const Asn1Integer) BoringError!u64 {
        var value: u64 = 0;
        try internal.require_one(sys.ASN1_INTEGER_get_uint64(&value, try self.raw()));

        return value;
    }

    pub fn getI64(self: *const Asn1Integer) BoringError!i64 {
        var value: i64 = 0;
        try internal.require_one(sys.ASN1_INTEGER_get_int64(&value, try self.raw()));

        return value;
    }
};

pub const Asn1Time = struct {
    ptr: ?*sys.ASN1_TIME,

    pub fn init() BoringError!Asn1Time {
        const raw_ptr = sys.ASN1_TIME_new() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn fromPosix(seconds_since_epoch: i64) BoringError!Asn1Time {
        const raw_ptr = sys.ASN1_TIME_set_posix(null, seconds_since_epoch) orelse {
            return error.BoringSSL;
        };

        return .{ .ptr = raw_ptr };
    }

    pub fn daysFromNow(days: u31) BoringError!Asn1Time {
        const seconds_per_day: i64 = 60 * 60 * 24;
        const offset = std.math.mul(i64, seconds_per_day, days) catch {
            return error.Overflow;
        };
        const raw_ptr = sys.X509_gmtime_adj(null, offset) orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn fromString(value: [:0]const u8) BoringError!Asn1Time {
        var self = try init();
        errdefer self.deinit();
        try internal.require_one(sys.ASN1_TIME_set_string_X509(try self.raw(), value.ptr));

        return self;
    }

    pub fn deinit(self: *Asn1Time) void {
        if (self.ptr) |raw_ptr| {
            sys.ASN1_TIME_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const Asn1Time) BoringError!*sys.ASN1_TIME {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *Asn1Time) BoringError!*sys.ASN1_TIME {
        const raw_ptr = try self.raw();
        self.ptr = null;

        return raw_ptr;
    }

    /// Writes a human-readable form of the time into `output`. Returns the
    /// The function returns the number of bytes written.
    /// `output` must be at least `MaxPrintedTimeBytes` to guarantee success.
    pub fn print(self: *const Asn1Time, output: []u8) BoringError!usize {
        if (output.len < MaxPrintedTimeBytes) return error.InvalidArgument;

        var bio = try bio_mod.MemBio.init();
        defer bio.deinit();
        try internal.require_one(sys.ASN1_TIME_print(try bio.raw(), try self.raw()));

        const bytes = try bio.bytes();
        if (bytes.len > output.len) return error.Overflow;

        @memcpy(output[0..bytes.len], bytes);

        return bytes.len;
    }
};

pub const Asn1BitString = struct {
    ptr: ?*sys.ASN1_BIT_STRING,

    pub fn fromRaw(ptr: *sys.ASN1_BIT_STRING) Asn1BitString {
        return .{ .ptr = ptr };
    }

    pub fn bytes(self: *const Asn1BitString) []const u8 {
        const string_ptr = self.ptr orelse return "";
        const data = sys.ASN1_STRING_get0_data(@ptrCast(string_ptr));
        const len = sys.ASN1_STRING_length(@ptrCast(string_ptr));
        if (len <= 0) return "";

        return data[0..@intCast(len)];
    }
};

pub const Asn1Object = struct {
    ptr: ?*sys.ASN1_OBJECT,

    pub fn fromNid(nid_value: nid_mod.Nid) BoringError!Asn1Object {
        const raw_ptr = sys.OBJ_nid2obj(nid_value.asRaw()) orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn fromText(text: [:0]const u8, allow_numeric: bool) BoringError!Asn1Object {
        const raw_ptr = sys.OBJ_txt2obj(
            text.ptr,
            @intFromBool(!allow_numeric),
        ) orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *Asn1Object) void {
        if (self.ptr) |raw_ptr| {
            sys.ASN1_OBJECT_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const Asn1Object) BoringError!*sys.ASN1_OBJECT {
        return self.ptr orelse error.Closed;
    }

    pub fn nid(self: *const Asn1Object) BoringError!nid_mod.Nid {
        return nid_mod.Nid.fromRaw(sys.OBJ_obj2nid(try self.raw()));
    }
};

pub const Asn1String = struct {
    ptr: ?*sys.ASN1_STRING,

    pub fn bytes(self: *const Asn1String) []const u8 {
        const string_ptr = self.ptr orelse return "";
        const data = sys.ASN1_STRING_get0_data(string_ptr);
        const len = sys.ASN1_STRING_length(string_ptr);
        if (len <= 0) return "";

        return data[0..@intCast(len)];
    }

    pub fn raw(self: *const Asn1String) ?*sys.ASN1_STRING {
        return self.ptr;
    }
};

comptime {
    std.debug.assert(MaxPrintedTimeBytes >= 32);
}
