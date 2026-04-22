const std = @import("std");
const build_options = @import("build_options");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const X509CheckFlags = if (build_options.boringssl_underscore_wildcards_patch)
    X509CheckFlagsPatched
else
    X509CheckFlagsBase;

const X509CheckFlagsBase = struct {
    bits: c_uint,

    pub const alwaysCheckSubject = X509CheckFlagsBase{
        .bits = @intCast(sys.X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT),
    };
    pub const noWildcards = X509CheckFlagsBase{
        .bits = @intCast(sys.X509_CHECK_FLAG_NO_WILDCARDS),
    };
    pub const noPartialWildcards = X509CheckFlagsBase{
        .bits = @intCast(sys.X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS),
    };
    pub const multiLabelWildcards = X509CheckFlagsBase{
        .bits = @intCast(sys.X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS),
    };
    pub const singleLabelSubdomains = X509CheckFlagsBase{
        .bits = @intCast(sys.X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS),
    };
    pub const neverCheckSubject = X509CheckFlagsBase{
        .bits = @intCast(sys.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT),
    };

    pub fn combine(
        self: X509CheckFlagsBase,
        other: X509CheckFlagsBase,
    ) X509CheckFlagsBase {
        return .{ .bits = self.bits | other.bits };
    }
};

const X509CheckFlagsPatched = struct {
    bits: c_uint,

    pub const alwaysCheckSubject = X509CheckFlagsPatched{
        .bits = @intCast(sys.X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT),
    };
    pub const noWildcards = X509CheckFlagsPatched{
        .bits = @intCast(sys.X509_CHECK_FLAG_NO_WILDCARDS),
    };
    pub const noPartialWildcards = X509CheckFlagsPatched{
        .bits = @intCast(sys.X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS),
    };
    pub const multiLabelWildcards = X509CheckFlagsPatched{
        .bits = @intCast(sys.X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS),
    };
    pub const singleLabelSubdomains = X509CheckFlagsPatched{
        .bits = @intCast(sys.X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS),
    };
    pub const neverCheckSubject = X509CheckFlagsPatched{
        .bits = @intCast(sys.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT),
    };
    pub const underscoreWildcards = X509CheckFlagsPatched{
        .bits = @intCast(sys.X509_CHECK_FLAG_UNDERSCORE_WILDCARDS),
    };

    pub fn combine(
        self: X509CheckFlagsPatched,
        other: X509CheckFlagsPatched,
    ) X509CheckFlagsPatched {
        return .{ .bits = self.bits | other.bits };
    }
};

pub const X509VerifyFlags = struct {
    bits: c_ulong,

    pub const cbIssuerCheck = X509VerifyFlags{
        .bits = @intCast(sys.X509_V_FLAG_CB_ISSUER_CHECK),
    };
    pub const crlCheck = X509VerifyFlags{
        .bits = @intCast(sys.X509_V_FLAG_CRL_CHECK),
    };
    pub const crlCheckAll = X509VerifyFlags{
        .bits = @intCast(sys.X509_V_FLAG_CRL_CHECK_ALL),
    };
    pub const x509Strict = X509VerifyFlags{
        .bits = @intCast(sys.X509_V_FLAG_X509_STRICT),
    };
    pub const trustedFirst = X509VerifyFlags{
        .bits = @intCast(sys.X509_V_FLAG_TRUSTED_FIRST),
    };
    pub const partialChain = X509VerifyFlags{
        .bits = @intCast(sys.X509_V_FLAG_PARTIAL_CHAIN),
    };
    pub const noAltChains = X509VerifyFlags{
        .bits = @intCast(sys.X509_V_FLAG_NO_ALT_CHAINS),
    };

    pub fn combine(self: X509VerifyFlags, other: X509VerifyFlags) X509VerifyFlags {
        return .{ .bits = self.bits | other.bits };
    }
};

pub const X509VerifyError = struct {
    code: c_int,

    pub fn fromRaw(code: c_int) X509VerifyResult {
        return X509VerifyError{ .code = code };
    }

    pub fn asRaw(self: X509VerifyError) c_int {
        return self.code;
    }

    pub fn errorString(self: X509VerifyError) [:0]const u8 {
        return std.mem.span(sys.X509_verify_cert_error_string(@intCast(self.code)));
    }
};

pub const X509VerifyResult = X509VerifyError;

pub const X509VerifyParam = struct {
    ptr: ?*sys.X509_VERIFY_PARAM,

    pub fn init() BoringError!X509VerifyParam {
        const raw_ptr = sys.X509_VERIFY_PARAM_new() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *X509VerifyParam) void {
        if (self.ptr) |raw_ptr| {
            sys.X509_VERIFY_PARAM_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const X509VerifyParam) BoringError!*sys.X509_VERIFY_PARAM {
        return self.ptr orelse error.Closed;
    }

    pub fn setFlags(self: *X509VerifyParam, verify_flags: X509VerifyFlags) BoringError!void {
        try internal.require_one(sys.X509_VERIFY_PARAM_set_flags(
            try self.raw(),
            verify_flags.bits,
        ));
    }

    pub fn clearFlags(self: *X509VerifyParam, verify_flags: X509VerifyFlags) BoringError!void {
        try internal.require_one(
            sys.X509_VERIFY_PARAM_clear_flags(try self.raw(), verify_flags.bits),
        );
    }

    pub fn getFlags(self: *const X509VerifyParam) BoringError!X509VerifyFlags {
        return .{ .bits = sys.X509_VERIFY_PARAM_get_flags(try self.raw()) };
    }

    pub fn setHostflags(self: *X509VerifyParam, hostflags: X509CheckFlags) void {
        const param = self.ptr orelse unreachable;
        sys.X509_VERIFY_PARAM_set_hostflags(param, hostflags.bits);
    }

    pub fn setHost(self: *X509VerifyParam, host: [:0]const u8) BoringError!void {
        try internal.require_one(sys.X509_VERIFY_PARAM_set1_host(
            try self.raw(),
            host.ptr,
            host.len,
        ));
    }

    pub fn setEmail(self: *X509VerifyParam, email: [:0]const u8) BoringError!void {
        try internal.require_one(sys.X509_VERIFY_PARAM_set1_email(
            try self.raw(),
            email.ptr,
            email.len,
        ));
    }

    pub fn setIp4(self: *X509VerifyParam, octets: *const [4]u8) BoringError!void {
        try internal.require_one(sys.X509_VERIFY_PARAM_set1_ip(
            try self.raw(),
            octets,
            4,
        ));
    }

    pub fn setIp6(self: *X509VerifyParam, octets: *const [16]u8) BoringError!void {
        try internal.require_one(sys.X509_VERIFY_PARAM_set1_ip(
            try self.raw(),
            octets,
            16,
        ));
    }

    pub fn setTime(self: *X509VerifyParam, time: i64) void {
        const param = self.ptr orelse unreachable;
        sys.X509_VERIFY_PARAM_set_time(param, time);
    }

    pub fn setDepth(self: *X509VerifyParam, depth: c_int) void {
        const param = self.ptr orelse unreachable;
        sys.X509_VERIFY_PARAM_set_depth(param, depth);
    }

    pub fn copyFrom(self: *X509VerifyParam, source: *const X509VerifyParam) BoringError!void {
        try internal.require_one(
            sys.X509_VERIFY_PARAM_set1(try self.raw(), try source.raw()),
        );
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.X509_VERIFY_PARAM) > 0);
}
