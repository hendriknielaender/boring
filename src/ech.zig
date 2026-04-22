const std = @import("std");
const sys = @import("boringssl");

const hpke_mod = @import("hpke.zig");
const internal = @import("internal.zig");
const BoringError = internal.BoringError;

pub const EchKeys = struct {
    ptr: ?*sys.SSL_ECH_KEYS,

    pub fn init() BoringError!EchKeys {
        const keys = sys.SSL_ECH_KEYS_new() orelse return error.BoringSSL;

        return .{ .ptr = keys };
    }

    pub fn deinit(self: *EchKeys) void {
        if (self.ptr) |keys| {
            sys.SSL_ECH_KEYS_free(keys);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const EchKeys) BoringError!*sys.SSL_ECH_KEYS {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *EchKeys) BoringError!*sys.SSL_ECH_KEYS {
        const keys = try self.raw();
        self.ptr = null;

        return keys;
    }

    pub fn builder() BoringError!EchKeysBuilder {
        return EchKeysBuilder.init();
    }

    pub fn hasDuplicateConfigId(self: *const EchKeys) BoringError!bool {
        return sys.SSL_ECH_KEYS_has_duplicate_config_id(try self.raw()) == 1;
    }

    pub fn marshalRetryConfigs(self: *const EchKeys) BoringError!EchConfigList {
        var out_data: [*c]u8 = null;
        var out_len: usize = 0;
        try internal.require_one(sys.SSL_ECH_KEYS_marshal_retry_configs(
            try self.raw(),
            &out_data,
            &out_len,
        ));

        return EchConfigList.from_raw_owned(out_data, out_len);
    }
};

pub const EchKeysBuilder = struct {
    keys: EchKeys,

    pub fn init() BoringError!EchKeysBuilder {
        const keys = try EchKeys.init();

        return .{ .keys = keys };
    }

    pub fn deinit(self: *EchKeysBuilder) void {
        self.keys.deinit();
    }

    pub fn addKey(
        self: *EchKeysBuilder,
        is_retry_config: bool,
        ech_config: []const u8,
        key: *const hpke_mod.HpkeKey,
    ) BoringError!void {
        std.debug.assert(ech_config.len > 0);

        const keys = try self.keys.raw();
        const retry_flag: c_int = if (is_retry_config) 1 else 0;

        try internal.require_one(sys.SSL_ECH_KEYS_add(
            keys,
            retry_flag,
            ech_config.ptr,
            ech_config.len,
            try key.raw(),
        ));
    }

    pub fn build(self: *EchKeysBuilder) EchKeys {
        const keys = self.keys;
        self.keys.ptr = null;

        return keys;
    }
};

pub const EchConfig = struct {
    data: OwnedBytes,

    pub fn marshal(
        config_id: u8,
        key: *const hpke_mod.HpkeKey,
        public_name: [:0]const u8,
        max_name_len: usize,
    ) BoringError!EchConfig {
        if (public_name.len == 0) return error.InvalidArgument;
        if (max_name_len == 0) return error.InvalidArgument;

        var out_data: [*c]u8 = null;
        var out_len: usize = 0;
        try internal.require_one(sys.SSL_marshal_ech_config(
            &out_data,
            &out_len,
            config_id,
            try key.raw(),
            public_name.ptr,
            max_name_len,
        ));

        return .{ .data = try OwnedBytes.from_raw_owned(out_data, out_len) };
    }

    pub fn deinit(self: *EchConfig) void {
        self.data.deinit();
    }

    pub fn bytes(self: *const EchConfig) []const u8 {
        return self.data.bytes();
    }
};

pub const EchConfigList = struct {
    data: OwnedBytes,

    fn from_raw_owned(ptr: [*c]u8, len: usize) BoringError!EchConfigList {
        return .{ .data = try OwnedBytes.from_raw_owned(ptr, len) };
    }

    pub fn deinit(self: *EchConfigList) void {
        self.data.deinit();
    }

    pub fn bytes(self: *const EchConfigList) []const u8 {
        return self.data.bytes();
    }
};

const OwnedBytes = struct {
    ptr: [*c]u8,
    len: usize,

    fn from_raw_owned(ptr: [*c]u8, len: usize) BoringError!OwnedBytes {
        if (ptr == null) return error.BoringSSL;
        if (len == 0) {
            sys.OPENSSL_free(ptr);
            return error.BoringSSL;
        }

        return .{ .ptr = ptr, .len = len };
    }

    fn deinit(self: *OwnedBytes) void {
        if (self.ptr != null) {
            sys.OPENSSL_free(self.ptr);
            self.ptr = null;
            self.len = 0;
        }
    }

    fn bytes(self: *const OwnedBytes) []const u8 {
        if (self.ptr == null) return "";

        return @as([*]const u8, @ptrCast(self.ptr))[0..self.len];
    }
};

comptime {
    std.debug.assert(@sizeOf(c_int) >= 4);
    std.debug.assert(@sizeOf(usize) >= @sizeOf(u32));
}
