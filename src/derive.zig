const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const pkey_mod = @import("pkey.zig");
const BoringError = internal.BoringError;

pub const Deriver = struct {
    ctx: ?*sys.EVP_PKEY_CTX,

    pub fn init(key: *const pkey_mod.PKey) BoringError!Deriver {
        const ctx = sys.EVP_PKEY_CTX_new(try key.raw(), null) orelse return error.BoringSSL;
        errdefer sys.EVP_PKEY_CTX_free(ctx);

        try internal.require_one(sys.EVP_PKEY_derive_init(ctx));

        return .{ .ctx = ctx };
    }

    pub fn deinit(self: *Deriver) void {
        if (self.ctx) |ctx| {
            sys.EVP_PKEY_CTX_free(ctx);
            self.ctx = null;
        }
    }

    pub fn setPeer(self: *Deriver, peer: *const pkey_mod.PKey) BoringError!void {
        try internal.require_one(sys.EVP_PKEY_derive_set_peer(
            try self.raw(),
            try peer.raw(),
        ));
    }

    pub fn length(self: *Deriver) BoringError!usize {
        var len: usize = 0;
        try internal.require_one(sys.EVP_PKEY_derive(try self.raw(), null, &len));

        return len;
    }

    pub fn derive(self: *Deriver, output: []u8) BoringError!usize {
        var len = output.len;
        try internal.require_one(sys.EVP_PKEY_derive(try self.raw(), output.ptr, &len));

        return len;
    }

    fn raw(self: *const Deriver) BoringError!*sys.EVP_PKEY_CTX {
        return self.ctx orelse error.Closed;
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.EVP_PKEY_CTX) > 0);
}
