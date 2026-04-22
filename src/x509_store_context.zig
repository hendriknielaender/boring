const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const stack_mod = @import("stack.zig");
const verify_mod = @import("x509_verify.zig");
const x509_mod = @import("x509.zig");
const store_mod = @import("x509_store.zig");
const BoringError = internal.BoringError;

pub const X509StoreContext = struct {
    ptr: ?*sys.X509_STORE_CTX,

    pub fn init() BoringError!X509StoreContext {
        const raw_ptr = sys.X509_STORE_CTX_new() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *X509StoreContext) void {
        if (self.ptr) |raw_ptr| {
            sys.X509_STORE_CTX_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const X509StoreContext) BoringError!*sys.X509_STORE_CTX {
        return self.ptr orelse error.Closed;
    }

    pub fn initVerification(
        self: *X509StoreContext,
        store: *const store_mod.X509Store,
        leaf_cert: *const x509_mod.X509,
        untrusted_certs: *const stack_mod.X509Stack,
    ) BoringError!void {
        const ctx = try self.raw();
        try internal.require_one(sys.X509_STORE_CTX_init(
            ctx,
            try store.raw(),
            try leaf_cert.raw(),
            try untrusted_certs.raw(),
        ));
    }

    pub fn cleanup(self: *X509StoreContext) void {
        const ctx = self.ptr orelse return;
        sys.X509_STORE_CTX_cleanup(ctx);
    }

    pub fn verifyCert(self: *X509StoreContext) BoringError!bool {
        const ctx = try self.raw();
        const result = sys.X509_verify_cert(ctx);

        return result > 0;
    }

    pub fn verifyResult(self: *const X509StoreContext) verify_mod.X509VerifyResult {
        const ctx = self.ptr orelse return verify_mod.X509VerifyError{
            .code = sys.X509_V_ERR_UNSPECIFIED,
        };
        const code = sys.X509_STORE_CTX_get_error(ctx);

        return verify_mod.X509VerifyError.fromRaw(code);
    }

    pub fn verifyError(self: *const X509StoreContext) c_int {
        const ctx = self.ptr orelse return sys.X509_V_ERR_UNSPECIFIED;
        return sys.X509_STORE_CTX_get_error(ctx);
    }

    pub fn setError(self: *X509StoreContext, err: verify_mod.X509VerifyError) void {
        const ctx = self.ptr orelse return;
        sys.X509_STORE_CTX_set_error(ctx, err.asRaw());
    }

    pub fn cert(self: *const X509StoreContext) ?x509_mod.X509Ref {
        const ctx = self.ptr orelse return null;
        const cert_ptr = sys.X509_STORE_CTX_get0_cert(ctx);
        if (cert_ptr == null) return null;

        return x509_mod.X509Ref.fromRaw(cert_ptr.?);
    }

    pub fn currentCert(self: *const X509StoreContext) ?x509_mod.X509Ref {
        const ctx = self.ptr orelse return null;
        const cert_ptr = sys.X509_STORE_CTX_get_current_cert(ctx);
        if (cert_ptr == null) return null;

        return x509_mod.X509Ref.fromRaw(cert_ptr.?);
    }

    pub fn chain(self: *const X509StoreContext) ?stack_mod.X509Stack {
        const ctx = self.ptr orelse return null;
        const chain_ptr = sys.X509_STORE_CTX_get_chain(ctx);
        if (chain_ptr == null) return null;

        return stack_mod.X509Stack.fromRawBorrowed(chain_ptr.?) catch null;
    }

    pub fn untrusted(self: *const X509StoreContext) ?stack_mod.X509Stack {
        const ctx = self.ptr orelse return null;
        const untrusted_ptr = sys.X509_STORE_CTX_get0_untrusted(ctx);
        if (untrusted_ptr == null) return null;

        return stack_mod.X509Stack.fromRawBorrowed(untrusted_ptr.?) catch null;
    }

    pub fn errorDepth(self: *const X509StoreContext) u32 {
        const ctx = self.ptr orelse return 0;
        const depth = sys.X509_STORE_CTX_get_error_depth(ctx);
        if (depth < 0) return 0;

        return @intCast(depth);
    }

    pub fn verifyParam(self: *X509StoreContext) ?verify_mod.X509VerifyParam {
        const ctx = self.ptr orelse return null;
        const param = sys.X509_STORE_CTX_get0_param(ctx) orelse return null;

        return .{ .ptr = param };
    }

    pub fn setVerifyParam(self: *X509StoreContext, param: *verify_mod.X509VerifyParam) void {
        const ctx = self.ptr orelse return;
        const raw_param = param.ptr orelse return;
        sys.X509_STORE_CTX_set0_param(ctx, raw_param);
        param.ptr = null;
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.X509_STORE_CTX) > 0);
}
