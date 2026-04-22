const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const x509_mod = @import("x509.zig");
const BoringError = internal.BoringError;

/// Stacks are counted with size_t in BoringSSL.
/// Iteration is capped at this value to keep static bounds.
/// Certificate chains should never come close to this limit.
pub const MaxStackEntries: usize = 4096;

/// Owning stack of X509 certificates.
pub const X509Stack = struct {
    ptr: ?*sys.struct_stack_st_X509,

    pub fn init() BoringError!X509Stack {
        const raw_ptr = sys.sk_X509_new_null() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn fromRawOwned(raw_ptr: *sys.struct_stack_st_X509) X509Stack {
        return .{ .ptr = raw_ptr };
    }

    pub fn fromRawBorrowed(raw_ptr: *const sys.struct_stack_st_X509) BoringError!X509Stack {
        const stack_ptr = sys.sk_X509_dup(raw_ptr) orelse return error.BoringSSL;
        const count = sys.sk_X509_num(stack_ptr);
        if (count > MaxStackEntries) {
            sys.sk_X509_free(stack_ptr);
            return error.Overflow;
        }

        var index: usize = 0;
        errdefer {
            var rollback: usize = 0;
            while (rollback < index) : (rollback += 1) {
                const cert_ptr = sys.sk_X509_value(stack_ptr, rollback);
                if (cert_ptr != null) sys.X509_free(cert_ptr);
            }
            sys.sk_X509_free(stack_ptr);
        }

        while (index < count) : (index += 1) {
            const cert_ptr = sys.sk_X509_value(stack_ptr, index) orelse return error.BoringSSL;
            try internal.require_one(sys.X509_up_ref(cert_ptr));
        }

        return .{ .ptr = stack_ptr };
    }

    pub fn deinit(self: *X509Stack) void {
        if (self.ptr) |stack_ptr| {
            free_with_items(stack_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const X509Stack) BoringError!*sys.struct_stack_st_X509 {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *X509Stack) BoringError!*sys.struct_stack_st_X509 {
        const raw_ptr = try self.raw();
        self.ptr = null;

        return raw_ptr;
    }

    pub fn len(self: *const X509Stack) BoringError!usize {
        const count = sys.sk_X509_num(try self.raw());
        if (count > MaxStackEntries) return error.Overflow;

        return count;
    }

    pub fn isEmpty(self: *const X509Stack) BoringError!bool {
        return (try self.len()) == 0;
    }

    pub fn push(self: *X509Stack, cert: *x509_mod.X509) BoringError!void {
        const stack_ptr = try self.raw();
        const cert_ptr = try cert.intoRaw();
        errdefer sys.X509_free(cert_ptr);

        const position = sys.sk_X509_push(stack_ptr, cert_ptr);
        if (position == 0) return error.BoringSSL;
    }

    pub fn pop(self: *X509Stack) BoringError!?x509_mod.X509 {
        const stack_ptr = try self.raw();
        const raw_cert = sys.sk_X509_pop(stack_ptr) orelse return null;

        return x509_mod.X509.fromRawOwned(raw_cert);
    }

    /// Borrows the certificate at `index` without taking ownership.
    pub fn get(self: *const X509Stack, index: usize) BoringError!?x509_mod.X509Ref {
        const stack_ptr = try self.raw();
        const count = try self.len();
        if (index >= count) return null;

        const raw_cert = sys.sk_X509_value(stack_ptr, index) orelse return error.BoringSSL;

        return x509_mod.X509Ref.fromRaw(raw_cert);
    }
};

fn free_with_items(stack_ptr: *sys.struct_stack_st_X509) void {
    sys.sk_X509_pop_free(stack_ptr, sys.X509_free);
}

comptime {
    std.debug.assert(MaxStackEntries >= 16);
    std.debug.assert(MaxStackEntries <= std.math.maxInt(c_int));
}
