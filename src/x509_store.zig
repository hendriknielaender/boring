const std = @import("std");
const sys = @import("boringssl");

const internal = @import("internal.zig");
const verify_mod = @import("x509_verify.zig");
const x509_mod = @import("x509.zig");
const BoringError = internal.BoringError;

pub const MaxStoreObjects: usize = 4096;

pub const X509ObjectType = enum(c_int) {
    x509 = sys.X509_LU_X509,
    crl = sys.X509_LU_CRL,
};

pub const X509ObjectRef = struct {
    ptr: *const sys.X509_OBJECT,

    pub fn fromRaw(ptr: *const sys.X509_OBJECT) X509ObjectRef {
        return .{ .ptr = ptr };
    }

    pub fn objectType(self: X509ObjectRef) X509ObjectType {
        return @enumFromInt(sys.X509_OBJECT_get_type(self.ptr));
    }

    pub fn certificate(self: X509ObjectRef) ?x509_mod.X509Ref {
        if (sys.X509_OBJECT_get_type(self.ptr) != sys.X509_LU_X509) return null;
        const cert = sys.X509_OBJECT_get0_X509(self.ptr);
        if (cert == null) return null;

        return x509_mod.X509Ref.fromRaw(cert.?);
    }
};

pub const X509ObjectIterator = struct {
    ptr: ?*const sys.struct_stack_st_X509_OBJECT,
    index: usize,

    pub fn init(store: *const X509Store) X509ObjectIterator {
        const store_ptr = store.ptr orelse return .{ .ptr = null, .index = 0 };
        const objects = sys.X509_STORE_get0_objects(store_ptr);

        return .{ .ptr = objects, .index = 0 };
    }

    pub fn next(self: *X509ObjectIterator) ?X509ObjectRef {
        const stack_ptr = self.ptr orelse return null;
        const count = sys.struct_stack_st_X509_OBJECT.sk_X509_OBJECT_num(stack_ptr);
        if (self.index >= count) return null;
        if (self.index >= MaxStoreObjects) return null;

        const entry = sys.struct_stack_st_X509_OBJECT.sk_X509_OBJECT_value(stack_ptr, self.index);
        self.index += 1;
        if (entry == null) return null;

        return X509ObjectRef.fromRaw(entry.?);
    }
};

pub const X509StoreBuilder = struct {
    ptr: ?*sys.X509_STORE,

    pub fn init() BoringError!X509StoreBuilder {
        const raw_ptr = sys.X509_STORE_new() orelse return error.BoringSSL;

        return .{ .ptr = raw_ptr };
    }

    pub fn deinit(self: *X509StoreBuilder) void {
        if (self.ptr) |raw_ptr| {
            sys.X509_STORE_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn build(self: *X509StoreBuilder) X509Store {
        const store = self.ptr orelse unreachable;
        self.ptr = null;

        return .{ .ptr = store };
    }

    pub fn addCert(self: *X509StoreBuilder, cert: *const x509_mod.X509) BoringError!void {
        const store = self.ptr orelse return error.Closed;
        try internal.require_one(sys.X509_STORE_add_cert(store, try cert.raw()));
    }

    pub fn setDefaultPaths(self: *X509StoreBuilder) BoringError!void {
        const store = self.ptr orelse return error.Closed;
        try internal.require_one(sys.X509_STORE_set_default_paths(store));
    }

    pub fn setFlags(self: *X509StoreBuilder, flags: verify_mod.X509VerifyFlags) BoringError!void {
        const store = self.ptr orelse return error.Closed;
        try internal.require_one(sys.X509_STORE_set_flags(store, flags.bits));
    }

    pub fn verifyParam(self: *X509StoreBuilder) ?verify_mod.X509VerifyParam {
        const store = self.ptr orelse return null;
        const param = sys.X509_STORE_get0_param(store) orelse return null;

        return .{ .ptr = param };
    }

    pub fn setParam(
        self: *X509StoreBuilder,
        param: *const verify_mod.X509VerifyParam,
    ) BoringError!void {
        const store = self.ptr orelse return error.Closed;
        try internal.require_one(sys.X509_STORE_set1_param(store, try param.raw()));
    }
};

pub const X509Store = struct {
    ptr: ?*sys.X509_STORE,

    pub fn deinit(self: *X509Store) void {
        if (self.ptr) |raw_ptr| {
            sys.X509_STORE_free(raw_ptr);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const X509Store) BoringError!*sys.X509_STORE {
        return self.ptr orelse error.Closed;
    }

    pub fn clone(self: *const X509Store) BoringError!X509Store {
        const store = try self.raw();
        try internal.require_one(sys.X509_STORE_up_ref(store));

        return .{ .ptr = store };
    }

    pub fn objects(self: *const X509Store) X509ObjectIterator {
        return X509ObjectIterator.init(self);
    }

    pub fn objectsLen(self: *const X509Store) usize {
        const store = self.ptr orelse return 0;
        const stack_ptr = sys.X509_STORE_get0_objects(store) orelse return 0;
        return @intCast(sys.struct_stack_st_X509_OBJECT.sk_X509_OBJECT_num(
            stack_ptr,
        ));
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.X509_STORE) > 0);
}
