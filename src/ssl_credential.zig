const std = @import("std");
const build_options = @import("build_options");
const sys = @import("boringssl");

const ex_data_mod = @import("ex_data.zig");
const internal = @import("internal.zig");
const pkey_mod = @import("pkey.zig");
const BoringError = internal.BoringError;

pub const Credential = if (build_options.boringssl_rpk_patch) CredentialRpk else CredentialBase;

const CredentialBase = struct {
    ptr: ?*sys.SSL_CREDENTIAL,

    pub fn initX509() BoringError!CredentialBase {
        const cred = sys.SSL_CREDENTIAL_new_x509() orelse return error.BoringSSL;

        return .{ .ptr = cred };
    }

    pub fn initDelegated() BoringError!CredentialBase {
        const cred = sys.SSL_CREDENTIAL_new_delegated() orelse return error.BoringSSL;

        return .{ .ptr = cred };
    }

    pub fn deinit(self: *CredentialBase) void {
        if (self.ptr) |cred| {
            sys.SSL_CREDENTIAL_free(cred);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const CredentialBase) BoringError!*sys.SSL_CREDENTIAL {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *CredentialBase) BoringError!*sys.SSL_CREDENTIAL {
        const cred = try self.raw();
        self.ptr = null;

        return cred;
    }

    pub fn clone(self: *const CredentialBase) BoringError!CredentialBase {
        const cred = try self.raw();
        sys.SSL_CREDENTIAL_up_ref(cred);

        return .{ .ptr = cred };
    }

    pub fn newExIndex(comptime Data: type) BoringError!ex_data_mod.Index(Credential, Data) {
        const slot = sys.SSL_CREDENTIAL_get_ex_new_index(0, null, null, null, null);
        if (slot >= 0) return ex_data_mod.Index(Credential, Data).fromRaw(slot);

        return error.BoringSSL;
    }

    pub fn setExData(
        self: *CredentialBase,
        comptime Data: type,
        index: ex_data_mod.Index(Credential, Data),
        data: ?*Data,
    ) BoringError!void {
        const cred = self.ptr orelse return error.Closed;
        return internal.require_one(sys.SSL_CREDENTIAL_set_ex_data(cred, index.asRaw(), data));
    }

    pub fn exData(
        self: *const CredentialBase,
        comptime Data: type,
        index: ex_data_mod.Index(Credential, Data),
    ) ?*Data {
        const cred = self.ptr orelse return null;
        const data = sys.SSL_CREDENTIAL_get_ex_data(cred, index.asRaw()) orelse return null;

        return @ptrCast(@alignCast(data));
    }
};

const CredentialRpk = struct {
    ptr: ?*sys.SSL_CREDENTIAL,

    pub fn initX509() BoringError!CredentialRpk {
        const cred = sys.SSL_CREDENTIAL_new_x509() orelse return error.BoringSSL;

        return .{ .ptr = cred };
    }

    pub fn initDelegated() BoringError!CredentialRpk {
        const cred = sys.SSL_CREDENTIAL_new_delegated() orelse return error.BoringSSL;

        return .{ .ptr = cred };
    }

    pub fn initRawPublicKey() BoringError!CredentialRpk {
        const cred = sys.SSL_CREDENTIAL_new_raw_public_key() orelse return error.BoringSSL;

        return .{ .ptr = cred };
    }

    pub fn deinit(self: *CredentialRpk) void {
        if (self.ptr) |cred| {
            sys.SSL_CREDENTIAL_free(cred);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const CredentialRpk) BoringError!*sys.SSL_CREDENTIAL {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *CredentialRpk) BoringError!*sys.SSL_CREDENTIAL {
        const cred = try self.raw();
        self.ptr = null;

        return cred;
    }

    pub fn clone(self: *const CredentialRpk) BoringError!CredentialRpk {
        const cred = try self.raw();
        sys.SSL_CREDENTIAL_up_ref(cred);

        return .{ .ptr = cred };
    }

    pub fn newExIndex(comptime Data: type) BoringError!ex_data_mod.Index(Credential, Data) {
        const slot = sys.SSL_CREDENTIAL_get_ex_new_index(0, null, null, null, null);
        if (slot >= 0) return ex_data_mod.Index(Credential, Data).fromRaw(slot);

        return error.BoringSSL;
    }

    pub fn setExData(
        self: *CredentialRpk,
        comptime Data: type,
        index: ex_data_mod.Index(Credential, Data),
        data: ?*Data,
    ) BoringError!void {
        const cred = self.ptr orelse return error.Closed;
        return internal.require_one(sys.SSL_CREDENTIAL_set_ex_data(cred, index.asRaw(), data));
    }

    pub fn exData(
        self: *const CredentialRpk,
        comptime Data: type,
        index: ex_data_mod.Index(Credential, Data),
    ) ?*Data {
        const cred = self.ptr orelse return null;
        const data = sys.SSL_CREDENTIAL_get_ex_data(cred, index.asRaw()) orelse return null;

        return @ptrCast(@alignCast(data));
    }
};

pub const CredentialRef = struct {
    ptr: *sys.SSL_CREDENTIAL,

    pub fn fromRaw(ptr: *sys.SSL_CREDENTIAL) CredentialRef {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: *const CredentialRef) *sys.SSL_CREDENTIAL {
        return self.ptr;
    }

    pub fn exData(
        self: *const CredentialRef,
        comptime Data: type,
        index: ex_data_mod.Index(Credential, Data),
    ) ?*Data {
        const data = sys.SSL_CREDENTIAL_get_ex_data(self.ptr, index.asRaw()) orelse return null;

        return @ptrCast(@alignCast(data));
    }
};

pub const CredentialBuilder = if (build_options.boringssl_rpk_patch)
    CredentialBuilderRpk
else
    CredentialBuilderBase;

const CredentialBuilderBase = struct {
    cred: CredentialBase,

    pub fn initX509() BoringError!CredentialBuilderBase {
        const cred = try CredentialBase.initX509();

        return .{ .cred = cred };
    }

    pub fn initDelegated() BoringError!CredentialBuilderBase {
        const cred = try CredentialBase.initDelegated();

        return .{ .cred = cred };
    }

    pub fn deinit(self: *CredentialBuilderBase) void {
        self.cred.deinit();
    }

    pub fn setPrivateKey(
        self: *CredentialBuilderBase,
        key: *const pkey_mod.PKey,
    ) BoringError!void {
        const cred = try self.cred.raw();
        try internal.require_one(sys.SSL_CREDENTIAL_set1_private_key(cred, try key.raw()));
    }

    pub fn setCertChain(
        self: *CredentialBuilderBase,
        certs: []const *sys.CRYPTO_BUFFER,
    ) BoringError!void {
        std.debug.assert(certs.len > 0);

        const cred = try self.cred.raw();
        try internal.require_one(sys.SSL_CREDENTIAL_set1_cert_chain(
            cred,
            certs.ptr,
            certs.len,
        ));
    }

    pub fn setOcspResponse(
        self: *CredentialBuilderBase,
        response: *sys.CRYPTO_BUFFER,
    ) BoringError!void {
        const cred = try self.cred.raw();
        try internal.require_one(sys.SSL_CREDENTIAL_set1_ocsp_response(cred, response));
    }

    pub fn setSignedCertTimestampList(
        self: *CredentialBuilderBase,
        sct_list: *sys.CRYPTO_BUFFER,
    ) BoringError!void {
        const cred = try self.cred.raw();
        try internal.require_one(sys.SSL_CREDENTIAL_set1_signed_cert_timestamp_list(
            cred,
            sct_list,
        ));
    }

    pub fn build(self: *CredentialBuilderBase) CredentialBase {
        const cred = self.cred;
        std.debug.assert(cred.ptr != null);
        self.cred.ptr = null;

        return cred;
    }
};

const CredentialBuilderRpk = struct {
    cred: CredentialRpk,

    pub fn initX509() BoringError!CredentialBuilderRpk {
        const cred = try CredentialRpk.initX509();

        return .{ .cred = cred };
    }

    pub fn initDelegated() BoringError!CredentialBuilderRpk {
        const cred = try CredentialRpk.initDelegated();

        return .{ .cred = cred };
    }

    pub fn initRawPublicKey() BoringError!CredentialBuilderRpk {
        const cred = try CredentialRpk.initRawPublicKey();

        return .{ .cred = cred };
    }

    pub fn deinit(self: *CredentialBuilderRpk) void {
        self.cred.deinit();
    }

    pub fn setPrivateKey(
        self: *CredentialBuilderRpk,
        key: *const pkey_mod.PKey,
    ) BoringError!void {
        const cred = try self.cred.raw();
        try internal.require_one(sys.SSL_CREDENTIAL_set1_private_key(cred, try key.raw()));
    }

    pub fn setSpkiBytes(self: *CredentialBuilderRpk, spki: ?[]const u8) BoringError!void {
        const cred = try self.cred.raw();

        if (spki) |bytes| {
            try internal.require_non_empty(bytes);

            const buffer = sys.CRYPTO_BUFFER_new(bytes.ptr, bytes.len, null) orelse {
                return error.BoringSSL;
            };
            defer sys.CRYPTO_BUFFER_free(buffer);

            try internal.require_one(sys.SSL_CREDENTIAL_set1_spki(cred, buffer));
        } else {
            try internal.require_one(sys.SSL_CREDENTIAL_set1_spki(cred, null));
        }
    }

    pub fn setCertChain(
        self: *CredentialBuilderRpk,
        certs: []const *sys.CRYPTO_BUFFER,
    ) BoringError!void {
        std.debug.assert(certs.len > 0);

        const cred = try self.cred.raw();
        try internal.require_one(sys.SSL_CREDENTIAL_set1_cert_chain(
            cred,
            certs.ptr,
            certs.len,
        ));
    }

    pub fn setOcspResponse(
        self: *CredentialBuilderRpk,
        response: *sys.CRYPTO_BUFFER,
    ) BoringError!void {
        const cred = try self.cred.raw();
        try internal.require_one(sys.SSL_CREDENTIAL_set1_ocsp_response(cred, response));
    }

    pub fn setSignedCertTimestampList(
        self: *CredentialBuilderRpk,
        sct_list: *sys.CRYPTO_BUFFER,
    ) BoringError!void {
        const cred = try self.cred.raw();
        try internal.require_one(sys.SSL_CREDENTIAL_set1_signed_cert_timestamp_list(
            cred,
            sct_list,
        ));
    }

    pub fn build(self: *CredentialBuilderRpk) CredentialRpk {
        const cred = self.cred;
        std.debug.assert(cred.ptr != null);
        self.cred.ptr = null;

        return cred;
    }
};

comptime {
    std.debug.assert(@sizeOf(*sys.SSL_CREDENTIAL) > 0);
}
