const std = @import("std");
const sys = @import("boringssl");

const dh_mod = @import("dh.zig");
const ech_mod = @import("ech.zig");
const ex_data_mod = @import("ex_data.zig");
const hmac_mod = @import("hmac.zig");
const internal = @import("internal.zig");
const pkey_mod = @import("pkey.zig");
const srtp_mod = @import("srtp.zig");
const ssl_credential_mod = @import("ssl_credential.zig");
const stack_mod = @import("stack.zig");
const symm_mod = @import("symm.zig");
const x509_mod = @import("x509.zig");
const x509_store_context_mod = @import("x509_store_context.zig");
const x509_store_mod = @import("x509_store.zig");
const x509_verify_mod = @import("x509_verify.zig");
const BoringError = internal.BoringError;

pub const ContextRef = struct {
    ptr: *sys.SSL_CTX,

    pub fn fromRaw(ptr: *sys.SSL_CTX) ContextRef {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: ContextRef) *sys.SSL_CTX {
        return self.ptr;
    }

    pub fn certStore(self: ContextRef) ?x509_store_mod.X509Store {
        const store = sys.SSL_CTX_get_cert_store(self.ptr) orelse return null;
        if (sys.X509_STORE_up_ref(store) != 1) return null;

        return .{ .ptr = store };
    }

    pub fn sessionCacheSize(self: ContextRef) u32 {
        return sys.SSL_CTX_sess_get_cache_size(self.ptr);
    }
};

pub const SslRef = struct {
    ptr: *sys.SSL,

    pub fn fromRaw(ptr: *sys.SSL) SslRef {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: SslRef) *sys.SSL {
        return self.ptr;
    }

    pub fn sslContext(self: SslRef) ?ContextRef {
        const ctx = sys.SSL_get_SSL_CTX(self.ptr) orelse return null;
        return ContextRef.fromRaw(ctx);
    }

    pub fn exData(
        self: SslRef,
        comptime Data: type,
        index: ex_data_mod.Index(Ssl, Data),
    ) ?*Data {
        return ssl_ex_data(self.ptr, Data, index);
    }

    pub fn serverName(self: SslRef, name_type: NameType) ?[:0]const u8 {
        const ptr = sys.SSL_get_servername(self.ptr, name_type.raw());
        if (ptr == null) return null;
        return std.mem.span(ptr);
    }

    pub fn serverNameType(self: SslRef) ?NameType {
        const result = sys.SSL_get_servername_type(self.ptr);
        if (result < 0) return null;
        return NameType{ .value = result };
    }

    pub fn peerCertificate(self: SslRef) ?x509_mod.X509 {
        const cert = sys.SSL_get_peer_certificate(self.ptr) orelse return null;
        return x509_mod.X509.fromRawOwned(cert);
    }

    pub fn pending(self: SslRef) usize {
        const result = sys.SSL_pending(self.ptr);
        if (result < 0) return 0;
        return @intCast(result);
    }

    pub fn stateString(self: SslRef) [:0]const u8 {
        const ptr = sys.SSL_state_string(self.ptr);
        return std.mem.span(ptr);
    }

    pub fn stateStringLong(self: SslRef) [:0]const u8 {
        const ptr = sys.SSL_state_string_long(self.ptr);
        return std.mem.span(ptr);
    }

    pub fn selectedAlpn(self: SslRef) ?[]const u8 {
        return ssl_selected_alpn(self.ptr);
    }

    pub fn version(self: SslRef) [:0]const u8 {
        return std.mem.span(sys.SSL_get_version(self.ptr));
    }

    pub fn sessionReused(self: SslRef) bool {
        return sys.SSL_session_reused(self.ptr) == 1;
    }

    pub fn currentCipher(self: SslRef) ?SslCipher {
        const cipher = sys.SSL_get_current_cipher(self.ptr) orelse return null;
        return SslCipher.fromRaw(cipher);
    }

    pub fn ciphers(self: SslRef) ?SslCipherList {
        const ciphers_list = sys.SSL_get_ciphers(self.ptr) orelse return null;
        return .{ .ptr = ciphers_list };
    }

    pub fn serverRandom(self: SslRef, out: []u8) usize {
        if (out.len == 0) return 0;
        return sys.SSL_get_server_random(self.ptr, out.ptr, out.len);
    }

    pub fn clientRandom(self: SslRef, out: []u8) usize {
        if (out.len == 0) return 0;
        return sys.SSL_get_client_random(self.ptr, out.ptr, out.len);
    }

    pub fn exportKeyingMaterial(
        self: SslRef,
        out: []u8,
        label: []const u8,
        context_bytes: ?[]const u8,
    ) BoringError!void {
        const use_context: c_int = if (context_bytes != null) 1 else 0;
        const ctx_ptr = if (context_bytes) |c| c.ptr else null;
        const ctx_len = if (context_bytes) |c| c.len else 0;
        try internal.require_one(sys.SSL_export_keying_material(
            self.ptr,
            out.ptr,
            out.len,
            label.ptr,
            label.len,
            ctx_ptr,
            ctx_len,
            use_context,
        ));
    }

    pub fn srtpProfiles(self: SslRef) ?SrtpProfileList {
        const stack = sys.SSL_get_srtp_profiles(self.ptr) orelse return null;
        return SrtpProfileList{ .ptr = stack };
    }

    pub fn selectedSrtpProfile(self: SslRef) ?srtp_mod.SrtpProtectionProfile {
        const profile = sys.SSL_get_selected_srtp_profile(self.ptr);
        if (profile == null) return null;
        return srtp_mod.SrtpProtectionProfile.fromRaw(profile);
    }

    pub fn verifyResult(self: SslRef) x509_verify_mod.X509VerifyResult {
        const result = sys.SSL_get_verify_result(self.ptr);
        return x509_verify_mod.X509VerifyResult.fromRaw(result);
    }

    pub fn verifyParam(self: SslRef) BoringError!*sys.X509_VERIFY_PARAM {
        const param = sys.SSL_get0_param(self.ptr) orelse return error.BoringSSL;
        return param;
    }

    pub fn getMinProtoVersion(self: SslRef) ?SslVersion {
        const result = sys.SSL_get_min_proto_version(self.ptr);
        if (result == 0) return null;
        return SslVersion.fromRaw(result);
    }

    pub fn getMaxProtoVersion(self: SslRef) ?SslVersion {
        const result = sys.SSL_get_max_proto_version(self.ptr);
        if (result == 0) return null;
        return SslVersion.fromRaw(result);
    }

    pub fn curveId(self: SslRef) ?u16 {
        const result = sys.SSL_get_curve_id(self.ptr);
        if (result == 0) return null;
        return result;
    }

    pub fn curveName(self: SslRef) ?[:0]const u8 {
        const id = self.curveId() orelse return null;
        const name = sys.SSL_get_curve_name(id);
        if (name == null) return null;
        return std.mem.span(name);
    }

    pub fn usedHelloRetryRequest(self: SslRef) bool {
        return sys.SSL_used_hello_retry_request(self.ptr) != 0;
    }

    pub fn echAccepted(self: SslRef) bool {
        return sys.SSL_ech_accepted(self.ptr) == 1;
    }

    pub fn echNameOverride(self: SslRef) ?[]const u8 {
        var name: [*c]const u8 = null;
        var name_len: usize = 0;
        sys.SSL_get0_ech_name_override(self.ptr, &name, &name_len);

        if (name == null) return null;
        if (name_len == 0) return null;

        return @as([*]const u8, @ptrCast(name))[0..name_len];
    }

    pub fn echRetryConfigs(self: SslRef) ?[]const u8 {
        var configs: [*c]const u8 = null;
        var configs_len: usize = 0;
        sys.SSL_get0_ech_retry_configs(self.ptr, &configs, &configs_len);

        if (configs == null) return null;
        if (configs_len == 0) return null;

        return @as([*]const u8, @ptrCast(configs))[0..configs_len];
    }

    pub fn getShutdown(self: SslRef) ShutdownState {
        return .{ .bits = sys.SSL_get_shutdown(self.ptr) };
    }

    pub fn session(self: SslRef) ?SslSession {
        const raw_session = sys.SSL_get1_session(self.ptr) orelse return null;
        return SslSession.fromRawOwned(raw_session);
    }

    pub fn peerCertChain(self: SslRef) ?stack_mod.X509Stack {
        const chain = sys.SSL_get_peer_cert_chain(self.ptr) orelse return null;
        return stack_mod.X509Stack.fromRawBorrowed(chain) catch null;
    }
};

pub const Ssl = struct {
    ptr: ?*sys.SSL,

    pub fn fromRawOwned(ptr: *sys.SSL) Ssl {
        return .{ .ptr = ptr };
    }

    pub fn deinit(self: *Ssl) void {
        if (self.ptr) |ssl| {
            sys.SSL_free(ssl);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const Ssl) BoringError!*sys.SSL {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *Ssl) BoringError!*sys.SSL {
        const ssl = try self.raw();
        self.ptr = null;
        return ssl;
    }

    pub fn ref(self: *Ssl) BoringError!SslRef {
        return SslRef.fromRaw(try self.raw());
    }

    pub fn serverName(self: *const Ssl, name_type: NameType) ?[:0]const u8 {
        const ssl = self.ptr orelse return null;
        return SslRef.fromRaw(ssl).serverName(name_type);
    }

    pub fn serverNameType(self: *const Ssl) ?NameType {
        const ssl = self.ptr orelse return null;
        return SslRef.fromRaw(ssl).serverNameType();
    }

    pub fn newExIndex(comptime Data: type) BoringError!ex_data_mod.Index(Ssl, Data) {
        return ssl_ex_new_index(Data);
    }

    pub fn setExData(
        self: *Ssl,
        comptime Data: type,
        index: ex_data_mod.Index(Ssl, Data),
        data: ?*Data,
    ) BoringError!void {
        const ssl = self.ptr orelse return error.Closed;
        return ssl_set_ex_data(ssl, Data, index, data);
    }

    pub fn exData(
        self: *const Ssl,
        comptime Data: type,
        index: ex_data_mod.Index(Ssl, Data),
    ) ?*Data {
        const ssl = self.ptr orelse return null;
        return ssl_ex_data(ssl, Data, index);
    }

    pub fn replaceExData(
        self: *Ssl,
        comptime Data: type,
        index: ex_data_mod.Index(Ssl, Data),
        data: ?*Data,
    ) ?*Data {
        const ssl = self.ptr orelse return null;
        const old = ssl_ex_data(ssl, Data, index);
        ssl_set_ex_data(ssl, Data, index, data) catch return null;
        return old;
    }

    pub fn doHandshake(self: *Ssl) BoringError!void {
        const ssl = try self.raw();
        const result = sys.SSL_do_handshake(ssl);
        if (result > 0) return;
        _ = try ssl_result(ssl, result);
    }

    pub fn read(self: *Ssl, buf: []u8) BoringError!usize {
        const ssl = try self.raw();
        if (buf.len == 0) return 0;
        const len = try internal.c_int_len(buf.len);
        const result = sys.SSL_read(ssl, buf.ptr, len);
        if (result > 0) return @intCast(result);
        const checked = ssl_result(ssl, result) catch |err| {
            if (err == error.ZeroReturn) return 0;
            return err;
        };
        std.debug.assert(checked == 0);
        return 0;
    }

    pub fn write(self: *Ssl, buf: []const u8) BoringError!usize {
        const ssl = try self.raw();
        if (buf.len == 0) return 0;
        const len = try internal.c_int_len(buf.len);
        const result = sys.SSL_write(ssl, buf.ptr, len);
        if (result > 0) return @intCast(result);
        _ = try ssl_result(ssl, result);
        return error.WantWrite;
    }

    pub fn setFd(self: *Ssl, fd: c_int) BoringError!void {
        const ssl = try self.raw();
        try internal.require_one(sys.SSL_set_fd(ssl, fd));
    }

    pub fn setAcceptState(self: *Ssl) void {
        if (self.ptr) |ssl| sys.SSL_set_accept_state(ssl);
    }

    pub fn setConnectState(self: *Ssl) void {
        if (self.ptr) |ssl| sys.SSL_set_connect_state(ssl);
    }

    pub fn setBio(self: *Ssl, bio: *sys.BIO) void {
        if (self.ptr) |ssl| sys.SSL_set_bio(ssl, bio, bio);
    }

    pub fn setBioPair(self: *Ssl, pair: *BioPair) BoringError!void {
        const ssl = try self.raw();
        const rbio = pair.ssl_bio orelse return error.Closed;
        const wbio = pair.transport_bio orelse return error.Closed;
        sys.SSL_set_bio(ssl, rbio, wbio);
    }

    pub fn useCertificate(self: *Ssl, cert: *const x509_mod.X509) BoringError!void {
        const ssl = try self.raw();
        const raw_cert = try cert.asRef().raw();
        try internal.require_one(sys.SSL_use_certificate(ssl, raw_cert));
    }

    pub fn usePrivateKey(self: *Ssl, key: *const pkey_mod.PKey) BoringError!void {
        const ssl = try self.raw();
        const raw_key = try key.raw();
        try internal.require_one(sys.SSL_use_PrivateKey(ssl, raw_key));
    }

    pub fn add0ChainCert(self: *Ssl, cert: *const x509_mod.X509) BoringError!void {
        const ssl = try self.raw();
        const raw_cert = try cert.asRef().raw();
        try internal.require_one(sys.SSL_add0_chain_cert(ssl, raw_cert));
    }

    pub fn add1ChainCert(self: *Ssl, cert: *const x509_mod.X509) BoringError!void {
        const ssl = try self.raw();
        const raw_cert = try cert.asRef().raw();
        try internal.require_one(sys.SSL_add1_chain_cert(ssl, raw_cert));
    }

    pub fn setHostname(self: *Ssl, name: [:0]const u8) BoringError!void {
        const ssl = try self.raw();
        try internal.require_one(sys.SSL_set_tlsext_host_name(ssl, name.ptr));
    }

    pub fn setConnectHostname(self: *Ssl, host: [:0]const u8) BoringError!void {
        try internal.require_non_empty(host);

        if (!is_ip_address(host)) {
            try self.setHostname(host);
        }
        try self.setVerifyHostname(host);
    }

    pub fn setVerifyHostname(self: *Ssl, host: [:0]const u8) BoringError!void {
        try set_verify_hostname(try self.verifyParam(), host);
    }

    pub fn isHandshakeComplete(self: *const Ssl) bool {
        const ssl = self.ptr orelse return false;
        return sys.SSL_in_init(ssl) == 0;
    }

    pub fn selectedAlpn(self: *const Ssl) ?[]const u8 {
        const ssl = self.ptr orelse return null;
        return ssl_selected_alpn(ssl);
    }

    pub fn setSslContext(self: *Ssl, ctx: *const Context) BoringError!?Context {
        const ssl = try self.raw();
        const raw_ctx = ctx.ptr orelse return error.Closed;
        const old = sys.SSL_set_SSL_CTX(ssl, raw_ctx);
        if (old) |old_ctx| {
            return Context{ .ptr = old_ctx };
        }
        return null;
    }

    pub fn setSigningAlgorithmPrefs(
        self: *Ssl,
        prefs: []const SslSignatureAlgorithm,
    ) BoringError!void {
        const ssl = try self.raw();
        if (prefs.len == 0) return error.InvalidArgument;
        if (prefs.len > MaxSignatureAlgorithmPrefs) return error.InvalidArgument;
        var buf: [MaxSignatureAlgorithmPrefs]u16 = undefined;
        const encoded = try signature_algorithm_prefs(&buf, prefs);
        try internal.require_one(sys.SSL_set_signing_algorithm_prefs(
            ssl,
            encoded.ptr,
            encoded.len,
        ));
    }

    pub fn setVerifyAlgorithmPrefs(
        self: *Ssl,
        prefs: []const SslSignatureAlgorithm,
    ) BoringError!void {
        const ssl = try self.raw();
        if (prefs.len == 0) return error.InvalidArgument;
        if (prefs.len > MaxSignatureAlgorithmPrefs) return error.InvalidArgument;
        var buf: [MaxSignatureAlgorithmPrefs]u16 = undefined;
        const encoded = try signature_algorithm_prefs(&buf, prefs);
        try internal.require_one(sys.SSL_set_verify_algorithm_prefs(
            ssl,
            encoded.ptr,
            encoded.len,
        ));
    }

    pub fn setGroupsList(self: *Ssl, groups: [:0]const u8) BoringError!void {
        const ssl = try self.raw();
        try internal.require_non_empty(groups);
        try internal.require_one(sys.SSL_set1_groups_list(ssl, groups.ptr));
    }

    pub fn setCurvesList(self: *Ssl, curves: [:0]const u8) BoringError!void {
        return self.setGroupsList(curves);
    }

    pub fn setCustomVerifyCallback(
        self: *Ssl,
        mode: VerifyMode,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *SslRef) VerifyCallbackResult,
    ) BoringError!void {
        const ssl = try self.raw();
        const Bridge = ssl_custom_verify_callback_bridge(ContextType, callback);
        const index = try Bridge.index();
        try ssl_set_ex_data(ssl, ContextType, index, context);
        sys.SSL_set_custom_verify(ssl, mode.bits, Bridge.raw_callback);
    }

    pub fn setPrivateKeyMethodWithContext(
        self: *Ssl,
        comptime ContextType: type,
        context: *ContextType,
        comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
    ) BoringError!void {
        const ssl = try self.raw();
        const Bridge = ssl_private_key_method_bridge(ContextType, callbacks);
        const index = try Bridge.index();
        try ssl_set_ex_data(ssl, ContextType, index, context);
        sys.SSL_set_private_key_method(ssl, &Bridge.method);
    }

    pub fn setVerifyCallback(
        self: *Ssl,
        mode: VerifyMode,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, bool, *x509_store_context_mod.X509StoreContext) bool,
    ) BoringError!void {
        const ssl = try self.raw();
        const Bridge = ssl_verify_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try ssl_set_ex_data(ssl, ContextType, index, context);
        sys.SSL_set_verify(ssl, mode.bits, Bridge.raw_callback);
    }

    pub fn setEchConfigList(self: *Ssl, config_list: []const u8) BoringError!void {
        const ssl = try self.raw();
        try internal.require_one(sys.SSL_set1_ech_config_list(
            ssl,
            config_list.ptr,
            config_list.len,
        ));
    }

    pub fn setEnableEchGrease(self: *Ssl, enable: bool) void {
        const ssl = self.ptr orelse return;
        sys.SSL_set_enable_ech_grease(ssl, @intFromBool(enable));
    }

    pub fn verifyParam(self: *Ssl) BoringError!*sys.X509_VERIFY_PARAM {
        const ssl = try self.raw();
        const param = sys.SSL_get0_param(ssl) orelse return error.BoringSSL;
        return param;
    }

    pub fn shutdown(self: *Ssl) BoringError!ShutdownResult {
        const ssl = try self.raw();
        const result = sys.SSL_shutdown(ssl);
        if (result == 0) return .sent;
        if (result == 1) return .received;
        _ = try ssl_result(ssl, result);
        return error.BoringSSL;
    }

    pub fn setMtu(self: *Ssl, mtu: u16) BoringError!void {
        const ssl = try self.raw();
        try internal.require_one(sys.SSL_set_mtu(ssl, mtu));
    }

    pub fn setSrtpProfiles(self: *Ssl, profiles: [:0]const u8) BoringError!void {
        const ssl = try self.raw();
        try internal.require_non_empty(profiles);
        try internal.require_zero(sys.SSL_set_tlsext_use_srtp(ssl, profiles));
    }

    pub fn setMinProtoVersion(self: *Ssl, version: SslVersion) BoringError!void {
        const ssl = try self.raw();
        try internal.require_one(sys.SSL_set_min_proto_version(ssl, version.raw()));
    }

    pub fn setMaxProtoVersion(self: *Ssl, version: SslVersion) BoringError!void {
        const ssl = try self.raw();
        try internal.require_one(sys.SSL_set_max_proto_version(ssl, version.raw()));
    }

    pub fn setCompliancePolicy(self: *Ssl, policy: CompliancePolicy) BoringError!void {
        const ssl = try self.raw();
        try internal.require_one(sys.SSL_set_compliance_policy(ssl, policy.raw()));
    }

    pub fn session(self: *const Ssl) ?SslSession {
        const ssl = self.ptr orelse return null;
        const raw_session = sys.SSL_get1_session(ssl) orelse return null;
        return SslSession.fromRawOwned(raw_session);
    }

    pub fn setSession(self: *Ssl, sess: *const SslSessionRef) BoringError!void {
        const ssl = try self.raw();
        try internal.require_one(sys.SSL_set_session(ssl, sess.ptr));
    }
};

pub const MaxAlpnWireBytes: u32 = 4096;
pub const MaxBioPairCapacityBytes: u32 = 1024 * 1024;
pub const MaxClientHelloBytes: u32 = 128 * 1024;
pub const MaxClientHelloExtensionBytes: u32 = 64 * 1024;
pub const MaxPrivateKeyOperationBytes: u32 = 16 * 1024;
pub const MaxPskBytes: u32 = @intCast(sys.PSK_MAX_PSK_LEN);
pub const MaxPskIdentityBytes: u32 = @intCast(sys.PSK_MAX_IDENTITY_LEN);
pub const MaxSignatureAlgorithmPrefs: u32 = 64;
pub const MaxSingleAlpnProtocolBytes: u8 = 255;
pub const MaxCipherListEntries: u32 = 4096;
pub const MaxSessionIdBytes: u32 = 32;
pub const MaxSessionBytes: u32 = 64 * 1024;
pub const MaxSessionCacheEntries: u32 = 1024;

pub const PrivateKeyResult = enum(c_uint) {
    success = @intCast(sys.ssl_private_key_success),
    retry = @intCast(sys.ssl_private_key_retry),
    failure = @intCast(sys.ssl_private_key_failure),
};

pub const PrivateKeyCallbackResult = union(enum) {
    success: usize,
    retry,
    failure,
};

pub const SslSignatureAlgorithm = struct {
    value: u16,

    pub const rsaPkcs1Sha1: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_RSA_PKCS1_SHA1),
    };
    pub const rsaPkcs1Sha256: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_RSA_PKCS1_SHA256),
    };
    pub const rsaPkcs1Sha384: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_RSA_PKCS1_SHA384),
    };
    pub const rsaPkcs1Sha512: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_RSA_PKCS1_SHA512),
    };
    pub const rsaPkcs1Md5Sha1: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_RSA_PKCS1_MD5_SHA1),
    };
    pub const ecdsaSha1: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_ECDSA_SHA1),
    };
    pub const ecdsaSecp256r1Sha256: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_ECDSA_SECP256R1_SHA256),
    };
    pub const ecdsaSecp384r1Sha384: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_ECDSA_SECP384R1_SHA384),
    };
    pub const ecdsaSecp521r1Sha512: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_ECDSA_SECP521R1_SHA512),
    };
    pub const rsaPssRsaeSha256: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_RSA_PSS_RSAE_SHA256),
    };
    pub const rsaPssRsaeSha384: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_RSA_PSS_RSAE_SHA384),
    };
    pub const rsaPssRsaeSha512: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_RSA_PSS_RSAE_SHA512),
    };
    pub const ed25519: SslSignatureAlgorithm = .{
        .value = @intCast(sys.SSL_SIGN_ED25519),
    };

    pub fn fromRaw(value: u16) SslSignatureAlgorithm {
        return .{ .value = value };
    }

    pub fn raw(self: SslSignatureAlgorithm) u16 {
        return self.value;
    }
};

pub const SelectCertificateResult = enum(c_int) {
    retry = sys.ssl_select_cert_retry,
    success = sys.ssl_select_cert_success,
    failure = sys.ssl_select_cert_error,
    disableEch = sys.ssl_select_cert_disable_ech,
};

pub const ServerNameCallbackResult = union(enum) {
    ok,
    noAck,
    alertFatal: SslAlert,
    alertWarning: SslAlert,
};

pub const AlpnSelectResult = union(enum) {
    selected: []const u8,
    noAck,
    alertFatal,
};

pub const VerifyResult = enum(c_uint) {
    ok = @intCast(sys.ssl_verify_ok),
    invalid = @intCast(sys.ssl_verify_invalid),
    retry = @intCast(sys.ssl_verify_retry),
};

pub const VerifyCallbackResult = union(enum) {
    ok,
    retry,
    invalid: SslAlert,
};

pub const SslAlert = enum(u8) {
    closeNotify = @intCast(sys.SSL_AD_CLOSE_NOTIFY),
    unexpectedMessage = @intCast(sys.SSL_AD_UNEXPECTED_MESSAGE),
    badRecordMac = @intCast(sys.SSL_AD_BAD_RECORD_MAC),
    decryptionFailed = @intCast(sys.SSL_AD_DECRYPTION_FAILED),
    recordOverflow = @intCast(sys.SSL_AD_RECORD_OVERFLOW),
    decompressionFailure = @intCast(sys.SSL_AD_DECOMPRESSION_FAILURE),
    handshakeFailure = @intCast(sys.SSL_AD_HANDSHAKE_FAILURE),
    noCertificate = @intCast(sys.SSL_AD_NO_CERTIFICATE),
    badCertificate = @intCast(sys.SSL_AD_BAD_CERTIFICATE),
    unsupportedCertificate = @intCast(sys.SSL_AD_UNSUPPORTED_CERTIFICATE),
    certificateRevoked = @intCast(sys.SSL_AD_CERTIFICATE_REVOKED),
    certificateExpired = @intCast(sys.SSL_AD_CERTIFICATE_EXPIRED),
    certificateUnknown = @intCast(sys.SSL_AD_CERTIFICATE_UNKNOWN),
    illegalParameter = @intCast(sys.SSL_AD_ILLEGAL_PARAMETER),
    unknownCa = @intCast(sys.SSL_AD_UNKNOWN_CA),
    accessDenied = @intCast(sys.SSL_AD_ACCESS_DENIED),
    decodeError = @intCast(sys.SSL_AD_DECODE_ERROR),
    decryptError = @intCast(sys.SSL_AD_DECRYPT_ERROR),
    exportRestriction = @intCast(sys.SSL_AD_EXPORT_RESTRICTION),
    protocolVersion = @intCast(sys.SSL_AD_PROTOCOL_VERSION),
    insufficientSecurity = @intCast(sys.SSL_AD_INSUFFICIENT_SECURITY),
    internalError = @intCast(sys.SSL_AD_INTERNAL_ERROR),
    inappropriateFallback = @intCast(sys.SSL_AD_INAPPROPRIATE_FALLBACK),
    userCancelled = @intCast(sys.SSL_AD_USER_CANCELLED),
    noRenegotiation = @intCast(sys.SSL_AD_NO_RENEGOTIATION),
    missingExtension = @intCast(sys.SSL_AD_MISSING_EXTENSION),
    unsupportedExtension = @intCast(sys.SSL_AD_UNSUPPORTED_EXTENSION),
    certificateUnobtainable = @intCast(sys.SSL_AD_CERTIFICATE_UNOBTAINABLE),
    unrecognizedName = @intCast(sys.SSL_AD_UNRECOGNIZED_NAME),
    badCertificateStatusResponse = @intCast(sys.SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE),
    badCertificateHashValue = @intCast(sys.SSL_AD_BAD_CERTIFICATE_HASH_VALUE),
    unknownPskIdentity = @intCast(sys.SSL_AD_UNKNOWN_PSK_IDENTITY),
    certificateRequired = @intCast(sys.SSL_AD_CERTIFICATE_REQUIRED),
    noApplicationProtocol = @intCast(sys.SSL_AD_NO_APPLICATION_PROTOCOL),
    echRequired = @intCast(sys.SSL_AD_ECH_REQUIRED),

    pub fn raw(self: SslAlert) u8 {
        return @intFromEnum(self);
    }
};

pub const ExtensionType = struct {
    value: u16,

    pub const serverName: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_server_name),
    };
    pub const statusRequest: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_status_request),
    };
    pub const ecPointFormats: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_ec_point_formats),
    };
    pub const signatureAlgorithms: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_signature_algorithms),
    };
    pub const srtp: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_srtp),
    };
    pub const applicationLayerProtocolNegotiation: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_application_layer_protocol_negotiation),
    };
    pub const padding: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_padding),
    };
    pub const extendedMasterSecret: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_extended_master_secret),
    };
    pub const quicTransportParametersLegacy: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_quic_transport_parameters_legacy),
    };
    pub const quicTransportParameters: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_quic_transport_parameters),
    };
    pub const certCompression: ExtensionType = .{
        .value = @intCast(sys.TLSEXT_TYPE_cert_compression),
    };

    pub fn raw(self: ExtensionType) u16 {
        return self.value;
    }
};

pub const CertificateCompressionAlgorithm = struct {
    value: u16,

    pub fn fromRaw(value: u16) CertificateCompressionAlgorithm {
        return .{ .value = value };
    }

    pub fn raw(self: CertificateCompressionAlgorithm) u16 {
        return self.value;
    }
};

pub const CertificateCompressionWriter = struct {
    ptr: *sys.CBB,

    pub fn writeAll(self: *CertificateCompressionWriter, bytes: []const u8) BoringError!void {
        if (bytes.len == 0) return;
        try internal.require_one(sys.CBB_add_bytes(self.ptr, bytes.ptr, bytes.len));
    }

    pub fn writeByte(self: *CertificateCompressionWriter, byte: u8) BoringError!void {
        const bytes: [1]u8 = .{byte};
        try self.writeAll(&bytes);
    }
};

pub fn CertificateCompressionCallbacks(comptime ContextType: type) type {
    return struct {
        compress: ?fn (
            *ContextType,
            *SslRef,
            []const u8,
            *CertificateCompressionWriter,
        ) BoringError!void = null,
        decompress: ?fn (
            *ContextType,
            *SslRef,
            []const u8,
            []u8,
        ) BoringError!void = null,
    };
}

pub const NameType = struct {
    value: c_int,

    pub const hostName: NameType = .{
        .value = sys.TLSEXT_NAMETYPE_host_name,
    };

    pub fn raw(self: NameType) c_int {
        return self.value;
    }
};

pub const GetSessionResult = union(enum) {
    none,
    retry,
    session: SslSession,
};

pub fn PrivateKeyMethodCallbacks(comptime ContextType: type) type {
    return struct {
        sign: fn (
            *ContextType,
            *SslRef,
            []const u8,
            SslSignatureAlgorithm,
            []u8,
        ) PrivateKeyCallbackResult,
        decrypt: fn (
            *ContextType,
            *SslRef,
            []const u8,
            []u8,
        ) PrivateKeyCallbackResult,
        complete: fn (
            *ContextType,
            *SslRef,
            []u8,
        ) PrivateKeyCallbackResult,
    };
}

pub fn selectAlpnProtocol(protocols_wire: []const u8, protocol: []const u8) ?[]const u8 {
    if (protocols_wire.len > MaxAlpnWireBytes) return null;
    if (protocol.len == 0) return null;
    if (protocol.len > MaxSingleAlpnProtocolBytes) return null;

    return select_alpn(protocols_wire, protocol);
}

pub const PrivateKeyMethod = struct {
    method: sys.SSL_PRIVATE_KEY_METHOD,

    pub fn init(
        sign_fn: ?*const fn (
            ssl: ?*sys.SSL,
            out: [*c]u8,
            out_len: [*c]usize,
            max_out: usize,
            signature_algorithm: u16,
            in: [*c]const u8,
            in_len: usize,
        ) callconv(.c) sys.enum_ssl_private_key_result_t,
        decrypt_fn: ?*const fn (
            ssl: ?*sys.SSL,
            out: [*c]u8,
            out_len: [*c]usize,
            max_out: usize,
            in: [*c]const u8,
            in_len: usize,
        ) callconv(.c) sys.enum_ssl_private_key_result_t,
        complete_fn: ?*const fn (
            ssl: ?*sys.SSL,
            out: [*c]u8,
            out_len: [*c]usize,
            max_out: usize,
        ) callconv(.c) sys.enum_ssl_private_key_result_t,
    ) PrivateKeyMethod {
        return .{
            .method = .{
                .sign = sign_fn,
                .decrypt = decrypt_fn,
                .complete = complete_fn,
            },
        };
    }

    pub fn raw(self: *const PrivateKeyMethod) *const sys.SSL_PRIVATE_KEY_METHOD {
        return &self.method;
    }
};

pub const SessionCacheMode = struct {
    bits: c_int,

    pub const off = SessionCacheMode{ .bits = sys.SSL_SESS_CACHE_OFF };
    pub const client = SessionCacheMode{ .bits = sys.SSL_SESS_CACHE_CLIENT };
    pub const server = SessionCacheMode{ .bits = sys.SSL_SESS_CACHE_SERVER };
    pub const both = SessionCacheMode{ .bits = sys.SSL_SESS_CACHE_BOTH };
    pub const noAutoClear = SessionCacheMode{ .bits = sys.SSL_SESS_CACHE_NO_AUTO_CLEAR };
    pub const noInternal = SessionCacheMode{ .bits = sys.SSL_SESS_CACHE_NO_INTERNAL };

    pub fn combine(self: SessionCacheMode, other: SessionCacheMode) SessionCacheMode {
        return .{ .bits = self.bits | other.bits };
    }
};

pub const SslSession = struct {
    ptr: ?*sys.SSL_SESSION,

    pub fn fromRawOwned(ptr: *sys.SSL_SESSION) SslSession {
        return .{ .ptr = ptr };
    }

    pub fn fromBytes(bytes: []const u8, ctx: *const Context) BoringError!SslSession {
        const session = sys.SSL_SESSION_from_bytes(
            bytes.ptr,
            bytes.len,
            ctx.ptr orelse return error.Closed,
        ) orelse return error.BoringSSL;

        return .{ .ptr = session };
    }

    pub fn fromBytesWithRef(bytes: []const u8, ctx: ContextRef) BoringError!SslSession {
        const session = sys.SSL_SESSION_from_bytes(
            bytes.ptr,
            bytes.len,
            ctx.raw(),
        ) orelse return error.BoringSSL;

        return .{ .ptr = session };
    }

    pub fn fromDer(bytes: []const u8) BoringError!SslSession {
        var ptr: [*c]const u8 = bytes.ptr;
        const session = sys.d2i_SSL_SESSION(
            null,
            &ptr,
            @intCast(bytes.len),
        ) orelse return error.BoringSSL;

        return .{ .ptr = session };
    }

    pub fn deinit(self: *SslSession) void {
        if (self.ptr) |session| {
            sys.SSL_SESSION_free(session);
            self.ptr = null;
        }
    }

    pub fn raw(self: *const SslSession) BoringError!*sys.SSL_SESSION {
        return self.ptr orelse error.Closed;
    }

    pub fn intoRaw(self: *SslSession) BoringError!*sys.SSL_SESSION {
        const session = try self.raw();
        self.ptr = null;

        return session;
    }

    pub fn toBytes(self: *const SslSession) BoringError![]const u8 {
        const session = try self.raw();
        var out_data: [*c]u8 = null;
        var out_len: usize = 0;
        try internal.require_one(sys.SSL_SESSION_to_bytes(session, &out_data, &out_len));
        if (out_data == null) return error.BoringSSL;
        if (out_len > MaxSessionBytes) {
            sys.OPENSSL_free(out_data);
            return error.Overflow;
        }

        return @as([*]u8, @ptrCast(out_data))[0..out_len];
    }

    pub fn clone(self: *const SslSession) BoringError!SslSession {
        const session = try self.raw();
        try internal.require_one(sys.SSL_SESSION_up_ref(session));

        return .{ .ptr = session };
    }

    pub fn asRef(self: *const SslSession) BoringError!SslSessionRef {
        return SslSessionRef.fromRaw(try self.raw());
    }

    pub fn masterKeyLength(self: *const SslSession) usize {
        const session = self.ptr orelse return 0;
        return sys.SSL_SESSION_get_master_key(session, null, 0);
    }

    pub fn protocolVersion(self: *const SslSession) u16 {
        const session = self.ptr orelse return 0;

        return sys.SSL_SESSION_get_protocol_version(session);
    }
};

pub const SslSessionRef = struct {
    ptr: *sys.SSL_SESSION,

    pub fn fromRaw(ptr: *sys.SSL_SESSION) SslSessionRef {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: *const SslSessionRef) *sys.SSL_SESSION {
        return self.ptr;
    }

    pub fn clone(self: *const SslSessionRef) BoringError!SslSession {
        try internal.require_one(sys.SSL_SESSION_up_ref(self.ptr));

        return SslSession.fromRawOwned(self.ptr);
    }

    pub fn protocolVersion(self: *const SslSessionRef) u16 {
        return sys.SSL_SESSION_get_protocol_version(self.ptr);
    }

    pub fn masterKey(self: *const SslSessionRef, out: []u8) usize {
        return sys.SSL_SESSION_get_master_key(self.ptr, out.ptr, out.len);
    }

    pub fn masterKeyLength(self: *const SslSessionRef) usize {
        return sys.SSL_SESSION_get_master_key(self.ptr, null, 0);
    }

    pub fn sessionId(self: *const SslSessionRef) []const u8 {
        var len: c_uint = 0;
        const id = sys.SSL_SESSION_get_id(self.ptr, &len);
        if (len == 0) return &[_]u8{};
        const id_ptr = id orelse return &[_]u8{};
        return id_ptr[0..len];
    }
};

pub const CipherBits = struct {
    secret: i32,
    algorithm: i32,
};

pub const SslCipherRef = struct {
    ptr: *sys.SSL_CIPHER,

    pub fn fromRaw(ptr: *sys.SSL_CIPHER) SslCipherRef {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: *const SslCipherRef) *sys.SSL_CIPHER {
        return self.ptr;
    }

    pub fn protocolId(self: *const SslCipherRef) u16 {
        return sys.SSL_CIPHER_get_protocol_id(self.ptr);
    }

    pub fn name(self: *const SslCipherRef) [:0]const u8 {
        return std.mem.span(sys.SSL_CIPHER_get_name(self.ptr));
    }

    pub fn standardName(self: *const SslCipherRef) ?[:0]const u8 {
        const ptr = sys.SSL_CIPHER_standard_name(self.ptr) orelse return null;

        return std.mem.span(ptr);
    }

    pub fn version(self: *const SslCipherRef) [:0]const u8 {
        return std.mem.span(sys.SSL_CIPHER_get_version(self.ptr));
    }

    pub fn bits(self: *const SslCipherRef) CipherBits {
        var algo_bits: c_int = 0;
        const secret_bits = sys.SSL_CIPHER_get_bits(self.ptr, &algo_bits);

        return .{
            .secret = secret_bits,
            .algorithm = algo_bits,
        };
    }

    pub fn isAead(self: *const SslCipherRef) bool {
        return sys.SSL_CIPHER_is_aead(self.ptr) != 0;
    }
};

pub const SslCipher = struct {
    ptr: *const sys.SSL_CIPHER,

    pub fn fromValue(value: u16) ?SslCipher {
        const ptr = sys.SSL_get_cipher_by_value(value) orelse return null;

        return .{ .ptr = ptr };
    }

    pub fn fromRaw(ptr: *const sys.SSL_CIPHER) SslCipher {
        return .{ .ptr = ptr };
    }

    pub fn raw(self: *const SslCipher) *const sys.SSL_CIPHER {
        return self.ptr;
    }

    pub fn asRef(self: *const SslCipher) SslCipherRef {
        return SslCipherRef.fromRaw(@constCast(self.ptr));
    }
};

pub const SslCipherList = struct {
    ptr: *const sys.struct_stack_st_SSL_CIPHER,

    pub fn len(self: SslCipherList) usize {
        const count = sys.sk_SSL_CIPHER_num(self.ptr);
        if (count > MaxCipherListEntries) return MaxCipherListEntries;

        return count;
    }

    pub fn get(self: SslCipherList, index: usize) ?SslCipher {
        const count = self.len();
        if (index >= count) return null;

        const cipher = sys.sk_SSL_CIPHER_value(self.ptr, index) orelse return null;

        return SslCipher.fromRaw(cipher);
    }
};

pub const SrtpProfileList = struct {
    ptr: *const sys.struct_stack_st_SRTP_PROTECTION_PROFILE,

    pub fn len(self: SrtpProfileList) usize {
        const count = sys.sk_SRTP_PROTECTION_PROFILE_num(self.ptr);
        if (count < 0) return 0;
        return @intCast(count);
    }

    pub fn get(self: SrtpProfileList, index: usize) ?srtp_mod.SrtpProtectionProfile {
        const count = self.len();
        if (index >= count) return null;
        const profile = sys.sk_SRTP_PROTECTION_PROFILE_value(self.ptr, index);
        if (profile == null) return null;
        return srtp_mod.SrtpProtectionProfile.fromRaw(profile);
    }
};

pub const Method = struct {
    ptr: *const sys.SSL_METHOD,

    pub fn tls() Method {
        return .{ .ptr = sys.TLS_method() orelse unreachable };
    }

    pub fn dtls() Method {
        return .{ .ptr = sys.DTLS_method() orelse unreachable };
    }
};

pub const FileType = enum(c_int) {
    pem = sys.SSL_FILETYPE_PEM,
    asn1 = sys.SSL_FILETYPE_ASN1,

    pub fn raw(self: FileType) c_int {
        return @intFromEnum(self);
    }
};

pub const VerifyMode = struct {
    bits: c_int,

    pub const none: VerifyMode = .{ .bits = sys.SSL_VERIFY_NONE };
    pub const peer: VerifyMode = .{ .bits = sys.SSL_VERIFY_PEER };
    pub const failIfNoPeerCert: VerifyMode = .{
        .bits = sys.SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    };

    pub fn combine(self: VerifyMode, other: VerifyMode) VerifyMode {
        return .{ .bits = self.bits | other.bits };
    }
};

pub const Options = struct {
    bits: u32,

    pub const none: Options = .{ .bits = 0 };
    pub const noQueryMtu: Options = .{ .bits = @intCast(sys.SSL_OP_NO_QUERY_MTU) };
    pub const noTicket: Options = .{ .bits = @intCast(sys.SSL_OP_NO_TICKET) };
    pub const cipherServerPreference: Options = .{
        .bits = @intCast(sys.SSL_OP_CIPHER_SERVER_PREFERENCE),
    };
    pub const noTlsV1: Options = .{ .bits = @intCast(sys.SSL_OP_NO_TLSv1) };
    pub const noTlsV1_1: Options = .{ .bits = @intCast(sys.SSL_OP_NO_TLSv1_1) };
    pub const noTlsV1_2: Options = .{ .bits = @intCast(sys.SSL_OP_NO_TLSv1_2) };
    pub const noTlsV1_3: Options = .{ .bits = @intCast(sys.SSL_OP_NO_TLSv1_3) };
    pub const noDtlsV1: Options = .{ .bits = @intCast(sys.SSL_OP_NO_DTLSv1) };
    pub const noDtlsV1_2: Options = .{ .bits = @intCast(sys.SSL_OP_NO_DTLSv1_2) };

    pub fn combine(self: Options, other: Options) Options {
        return .{ .bits = self.bits | other.bits };
    }

    pub fn raw(self: Options) u32 {
        return self.bits;
    }
};

pub const Mode = struct {
    bits: u32,

    pub const none: Mode = .{ .bits = 0 };
    pub const enablePartialWrite: Mode = .{
        .bits = @intCast(sys.SSL_MODE_ENABLE_PARTIAL_WRITE),
    };
    pub const acceptMovingWriteBuffer: Mode = .{
        .bits = @intCast(sys.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER),
    };
    pub const noAutoChain: Mode = .{ .bits = @intCast(sys.SSL_MODE_NO_AUTO_CHAIN) };
    pub const enableFalseStart: Mode = .{
        .bits = @intCast(sys.SSL_MODE_ENABLE_FALSE_START),
    };
    pub const cbcRecordSplitting: Mode = .{
        .bits = @intCast(sys.SSL_MODE_CBC_RECORD_SPLITTING),
    };
    pub const noSessionCreation: Mode = .{
        .bits = @intCast(sys.SSL_MODE_NO_SESSION_CREATION),
    };
    pub const sendFallbackScsv: Mode = .{
        .bits = @intCast(sys.SSL_MODE_SEND_FALLBACK_SCSV),
    };

    pub fn combine(self: Mode, other: Mode) Mode {
        return .{ .bits = self.bits | other.bits };
    }

    pub fn raw(self: Mode) u32 {
        return self.bits;
    }
};

pub const SslInfoCallbackMode = struct {
    value: c_int,

    pub const readAlert = SslInfoCallbackMode{ .value = sys.SSL_CB_READ_ALERT };
    pub const writeAlert = SslInfoCallbackMode{ .value = sys.SSL_CB_WRITE_ALERT };
    pub const handshakeStart = SslInfoCallbackMode{ .value = sys.SSL_CB_HANDSHAKE_START };
    pub const handshakeDone = SslInfoCallbackMode{ .value = sys.SSL_CB_HANDSHAKE_DONE };
    pub const acceptLoop = SslInfoCallbackMode{ .value = sys.SSL_CB_ACCEPT_LOOP };
    pub const acceptExit = SslInfoCallbackMode{ .value = sys.SSL_CB_ACCEPT_EXIT };
    pub const connectExit = SslInfoCallbackMode{ .value = sys.SSL_CB_CONNECT_EXIT };

    pub fn fromRaw(value: c_int) SslInfoCallbackMode {
        return .{ .value = value };
    }

    pub fn raw(self: SslInfoCallbackMode) c_int {
        return self.value;
    }
};

pub const TicketKeyCallbackResult = enum(c_int) {
    failure = -1,
    noop = 0,
    success = 1,
    decryptSuccessRenew = 2,
};

fn TicketKeyCallback(comptime ContextType: type) type {
    return fn (
        *ContextType,
        *SslRef,
        *[@intCast(sys.SSL_TICKET_KEY_NAME_LEN)]u8,
        *[@intCast(sys.EVP_MAX_IV_LENGTH)]u8,
        *symm_mod.CipherCtxRef,
        *hmac_mod.HmacCtxRef,
        bool,
    ) TicketKeyCallbackResult;
}

pub const TicketKeyNameLength = 16;
pub const TicketKeyIvLength = 16;

comptime {
    std.debug.assert(TicketKeyNameLength == sys.SSL_TICKET_KEY_NAME_LEN);
    std.debug.assert(TicketKeyIvLength == sys.EVP_MAX_IV_LENGTH);
}

pub const ShutdownResult = enum(c_int) {
    received = 0,
    sent = 1,
};

pub const ShutdownState = struct {
    bits: c_int,

    pub const none: ShutdownState = .{ .bits = 0 };
    pub const sent: ShutdownState = .{ .bits = sys.SSL_SENT_SHUTDOWN };
    pub const received: ShutdownState = .{ .bits = sys.SSL_RECEIVED_SHUTDOWN };

    pub fn combine(self: ShutdownState, other: ShutdownState) ShutdownState {
        return .{ .bits = self.bits | other.bits };
    }

    pub fn contains(self: ShutdownState, other: ShutdownState) bool {
        return (self.bits & other.bits) == other.bits;
    }
};

pub const SslVersion = struct {
    value: u16,

    pub const tlsV1 = SslVersion{ .value = sys.TLS1_VERSION };
    pub const tlsV1_1 = SslVersion{ .value = sys.TLS1_1_VERSION };
    pub const tlsV1_2 = SslVersion{ .value = sys.TLS1_2_VERSION };
    pub const tlsV1_3 = SslVersion{ .value = sys.TLS1_3_VERSION };
    pub const dtlsV1 = SslVersion{ .value = sys.DTLS1_VERSION };
    pub const dtlsV1_2 = SslVersion{ .value = sys.DTLS1_2_VERSION };

    pub fn fromRaw(value: u16) SslVersion {
        return .{ .value = value };
    }

    pub fn raw(self: SslVersion) u16 {
        return self.value;
    }
};

pub const CompliancePolicy = struct {
    value: sys.ssl_compliance_policy_t,

    pub const none = CompliancePolicy{
        .value = @intCast(sys.ssl_compliance_policy_none),
    };
    pub const fips202205 = CompliancePolicy{
        .value = @intCast(sys.ssl_compliance_policy_fips_202205),
    };
    pub const wpa3192202304 = CompliancePolicy{
        .value = @intCast(sys.ssl_compliance_policy_wpa3_192_202304),
    };

    pub fn raw(self: CompliancePolicy) sys.ssl_compliance_policy_t {
        return self.value;
    }
};

pub const StatusType = struct {
    value: c_int,

    pub const ocsp = StatusType{ .value = sys.TLSEXT_STATUSTYPE_ocsp };

    pub fn fromRaw(value: c_int) StatusType {
        return .{ .value = value };
    }

    pub fn raw(self: StatusType) c_int {
        return self.value;
    }
};

pub const ContextBuilder = struct {
    ptr: ?*sys.SSL_CTX,

    pub fn init(method: Method) BoringError!ContextBuilder {
        const ctx = sys.SSL_CTX_new(method.ptr) orelse return error.BoringSSL;
        return .{ .ptr = ctx };
    }

    pub fn deinit(self: *ContextBuilder) void {
        if (self.ptr) |ctx| {
            sys.SSL_CTX_free(ctx);
            self.ptr = null;
        }
    }

    pub fn build(self: *ContextBuilder) Context {
        const ctx = self.ptr orelse unreachable;
        self.ptr = null;

        return .{ .ptr = ctx };
    }

    pub fn newExIndex(comptime Data: type) BoringError!ex_data_mod.Index(Context, Data) {
        return context_ex_new_index(Data);
    }

    pub fn setExData(
        self: *ContextBuilder,
        comptime Data: type,
        index: ex_data_mod.Index(Context, Data),
        data: ?*Data,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        return context_set_ex_data(ctx, Data, index, data);
    }

    pub fn exData(
        self: *const ContextBuilder,
        comptime Data: type,
        index: ex_data_mod.Index(Context, Data),
    ) ?*Data {
        const ctx = self.ptr orelse return null;
        return context_ex_data(ctx, Data, index);
    }

    pub fn replaceExData(
        self: *ContextBuilder,
        comptime Data: type,
        index: ex_data_mod.Index(Context, Data),
        data: ?*Data,
    ) ?*Data {
        const ctx = self.ptr orelse return null;
        const old = context_ex_data(ctx, Data, index);
        context_set_ex_data(ctx, Data, index, data) catch return null;
        return old;
    }

    pub fn setCertStore(
        self: *ContextBuilder,
        store: *x509_store_mod.X509Store,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const raw_store = try store.raw();
        try internal.require_one(sys.X509_STORE_up_ref(raw_store));
        sys.SSL_CTX_set_cert_store(ctx, raw_store);
    }

    pub fn setEchKeys(self: *ContextBuilder, keys: *const ech_mod.EchKeys) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_one(sys.SSL_CTX_set1_ech_keys(ctx, try keys.raw()));
    }

    pub fn setClientCaList(
        self: *ContextBuilder,
        names: *x509_mod.X509NameStack,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        sys.SSL_CTX_set_client_CA_list(ctx, try names.intoRaw());
    }

    pub fn setDefaultVerifyPaths(self: *ContextBuilder) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_one(sys.SSL_CTX_set_default_verify_paths(ctx));
    }

    pub fn setCaFile(self: *ContextBuilder, ca_file: [:0]const u8) BoringError!void {
        try self.loadVerifyLocations(ca_file, null);
    }

    pub fn loadVerifyLocations(
        self: *ContextBuilder,
        ca_file: ?[:0]const u8,
        ca_dir: ?[:0]const u8,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;

        if (ca_file) |file| {
            try internal.require_non_empty(file);
        } else {
            if (ca_dir == null) return error.InvalidArgument;
        }

        if (ca_dir) |dir| {
            try internal.require_non_empty(dir);
        }

        const ca_file_ptr = if (ca_file) |file| file.ptr else null;
        const ca_dir_ptr = if (ca_dir) |dir| dir.ptr else null;
        try internal.require_one(
            sys.SSL_CTX_load_verify_locations(ctx, ca_file_ptr, ca_dir_ptr),
        );
    }

    pub fn ciphers(self: *const ContextBuilder) BoringError!SslCipherList {
        const ctx = self.ptr orelse return error.Closed;
        const ciphers_list = sys.SSL_CTX_get_ciphers(ctx) orelse return error.BoringSSL;

        return .{ .ptr = ciphers_list };
    }

    pub fn setCipherList(
        self: *ContextBuilder,
        cipher_list: [:0]const u8,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        return internal.require_one(sys.SSL_CTX_set_cipher_list(ctx, cipher_list.ptr));
    }

    pub fn setCertificateFile(
        self: *ContextBuilder,
        path: [:0]const u8,
        file_type: FileType,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        return internal.require_one(
            sys.SSL_CTX_use_certificate_file(ctx, path.ptr, file_type.raw()),
        );
    }

    pub fn setCertificateChainFile(
        self: *ContextBuilder,
        path: [:0]const u8,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        return internal.require_one(sys.SSL_CTX_use_certificate_chain_file(ctx, path.ptr));
    }

    pub fn setPrivateKeyFile(
        self: *ContextBuilder,
        path: [:0]const u8,
        file_type: FileType,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        return internal.require_one(
            sys.SSL_CTX_use_PrivateKey_file(ctx, path.ptr, file_type.raw()),
        );
    }

    pub fn checkPrivateKey(self: *ContextBuilder) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        return internal.require_one(sys.SSL_CTX_check_private_key(ctx));
    }

    pub fn setVerify(self: *ContextBuilder, mode: VerifyMode) void {
        const ctx = self.ptr orelse unreachable;
        sys.SSL_CTX_set_verify(ctx, mode.bits, null);
    }

    pub fn setVerifyDepth(self: *ContextBuilder, depth: u31) void {
        const ctx = self.ptr orelse unreachable;
        sys.SSL_CTX_set_verify_depth(ctx, depth);
    }

    pub fn setVerifyCallback(
        self: *ContextBuilder,
        mode: VerifyMode,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, bool, *x509_store_context_mod.X509StoreContext) bool,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = verify_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_set_verify(ctx, mode.bits, Bridge.raw_callback);
    }

    pub fn setCertVerifyCallback(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *x509_store_context_mod.X509StoreContext) bool,
    ) void {
        const ctx = self.ptr orelse return;
        const Bridge = cert_verify_callback_bridge(ContextType, callback);
        sys.SSL_CTX_set_cert_verify_callback(ctx, Bridge.raw_callback, context);
    }

    pub fn setOptions(self: *ContextBuilder, options: Options) u32 {
        const ctx = self.ptr orelse unreachable;
        return sys.SSL_CTX_set_options(ctx, options.raw());
    }

    pub fn getOptions(self: *const ContextBuilder) u32 {
        const ctx = self.ptr orelse return 0;
        return sys.SSL_CTX_get_options(ctx);
    }

    pub fn clearOptions(self: *ContextBuilder, options: Options) u32 {
        const ctx = self.ptr orelse unreachable;
        return sys.SSL_CTX_clear_options(ctx, options.raw());
    }

    pub fn setMode(self: *ContextBuilder, mode: Mode) u32 {
        const ctx = self.ptr orelse unreachable;
        return sys.SSL_CTX_set_mode(ctx, mode.raw());
    }

    pub fn getMode(self: *const ContextBuilder) u32 {
        const ctx = self.ptr orelse return 0;
        return sys.SSL_CTX_get_mode(ctx);
    }

    pub fn setMinProtoVersion(
        self: *ContextBuilder,
        version: ?SslVersion,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const raw: u16 = if (version) |v| v.raw() else 0;
        try internal.require_one(sys.SSL_CTX_set_min_proto_version(ctx, raw));
    }

    pub fn setMaxProtoVersion(
        self: *ContextBuilder,
        version: ?SslVersion,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const raw: u16 = if (version) |v| v.raw() else 0;
        try internal.require_one(sys.SSL_CTX_set_max_proto_version(ctx, raw));
    }

    pub fn getMinProtoVersion(self: *const ContextBuilder) ?SslVersion {
        const ctx = self.ptr orelse return null;
        const result = sys.SSL_CTX_get_min_proto_version(ctx);
        if (result == 0) return null;
        return SslVersion.fromRaw(result);
    }

    pub fn getMaxProtoVersion(self: *const ContextBuilder) ?SslVersion {
        const ctx = self.ptr orelse return null;
        const result = sys.SSL_CTX_get_max_proto_version(ctx);
        if (result == 0) return null;
        return SslVersion.fromRaw(result);
    }

    pub fn setCompliancePolicy(
        self: *ContextBuilder,
        policy: CompliancePolicy,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_one(sys.SSL_CTX_set_compliance_policy(ctx, policy.raw()));
    }

    pub fn setSigningAlgorithmPrefs(
        self: *ContextBuilder,
        prefs: []const SslSignatureAlgorithm,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        var raw_prefs: [MaxSignatureAlgorithmPrefs]u16 = undefined;
        const prefs_raw = try signature_algorithm_prefs(&raw_prefs, prefs);

        return internal.require_one(
            sys.SSL_CTX_set_signing_algorithm_prefs(ctx, prefs_raw.ptr, prefs_raw.len),
        );
    }

    pub fn setVerifyAlgorithmPrefs(
        self: *ContextBuilder,
        prefs: []const SslSignatureAlgorithm,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        var raw_prefs: [MaxSignatureAlgorithmPrefs]u16 = undefined;
        const prefs_raw = try signature_algorithm_prefs(&raw_prefs, prefs);

        return internal.require_one(
            sys.SSL_CTX_set_verify_algorithm_prefs(ctx, prefs_raw.ptr, prefs_raw.len),
        );
    }

    pub fn setGroupsList(self: *ContextBuilder, groups: [:0]const u8) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_non_empty(groups);
        try internal.require_one(sys.SSL_CTX_set1_groups_list(ctx, groups.ptr));
    }

    pub fn setCurvesList(self: *ContextBuilder, curves: [:0]const u8) BoringError!void {
        return self.setGroupsList(curves);
    }

    pub fn setSrtpProfiles(self: *ContextBuilder, profiles: [:0]const u8) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_non_empty(profiles);
        try internal.require_zero(sys.SSL_CTX_set_tlsext_use_srtp(ctx, profiles));
    }

    pub fn addCertificateCompressionAlgorithmWithContext(
        self: *ContextBuilder,
        algorithm: CertificateCompressionAlgorithm,
        comptime ContextType: type,
        context: *ContextType,
        comptime callbacks: CertificateCompressionCallbacks(ContextType),
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        if (callbacks.compress == null) {
            if (callbacks.decompress == null) return error.InvalidArgument;
        }

        const Bridge = certificate_compression_callback_bridge(ContextType, callbacks);
        const index = try Bridge.index();
        const compress = if (callbacks.compress == null) null else Bridge.compress_callback;
        const decompress = if (callbacks.decompress == null) null else Bridge.decompress_callback;

        try context_set_ex_data(ctx, ContextType, index, context);
        try internal.require_one(
            sys.SSL_CTX_add_cert_compression_alg(
                ctx,
                algorithm.raw(),
                compress,
                decompress,
            ),
        );
    }

    pub fn setClientAlpnProtos(
        self: *ContextBuilder,
        protocols_wire: []const u8,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        if (protocols_wire.len > MaxAlpnWireBytes) return error.InvalidArgument;

        return internal.require_zero(
            sys.SSL_CTX_set_alpn_protos(ctx, protocols_wire.ptr, protocols_wire.len),
        );
    }

    pub fn setClientAlpnProtocol(
        self: *ContextBuilder,
        protocol: []const u8,
    ) BoringError!void {
        try internal.require_non_empty(protocol);
        if (protocol.len > MaxSingleAlpnProtocolBytes) return error.InvalidArgument;

        var protocols_wire: [@as(usize, MaxSingleAlpnProtocolBytes) + 1]u8 = undefined;
        protocols_wire[0] = @intCast(protocol.len);
        @memcpy(protocols_wire[1..][0..protocol.len], protocol);

        return self.setClientAlpnProtos(protocols_wire[0 .. protocol.len + 1]);
    }

    pub fn setServerAlpnH2Http11(self: *ContextBuilder) void {
        const ctx = self.ptr orelse unreachable;
        sys.SSL_CTX_set_alpn_select_cb(ctx, alpn_select_h2_http11, null);
    }

    pub fn setAlpnSelectCallback(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *SslRef, []const u8) AlpnSelectResult,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = alpn_select_callback_bridge(ContextType, callback);

        sys.SSL_CTX_set_alpn_select_cb(ctx, Bridge.raw_callback, context);
    }

    pub fn setInfoCallback(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *SslRef, SslInfoCallbackMode, c_int) void,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = info_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_set_info_callback(ctx, Bridge.raw_callback);
    }

    pub fn setPskClientCallbackWithContext(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (
            *ContextType,
            *SslRef,
            ?[]const u8,
            []u8,
            []u8,
        ) BoringError!usize,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = psk_client_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_set_psk_client_callback(ctx, Bridge.raw_callback);
    }

    pub fn setPskServerCallbackWithContext(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (
            *ContextType,
            *SslRef,
            ?[]const u8,
            []u8,
        ) BoringError!usize,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = psk_server_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_set_psk_server_callback(ctx, Bridge.raw_callback);
    }

    pub fn setServerNameCallback(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *SslRef, *SslAlert) ServerNameCallbackResult,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = server_name_callback_bridge(ContextType, callback);

        try internal.require_one(sys.SSL_CTX_set_tlsext_servername_arg(ctx, context));
        try internal.require_one(
            sys.SSL_CTX_set_tlsext_servername_callback(ctx, Bridge.raw_callback),
        );
    }

    pub fn setTmpDh(self: *ContextBuilder, dh: *const dh_mod.Dh) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_one(sys.SSL_CTX_set_tmp_dh(ctx, try dh.raw()));
    }

    pub fn useCertificate(self: *ContextBuilder, cert: *const x509_mod.X509) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_one(sys.SSL_CTX_use_certificate(ctx, try cert.raw()));
    }

    pub fn usePrivateKey(self: *ContextBuilder, key: *const pkey_mod.PKey) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_one(sys.SSL_CTX_use_PrivateKey(ctx, try key.raw()));
    }

    pub fn useCertificateChainFile(self: *ContextBuilder, path: [:0]const u8) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        return internal.require_one(sys.SSL_CTX_use_certificate_chain_file(ctx, path.ptr));
    }

    pub fn add0ChainCert(self: *ContextBuilder, cert: *const x509_mod.X509) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const raw_cert = (try cert.asRef()).raw();
        try internal.require_one(sys.SSL_CTX_add0_chain_cert(ctx, raw_cert));
    }

    pub fn add1ChainCert(self: *ContextBuilder, cert: *const x509_mod.X509) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const raw_cert = (try cert.asRef()).raw();
        try internal.require_one(sys.SSL_CTX_add1_chain_cert(ctx, raw_cert));
    }

    pub fn usePrivateKeyFile(
        self: *ContextBuilder,
        path: [:0]const u8,
        file_type: FileType,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        return internal.require_one(
            sys.SSL_CTX_use_PrivateKey_file(ctx, path.ptr, file_type.raw()),
        );
    }

    pub fn setPrivateKeyMethod(
        self: *ContextBuilder,
        method: *const PrivateKeyMethod,
    ) void {
        const ctx = self.ptr orelse return;
        sys.SSL_CTX_set_private_key_method(ctx, method.raw());
    }

    pub fn setPrivateKeyMethodWithContext(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = context_private_key_method_bridge(ContextType, callbacks);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_set_private_key_method(ctx, &Bridge.method);
    }

    /// Install a custom session-ticket encryption callback on the context.
    /// The callback receives the key name, IV, cipher context, HMAC context.
    /// The callback also receives an encrypt flag.
    /// It must initialise the contexts in encrypt mode.
    /// The callback must validate the key name in decrypt mode.
    pub fn setTicketKeyCallback(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: TicketKeyCallback(ContextType),
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = ticket_key_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        try internal.require_one(
            sys.SSL_CTX_set_tlsext_ticket_key_cb(ctx, Bridge.raw_callback),
        );
    }

    pub fn setSessionCacheMode(self: *ContextBuilder, mode: SessionCacheMode) void {
        const ctx = self.ptr orelse return;
        _ = sys.SSL_CTX_set_session_cache_mode(ctx, mode.bits);
    }

    pub fn setSessionCacheSize(self: *ContextBuilder, size: u32) void {
        const ctx = self.ptr orelse return;
        _ = sys.SSL_CTX_sess_set_cache_size(ctx, size);
    }

    pub fn setSessionIdContext(
        self: *ContextBuilder,
        context: []const u8,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_one(
            sys.SSL_CTX_set_session_id_context(ctx, context.ptr, context.len),
        );
    }

    pub fn setNewSessionCallback(
        self: *ContextBuilder,
        callback: ?*const fn (ssl: ?*sys.SSL, session: ?*sys.SSL_SESSION) callconv(.c) c_int,
    ) void {
        const ctx = self.ptr orelse return;
        sys.SSL_CTX_sess_set_new_cb(ctx, callback);
    }

    pub fn setNewSessionCallbackWithContext(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *SslRef, *SslSessionRef) void,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = new_session_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_sess_set_new_cb(ctx, Bridge.raw_callback);
    }

    pub fn setRemoveSessionCallback(
        self: *ContextBuilder,
        callback: ?*const fn (ctx: ?*sys.SSL_CTX, session: ?*sys.SSL_SESSION) callconv(.c) void,
    ) void {
        const ctx = self.ptr orelse return;
        sys.SSL_CTX_sess_set_remove_cb(ctx, callback);
    }

    pub fn setRemoveSessionCallbackWithContext(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *ContextRef, *SslSessionRef) void,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = remove_session_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_sess_set_remove_cb(ctx, Bridge.raw_callback);
    }

    pub fn setGetSessionCallback(
        self: *ContextBuilder,
        callback: ?*const fn (
            ssl: ?*sys.SSL,
            id: [*c]const u8,
            id_len: c_int,
            out_copy: [*c]c_int,
        ) callconv(.c) ?*sys.SSL_SESSION,
    ) void {
        const ctx = self.ptr orelse return;
        sys.SSL_CTX_sess_set_get_cb(ctx, callback);
    }

    pub fn setGetSessionCallbackWithContext(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *SslRef, []const u8) GetSessionResult,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = get_session_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_sess_set_get_cb(ctx, Bridge.raw_callback);
    }

    pub fn setSelectCertificateCallback(
        self: *ContextBuilder,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *ClientHello) SelectCertificateResult,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = select_certificate_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_set_select_certificate_cb(ctx, Bridge.raw_callback);
    }

    pub fn setCustomVerifyCallback(
        self: *ContextBuilder,
        mode: VerifyMode,
        comptime ContextType: type,
        context: *ContextType,
        comptime callback: fn (*ContextType, *SslRef) VerifyCallbackResult,
    ) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        const Bridge = context_custom_verify_callback_bridge(ContextType, callback);
        const index = try Bridge.index();

        try context_set_ex_data(ctx, ContextType, index, context);
        sys.SSL_CTX_set_custom_verify(ctx, mode.bits, Bridge.raw_callback);
    }

    pub fn verifyParam(self: *const ContextBuilder) BoringError!*sys.X509_VERIFY_PARAM {
        const ctx = self.ptr orelse return error.Closed;
        const param = sys.SSL_CTX_get0_param(ctx) orelse return error.BoringSSL;

        return param;
    }

    pub fn addCredential(self: *ContextBuilder, cred: *sys.SSL_CREDENTIAL) BoringError!void {
        const ctx = self.ptr orelse return error.Closed;
        try internal.require_one(sys.SSL_CTX_add1_credential(ctx, cred));
    }
};

pub const Context = struct {
    ptr: ?*sys.SSL_CTX,

    pub fn newExIndex(comptime Data: type) BoringError!ex_data_mod.Index(Context, Data) {
        return context_ex_new_index(Data);
    }

    pub fn deinit(self: *Context) void {
        if (self.ptr) |ctx| {
            sys.SSL_CTX_free(ctx);
            self.ptr = null;
        }
    }

    pub fn createSsl(self: *const Context) BoringError!Ssl {
        const ctx = self.ptr orelse return error.Closed;
        const ssl = sys.SSL_new(ctx) orelse return error.BoringSSL;
        const index = try get_session_ctx_index();
        try internal.require_one(sys.SSL_CTX_up_ref(ctx));
        try internal.require_one(sys.SSL_set_ex_data(ssl, index, ctx));

        return .{ .ptr = ssl };
    }

    pub fn exData(
        self: *const Context,
        comptime Data: type,
        index: ex_data_mod.Index(Context, Data),
    ) ?*Data {
        const ctx = self.ptr orelse return null;
        return context_ex_data(ctx, Data, index);
    }

    pub fn sessionCacheSize(self: *const Context) u32 {
        const ctx = self.ptr orelse return 0;
        return @intCast(sys.SSL_CTX_sess_get_cache_size(ctx));
    }

    pub fn ciphers(self: *const Context) BoringError!SslCipherList {
        const ctx = self.ptr orelse return error.Closed;
        const ciphers_list = sys.SSL_CTX_get_ciphers(ctx) orelse return error.BoringSSL;

        return .{ .ptr = ciphers_list };
    }
};

pub const ClientHello = struct {
    ptr: [*c]const sys.SSL_CLIENT_HELLO,

    pub fn fromRaw(ptr: [*c]const sys.SSL_CLIENT_HELLO) ClientHello {
        std.debug.assert(ptr != null);

        return .{ .ptr = ptr };
    }

    pub fn raw(self: *const ClientHello) [*c]const sys.SSL_CLIENT_HELLO {
        return self.ptr;
    }

    pub fn ssl(self: *const ClientHello) ?SslRef {
        const raw_ssl = self.ptr[0].ssl orelse return null;

        return SslRef.fromRaw(raw_ssl);
    }

    pub fn extension(self: *const ClientHello, extension_type: ExtensionType) ?[]const u8 {
        var data: [*c]const u8 = null;
        var len: usize = 0;
        const result = sys.SSL_early_callback_ctx_extension_get(
            self.ptr,
            extension_type.raw(),
            &data,
            &len,
        );
        if (result == 0) return null;

        return bounded_c_slice(data, len, MaxClientHelloExtensionBytes);
    }

    pub fn bytes(self: *const ClientHello) ?[]const u8 {
        return bounded_c_slice(
            self.ptr[0].client_hello,
            self.ptr[0].client_hello_len,
            MaxClientHelloBytes,
        );
    }

    pub fn random(self: *const ClientHello) ?[]const u8 {
        return bounded_c_slice(self.ptr[0].random, self.ptr[0].random_len, 32);
    }

    pub fn ciphers(self: *const ClientHello) ?[]const u8 {
        return bounded_c_slice(
            self.ptr[0].cipher_suites,
            self.ptr[0].cipher_suites_len,
            MaxClientHelloBytes,
        );
    }

    pub fn clientVersion(self: *const ClientHello) u16 {
        return self.ptr[0].version;
    }
};

pub const BioPair = struct {
    ssl_bio: ?*sys.BIO,
    transport_bio: ?*sys.BIO,

    pub fn init(capacity_bytes: usize) BoringError!BioPair {
        if (capacity_bytes == 0) return error.InvalidArgument;
        if (capacity_bytes > MaxBioPairCapacityBytes) return error.InvalidArgument;

        var ssl_bio: ?*sys.BIO = null;
        var transport_bio: ?*sys.BIO = null;
        const result = sys.BIO_new_bio_pair(
            &ssl_bio,
            capacity_bytes,
            &transport_bio,
            capacity_bytes,
        );
        try internal.require_one(result);

        return .{
            .ssl_bio = ssl_bio orelse unreachable,
            .transport_bio = transport_bio orelse unreachable,
        };
    }

    pub fn deinit(self: *BioPair) void {
        if (self.ssl_bio) |bio| {
            _ = sys.BIO_free(bio);
            self.ssl_bio = null;
        }
        if (self.transport_bio) |bio| {
            _ = sys.BIO_free(bio);
            self.transport_bio = null;
        }
    }

    pub fn pending(self: *const BioPair) BoringError!usize {
        const bio = self.transport_bio orelse return error.Closed;
        return sys.BIO_ctrl_pending(bio);
    }

    pub fn readEncrypted(self: *BioPair, output: []u8) BoringError!usize {
        const bio = self.transport_bio orelse return error.Closed;
        if (output.len == 0) return 0;

        const len = try internal.c_int_len(output.len);
        const result = sys.BIO_read(bio, output.ptr, len);
        if (result > 0) return @intCast(result);

        return error.WantRead;
    }

    pub fn writeEncrypted(self: *BioPair, input: []const u8) BoringError!usize {
        const bio = self.transport_bio orelse return error.Closed;
        if (input.len == 0) return 0;

        const len = try internal.c_int_len(input.len);
        const result = sys.BIO_write(bio, input.ptr, len);
        if (result > 0) return @intCast(result);

        return error.WantWrite;
    }
};

fn spin_lock(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) {
        std.atomic.spinLoopHint();
    }
}

fn context_ex_new_index(comptime Data: type) BoringError!ex_data_mod.Index(Context, Data) {
    const slot = sys.SSL_CTX_get_ex_new_index(0, null, null, null, null);
    if (slot >= 0) return ex_data_mod.Index(Context, Data).fromRaw(slot);

    return error.BoringSSL;
}

fn context_set_ex_data(
    ctx: *sys.SSL_CTX,
    comptime Data: type,
    index: ex_data_mod.Index(Context, Data),
    data: ?*Data,
) BoringError!void {
    return internal.require_one(
        sys.SSL_CTX_set_ex_data(ctx, index.asRaw(), data),
    );
}

fn context_ex_data(
    ctx: *const sys.SSL_CTX,
    comptime Data: type,
    index: ex_data_mod.Index(Context, Data),
) ?*Data {
    const data = sys.SSL_CTX_get_ex_data(ctx, index.asRaw()) orelse return null;

    return @ptrCast(@alignCast(data));
}

fn session_ctx_free(
    _: ?*anyopaque,
    ptr: ?*anyopaque,
    _: [*c]sys.CRYPTO_EX_DATA,
    _: c_int,
    _: c_long,
    _: ?*anyopaque,
) callconv(.c) void {
    if (ptr) |p| sys.SSL_CTX_free(@ptrCast(@alignCast(p)));
}

var session_ctx_index: c_int = -1;
var session_ctx_index_mutex: std.atomic.Mutex = .unlocked;

fn get_session_ctx_index() BoringError!c_int {
    spin_lock(&session_ctx_index_mutex);
    defer session_ctx_index_mutex.unlock();

    if (session_ctx_index < 0) {
        const slot = sys.SSL_get_ex_new_index(
            0,
            null,
            null,
            null,
            session_ctx_free,
        );
        if (slot < 0) return error.BoringSSL;
        session_ctx_index = slot;
    }
    return session_ctx_index;
}

fn ssl_ex_new_index(comptime Data: type) BoringError!ex_data_mod.Index(Ssl, Data) {
    const slot = sys.SSL_get_ex_new_index(0, null, null, null, null);
    if (slot >= 0) return ex_data_mod.Index(Ssl, Data).fromRaw(slot);

    return error.BoringSSL;
}

fn ssl_set_ex_data(
    ssl: *sys.SSL,
    comptime Data: type,
    index: ex_data_mod.Index(Ssl, Data),
    data: ?*Data,
) BoringError!void {
    return internal.require_one(
        sys.SSL_set_ex_data(ssl, index.asRaw(), data),
    );
}

fn ssl_ex_data(
    ssl: *const sys.SSL,
    comptime Data: type,
    index: ex_data_mod.Index(Ssl, Data),
) ?*Data {
    const data = sys.SSL_get_ex_data(ssl, index.asRaw()) orelse return null;

    return @ptrCast(@alignCast(data));
}

fn set_verify_hostname(param: *sys.X509_VERIFY_PARAM, host: [:0]const u8) BoringError!void {
    try internal.require_non_empty(host);

    sys.X509_VERIFY_PARAM_set_hostflags(
        param,
        x509_verify_mod.X509CheckFlags.noPartialWildcards.bits,
    );

    if (is_ip_address(host)) {
        var octets: [16]u8 = undefined;
        const octets_len = try parse_ip_address(host, &octets);
        if (octets_len == 4) {
            try set_verify_ip4(param, octets[0..4]);
        } else {
            try set_verify_ip6(param, &octets);
        }
    } else {
        try set_verify_host(param, host);
    }
}

fn is_ip_address(host: []const u8) bool {
    std.debug.assert(host.len > 0);

    var octets: [16]u8 = undefined;
    _ = parse_ip_address(host, &octets) catch return false;
    return true;
}

fn parse_ip_address(host: []const u8, octets: *[16]u8) BoringError!usize {
    std.debug.assert(host.len > 0);

    if (std.Io.net.IpAddress.parseIp4(host, 0)) |address| {
        switch (address) {
            .ip4 => |ip4| {
                @memcpy(octets[0..4], &ip4.bytes);
                return 4;
            },
            .ip6 => unreachable,
        }
    } else |_| {}

    if (std.Io.net.IpAddress.parseIp6(host, 0)) |address| {
        switch (address) {
            .ip4 => unreachable,
            .ip6 => |ip6| {
                @memcpy(octets[0..16], &ip6.bytes);
                return 16;
            },
        }
    } else |_| {}

    return error.InvalidArgument;
}

fn set_verify_host(param: *sys.X509_VERIFY_PARAM, host: [:0]const u8) BoringError!void {
    try internal.require_non_empty(host);
    try internal.require_one(sys.X509_VERIFY_PARAM_set1_host(param, host.ptr, host.len));
}

fn set_verify_ip4(param: *sys.X509_VERIFY_PARAM, octets: *const [4]u8) BoringError!void {
    try internal.require_one(sys.X509_VERIFY_PARAM_set1_ip(param, octets.ptr, 4));
}

fn set_verify_ip6(param: *sys.X509_VERIFY_PARAM, octets: *const [16]u8) BoringError!void {
    try internal.require_one(sys.X509_VERIFY_PARAM_set1_ip(param, octets.ptr, 16));
}

const PrivateKeyCallbackOutput = struct {
    bytes: []u8,
    out_len: [*c]usize,
};

const PrivateKeyContextSource = enum {
    context,
    ssl,
};

fn private_key_index_type(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
) type {
    return switch (source) {
        .context => ex_data_mod.Index(Context, ContextType),
        .ssl => ex_data_mod.Index(Ssl, ContextType),
    };
}

fn private_key_method_state(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
) type {
    _ = callbacks;

    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!private_key_index_type(source, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return private_key_index_type(source, ContextType).fromRaw(index_slot);
            }

            const new_index = switch (source) {
                .context => try context_ex_new_index(ContextType),
                .ssl => try ssl_ex_new_index(ContextType),
            };
            index_slot = new_index.asRaw();

            return new_index;
        }
    };
}

fn context_private_key_method_bridge(
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
) type {
    return private_key_method_bridge(.context, ContextType, callbacks);
}

fn ssl_private_key_method_bridge(
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
) type {
    return private_key_method_bridge(.ssl, ContextType, callbacks);
}

fn private_key_method_bridge(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
) type {
    const State = private_key_method_state(source, ContextType, callbacks);

    return struct {
        const method: sys.SSL_PRIVATE_KEY_METHOD = .{
            .sign = private_key_sign_bridge(source, ContextType, callbacks, State).raw,
            .decrypt = private_key_decrypt_bridge(source, ContextType, callbacks, State).raw,
            .complete = private_key_complete_bridge(source, ContextType, callbacks, State).raw,
        };

        fn index() BoringError!private_key_index_type(source, ContextType) {
            return State.index();
        }
    };
}

fn private_key_sign_bridge(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
    comptime State: type,
) type {
    return struct {
        fn raw(
            ssl: ?*sys.SSL,
            out: [*c]u8,
            out_len: [*c]usize,
            max_out: usize,
            signature_algorithm: u16,
            input: [*c]const u8,
            input_len: usize,
        ) callconv(.c) sys.enum_ssl_private_key_result_t {
            return private_key_sign_callback(
                source,
                ContextType,
                callbacks,
                State.index_slot,
                ssl,
                out,
                out_len,
                max_out,
                signature_algorithm,
                input,
                input_len,
            );
        }
    };
}

fn private_key_decrypt_bridge(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
    comptime State: type,
) type {
    return struct {
        fn raw(
            ssl: ?*sys.SSL,
            out: [*c]u8,
            out_len: [*c]usize,
            max_out: usize,
            input: [*c]const u8,
            input_len: usize,
        ) callconv(.c) sys.enum_ssl_private_key_result_t {
            return private_key_decrypt_callback(
                source,
                ContextType,
                callbacks,
                State.index_slot,
                ssl,
                out,
                out_len,
                max_out,
                input,
                input_len,
            );
        }
    };
}

fn private_key_complete_bridge(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
    comptime State: type,
) type {
    return struct {
        fn raw(
            ssl: ?*sys.SSL,
            out: [*c]u8,
            out_len: [*c]usize,
            max_out: usize,
        ) callconv(.c) sys.enum_ssl_private_key_result_t {
            return private_key_complete_callback(
                source,
                ContextType,
                callbacks,
                State.index_slot,
                ssl,
                out,
                out_len,
                max_out,
            );
        }
    };
}

fn new_session_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *SslRef, *SslSessionRef) void,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_ssl: ?*sys.SSL,
            raw_session: ?*sys.SSL_SESSION,
        ) callconv(.c) c_int {
            const ssl = raw_ssl orelse return 0;
            const session = raw_session orelse return 0;
            if (index_slot < 0) return 0;

            const sess_ctx_raw = sys.SSL_get_ex_data(
                ssl,
                get_session_ctx_index() catch return 0,
            ) orelse return 0;
            const sess_ctx: *const sys.SSL_CTX = @ptrCast(@alignCast(sess_ctx_raw));
            const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            const context = context_ex_data(sess_ctx, ContextType, index_value) orelse return 0;

            var ssl_ref = SslRef.fromRaw(ssl);
            var session_ref = SslSessionRef.fromRaw(session);
            callback(context, &ssl_ref, &session_ref);

            return 0;
        }
    };
}

fn remove_session_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *ContextRef, *SslSessionRef) void,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_ctx: ?*sys.SSL_CTX,
            raw_session: ?*sys.SSL_SESSION,
        ) callconv(.c) void {
            const ctx = raw_ctx orelse return;
            const session = raw_session orelse return;
            if (index_slot < 0) return;

            const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            const context = context_ex_data(ctx, ContextType, index_value) orelse return;

            var context_ref = ContextRef.fromRaw(ctx);
            var session_ref = SslSessionRef.fromRaw(session);
            callback(context, &context_ref, &session_ref);
        }
    };
}

fn alpn_select_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *SslRef, []const u8) AlpnSelectResult,
) type {
    return struct {
        fn raw_callback(
            raw_ssl: ?*sys.SSL,
            out: [*c][*c]const u8,
            out_len: [*c]u8,
            input: [*c]const u8,
            input_len: c_uint,
            arg: ?*anyopaque,
        ) callconv(.c) c_int {
            const ssl = raw_ssl orelse return sys.SSL_TLSEXT_ERR_ALERT_FATAL;
            const context = callback_arg(ContextType, arg) orelse {
                return sys.SSL_TLSEXT_ERR_ALERT_FATAL;
            };
            const protocols = bounded_c_slice(input, input_len, MaxAlpnWireBytes) orelse {
                return sys.SSL_TLSEXT_ERR_ALERT_FATAL;
            };

            var ssl_ref = SslRef.fromRaw(ssl);
            const result = callback(context, &ssl_ref, protocols);

            return alpn_select_callback_result(result, protocols, out, out_len);
        }
    };
}

fn server_name_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *SslRef, *SslAlert) ServerNameCallbackResult,
) type {
    return struct {
        fn raw_callback(
            raw_ssl: ?*sys.SSL,
            out_alert: [*c]c_int,
            arg: ?*anyopaque,
        ) callconv(.c) c_int {
            const ssl = raw_ssl orelse return sys.SSL_TLSEXT_ERR_ALERT_FATAL;
            const context = callback_arg(ContextType, arg) orelse {
                return sys.SSL_TLSEXT_ERR_ALERT_FATAL;
            };

            var ssl_ref = SslRef.fromRaw(ssl);
            var alert = SslAlert.unrecognizedName;
            const result = callback(context, &ssl_ref, &alert);

            return server_name_callback_result(result, out_alert);
        }
    };
}

fn info_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *SslRef, SslInfoCallbackMode, c_int) void,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_ssl: ?*const sys.SSL,
            mode: c_int,
            value: c_int,
        ) callconv(.c) void {
            const ssl = raw_ssl orelse return;
            if (index_slot < 0) return;

            const ctx = sys.SSL_get_SSL_CTX(ssl) orelse return;
            const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            const context = context_ex_data(ctx, ContextType, index_value) orelse return;

            var ssl_ref = SslRef.fromRaw(@constCast(ssl));
            callback(context, &ssl_ref, SslInfoCallbackMode.fromRaw(mode), value);
        }
    };
}

fn psk_client_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (
        *ContextType,
        *SslRef,
        ?[]const u8,
        []u8,
        []u8,
    ) BoringError!usize,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_ssl: ?*sys.SSL,
            hint: [*c]const u8,
            identity: [*c]u8,
            max_identity_len: c_uint,
            psk: [*c]u8,
            max_psk_len: c_uint,
        ) callconv(.c) c_uint {
            const ssl = raw_ssl orelse return 0;
            const context = psk_callback_context(ContextType, index_slot, ssl) orelse return 0;
            var ssl_ref = SslRef.fromRaw(ssl);
            const hint_bytes = c_string_or_null(hint);
            const identity_out = bounded_c_slice_mut_capacity(
                identity,
                max_identity_len,
                MaxPskIdentityBytes,
            ) orelse return 0;
            const psk_out = bounded_c_slice_mut_capacity(psk, max_psk_len, MaxPskBytes) orelse {
                return 0;
            };

            const psk_len = callback(
                context,
                &ssl_ref,
                hint_bytes,
                identity_out,
                psk_out,
            ) catch return 0;
            if (psk_len > psk_out.len) return 0;

            return @intCast(psk_len);
        }
    };
}

fn psk_server_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (
        *ContextType,
        *SslRef,
        ?[]const u8,
        []u8,
    ) BoringError!usize,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_ssl: ?*sys.SSL,
            identity: [*c]const u8,
            psk: [*c]u8,
            max_psk_len: c_uint,
        ) callconv(.c) c_uint {
            const ssl = raw_ssl orelse return 0;
            const context = psk_callback_context(ContextType, index_slot, ssl) orelse return 0;
            var ssl_ref = SslRef.fromRaw(ssl);
            const identity_bytes = c_string_or_null(identity);
            const psk_out = bounded_c_slice_mut_capacity(psk, max_psk_len, MaxPskBytes) orelse {
                return 0;
            };

            const psk_len = callback(context, &ssl_ref, identity_bytes, psk_out) catch {
                return 0;
            };
            if (psk_len > psk_out.len) return 0;

            return @intCast(psk_len);
        }
    };
}

fn psk_callback_context(
    comptime ContextType: type,
    index_slot: c_int,
    ssl: *sys.SSL,
) ?*ContextType {
    if (index_slot < 0) return null;

    const ctx = sys.SSL_get_SSL_CTX(ssl) orelse return null;
    const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);

    return context_ex_data(ctx, ContextType, index_value);
}

fn callback_arg(comptime ContextType: type, arg: ?*anyopaque) ?*ContextType {
    const context = arg orelse return null;

    return @ptrCast(@alignCast(context));
}

fn select_certificate_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *ClientHello) SelectCertificateResult,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_client_hello: [*c]const sys.SSL_CLIENT_HELLO,
        ) callconv(.c) sys.enum_ssl_select_cert_result_t {
            if (raw_client_hello == null) return sys.ssl_select_cert_error;
            if (index_slot < 0) return sys.ssl_select_cert_error;

            const raw_ssl = raw_client_hello[0].ssl orelse return sys.ssl_select_cert_error;
            const raw_ctx = sys.SSL_get_SSL_CTX(raw_ssl) orelse return sys.ssl_select_cert_error;
            const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            const context = context_ex_data(raw_ctx, ContextType, index_value) orelse {
                return sys.ssl_select_cert_error;
            };

            var client_hello = ClientHello.fromRaw(raw_client_hello);
            return @intFromEnum(callback(context, &client_hello));
        }
    };
}

fn verify_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, bool, *x509_store_context_mod.X509StoreContext) bool,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            ok: c_int,
            store_ctx: ?*sys.X509_STORE_CTX,
        ) callconv(.c) c_int {
            if (store_ctx == null) return 0;
            if (index_slot < 0) return ok;

            const idx = sys.SSL_get_ex_data_X509_STORE_CTX_idx();
            const raw_ssl = sys.X509_STORE_CTX_get_ex_data(store_ctx, idx);
            if (raw_ssl == null) return ok;
            const ssl = @as(?*sys.SSL, @ptrCast(raw_ssl)) orelse return ok;
            const raw_ctx = sys.SSL_get_SSL_CTX(ssl) orelse return ok;
            const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            const context = context_ex_data(raw_ctx, ContextType, index_value) orelse return ok;

            var ctx = x509_store_context_mod.X509StoreContext{ .ptr = store_ctx };
            return @intFromBool(callback(context, ok != 0, &ctx));
        }
    };
}

fn ssl_verify_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, bool, *x509_store_context_mod.X509StoreContext) bool,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Ssl, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Ssl, ContextType).fromRaw(index_slot);
            }

            const new_index = try ssl_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            ok: c_int,
            store_ctx: ?*sys.X509_STORE_CTX,
        ) callconv(.c) c_int {
            if (store_ctx == null) return 0;
            if (index_slot < 0) return ok;

            const idx = sys.SSL_get_ex_data_X509_STORE_CTX_idx();
            const raw_ssl = sys.X509_STORE_CTX_get_ex_data(store_ctx, idx);
            if (raw_ssl == null) return ok;
            const ssl = @as(?*sys.SSL, @ptrCast(raw_ssl)) orelse return ok;
            const index_value = ex_data_mod.Index(Ssl, ContextType).fromRaw(index_slot);
            const context = ssl_ex_data(ssl, ContextType, index_value) orelse return ok;

            var ctx = x509_store_context_mod.X509StoreContext{ .ptr = store_ctx };
            return @intFromBool(callback(context, ok != 0, &ctx));
        }
    };
}

fn cert_verify_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *x509_store_context_mod.X509StoreContext) bool,
) type {
    return struct {
        fn raw_callback(
            store_ctx: ?*sys.X509_STORE_CTX,
            arg: ?*anyopaque,
        ) callconv(.c) c_int {
            if (store_ctx == null) return 0;
            const context = @as(?*ContextType, @ptrCast(arg)) orelse return 0;
            var ctx = x509_store_context_mod.X509StoreContext{ .ptr = store_ctx };
            return @intFromBool(callback(context, &ctx));
        }
    };
}

fn context_custom_verify_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *SslRef) VerifyCallbackResult,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_ssl: ?*sys.SSL,
            out_alert: [*c]u8,
        ) callconv(.c) sys.enum_ssl_verify_result_t {
            const ssl = raw_ssl orelse return verify_callback_invalid(out_alert);
            if (index_slot < 0) return verify_callback_invalid(out_alert);

            const raw_ctx = sys.SSL_get_SSL_CTX(ssl) orelse {
                return verify_callback_invalid(out_alert);
            };
            const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            const context = context_ex_data(raw_ctx, ContextType, index_value) orelse {
                return verify_callback_invalid(out_alert);
            };

            var ssl_ref = SslRef.fromRaw(ssl);
            return verify_callback_result(callback(context, &ssl_ref), out_alert);
        }
    };
}

fn ssl_custom_verify_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *SslRef) VerifyCallbackResult,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Ssl, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Ssl, ContextType).fromRaw(index_slot);
            }

            const new_index = try ssl_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_ssl: ?*sys.SSL,
            out_alert: [*c]u8,
        ) callconv(.c) sys.enum_ssl_verify_result_t {
            const ssl = raw_ssl orelse return verify_callback_invalid(out_alert);
            if (index_slot < 0) return verify_callback_invalid(out_alert);

            const index_value = ex_data_mod.Index(Ssl, ContextType).fromRaw(index_slot);
            const context = ssl_ex_data(ssl, ContextType, index_value) orelse {
                return verify_callback_invalid(out_alert);
            };

            var ssl_ref = SslRef.fromRaw(ssl);
            return verify_callback_result(callback(context, &ssl_ref), out_alert);
        }
    };
}

fn get_session_callback_bridge(
    comptime ContextType: type,
    comptime callback: fn (*ContextType, *SslRef, []const u8) GetSessionResult,
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_ssl: ?*sys.SSL,
            id: [*c]const u8,
            id_len: c_int,
            out_copy: [*c]c_int,
        ) callconv(.c) ?*sys.SSL_SESSION {
            const ssl = raw_ssl orelse return null;
            if (id_len < 0) return null;
            if (out_copy == null) return null;
            if (index_slot < 0) return null;

            const id_len_usize: usize = @intCast(id_len);
            const id_bytes = bounded_c_slice(id, id_len_usize, MaxSessionIdBytes) orelse {
                return null;
            };
            const sess_ctx_raw = sys.SSL_get_ex_data(
                ssl,
                get_session_ctx_index() catch return null,
            ) orelse return null;
            const sess_ctx: *const sys.SSL_CTX = @ptrCast(@alignCast(sess_ctx_raw));
            const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            const context = context_ex_data(sess_ctx, ContextType, index_value) orelse return null;

            var ssl_ref = SslRef.fromRaw(ssl);
            var result = callback(context, &ssl_ref, id_bytes);
            return switch (result) {
                .none => null,
                .retry => sys.SSL_magic_pending_session_ptr(),
                .session => |*session| get_session_callback_session(out_copy, session),
            };
        }
    };
}

fn get_session_callback_session(
    out_copy: [*c]c_int,
    session: *SslSession,
) ?*sys.SSL_SESSION {
    out_copy[0] = 0;

    return session.intoRaw() catch null;
}

fn private_key_sign_callback(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
    index_slot: c_int,
    raw_ssl: ?*sys.SSL,
    out: [*c]u8,
    out_len: [*c]usize,
    max_out: usize,
    signature_algorithm: u16,
    input: [*c]const u8,
    input_len: usize,
) sys.enum_ssl_private_key_result_t {
    const ssl = raw_ssl orelse return private_key_failure();
    const context = private_key_callback_context(
        source,
        ContextType,
        index_slot,
        ssl,
    ) orelse return private_key_failure();
    var output = private_key_callback_output(out, out_len, max_out) orelse {
        return private_key_failure();
    };
    const input_bytes = bounded_c_slice(input, input_len, MaxPrivateKeyOperationBytes) orelse {
        return private_key_failure();
    };

    var ssl_ref = SslRef.fromRaw(ssl);
    const algorithm = SslSignatureAlgorithm.fromRaw(signature_algorithm);
    const result = callbacks.sign(context, &ssl_ref, input_bytes, algorithm, output.bytes);

    return private_key_callback_result(result, &output);
}

fn private_key_decrypt_callback(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
    index_slot: c_int,
    raw_ssl: ?*sys.SSL,
    out: [*c]u8,
    out_len: [*c]usize,
    max_out: usize,
    input: [*c]const u8,
    input_len: usize,
) sys.enum_ssl_private_key_result_t {
    const ssl = raw_ssl orelse return private_key_failure();
    const context = private_key_callback_context(
        source,
        ContextType,
        index_slot,
        ssl,
    ) orelse return private_key_failure();
    var output = private_key_callback_output(out, out_len, max_out) orelse {
        return private_key_failure();
    };
    const input_bytes = bounded_c_slice(input, input_len, MaxPrivateKeyOperationBytes) orelse {
        return private_key_failure();
    };

    var ssl_ref = SslRef.fromRaw(ssl);
    const result = callbacks.decrypt(context, &ssl_ref, input_bytes, output.bytes);

    return private_key_callback_result(result, &output);
}

fn private_key_complete_callback(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
    comptime callbacks: PrivateKeyMethodCallbacks(ContextType),
    index_slot: c_int,
    raw_ssl: ?*sys.SSL,
    out: [*c]u8,
    out_len: [*c]usize,
    max_out: usize,
) sys.enum_ssl_private_key_result_t {
    const ssl = raw_ssl orelse return private_key_failure();
    const context = private_key_callback_context(
        source,
        ContextType,
        index_slot,
        ssl,
    ) orelse return private_key_failure();
    var output = private_key_callback_output(out, out_len, max_out) orelse {
        return private_key_failure();
    };

    var ssl_ref = SslRef.fromRaw(ssl);
    const result = callbacks.complete(context, &ssl_ref, output.bytes);

    return private_key_callback_result(result, &output);
}

fn private_key_callback_context(
    comptime source: PrivateKeyContextSource,
    comptime ContextType: type,
    index_slot: c_int,
    ssl: *sys.SSL,
) ?*ContextType {
    if (index_slot < 0) return null;

    return switch (source) {
        .context => private_key_callback_context_ctx(ContextType, index_slot, ssl),
        .ssl => private_key_callback_context_ssl(ContextType, index_slot, ssl),
    };
}

fn private_key_callback_context_ctx(
    comptime ContextType: type,
    index_slot: c_int,
    ssl: *sys.SSL,
) ?*ContextType {
    const raw_ctx = sys.SSL_get_SSL_CTX(ssl) orelse return null;
    const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);

    return context_ex_data(raw_ctx, ContextType, index_value);
}

fn private_key_callback_context_ssl(
    comptime ContextType: type,
    index_slot: c_int,
    ssl: *sys.SSL,
) ?*ContextType {
    const index_value = ex_data_mod.Index(Ssl, ContextType).fromRaw(index_slot);

    return ssl_ex_data(ssl, ContextType, index_value);
}

fn private_key_callback_output(
    out: [*c]u8,
    out_len: [*c]usize,
    max_out: usize,
) ?PrivateKeyCallbackOutput {
    if (out_len == null) return null;

    const bytes = bounded_c_slice_mut(out, max_out, MaxPrivateKeyOperationBytes) orelse {
        return null;
    };

    return .{
        .bytes = bytes,
        .out_len = out_len,
    };
}

fn private_key_callback_result(
    result: PrivateKeyCallbackResult,
    output: *PrivateKeyCallbackOutput,
) sys.enum_ssl_private_key_result_t {
    return switch (result) {
        .success => |written| private_key_success(output, written),
        .retry => @intCast(sys.ssl_private_key_retry),
        .failure => private_key_failure(),
    };
}

fn private_key_success(
    output: *PrivateKeyCallbackOutput,
    written: usize,
) sys.enum_ssl_private_key_result_t {
    if (written > output.bytes.len) return private_key_failure();

    output.out_len[0] = written;
    return @intCast(sys.ssl_private_key_success);
}

fn private_key_failure() sys.enum_ssl_private_key_result_t {
    return @intCast(sys.ssl_private_key_failure);
}

fn alpn_select_callback_result(
    result: AlpnSelectResult,
    protocols: []const u8,
    out: [*c][*c]const u8,
    out_len: [*c]u8,
) c_int {
    return switch (result) {
        .selected => |selected| alpn_select_callback_selected(
            protocols,
            selected,
            out,
            out_len,
        ),
        .noAck => sys.SSL_TLSEXT_ERR_NOACK,
        .alertFatal => sys.SSL_TLSEXT_ERR_ALERT_FATAL,
    };
}

fn alpn_select_callback_selected(
    protocols: []const u8,
    selected: []const u8,
    out: [*c][*c]const u8,
    out_len: [*c]u8,
) c_int {
    if (out == null) return sys.SSL_TLSEXT_ERR_ALERT_FATAL;
    if (out_len == null) return sys.SSL_TLSEXT_ERR_ALERT_FATAL;
    if (selected.len == 0) return sys.SSL_TLSEXT_ERR_ALERT_FATAL;
    if (selected.len > MaxSingleAlpnProtocolBytes) return sys.SSL_TLSEXT_ERR_ALERT_FATAL;
    if (!slice_contains(protocols, selected)) return sys.SSL_TLSEXT_ERR_ALERT_FATAL;

    out[0] = selected.ptr;
    out_len[0] = @intCast(selected.len);

    return sys.SSL_TLSEXT_ERR_OK;
}

fn server_name_callback_result(
    result: ServerNameCallbackResult,
    out_alert: [*c]c_int,
) c_int {
    return switch (result) {
        .ok => sys.SSL_TLSEXT_ERR_OK,
        .noAck => sys.SSL_TLSEXT_ERR_NOACK,
        .alertFatal => |alert| server_name_callback_alert(
            out_alert,
            alert,
            sys.SSL_TLSEXT_ERR_ALERT_FATAL,
        ),
        .alertWarning => |alert| server_name_callback_alert(
            out_alert,
            alert,
            sys.SSL_TLSEXT_ERR_ALERT_WARNING,
        ),
    };
}

fn server_name_callback_alert(
    out_alert: [*c]c_int,
    alert: SslAlert,
    result: c_int,
) c_int {
    if (out_alert != null) {
        out_alert[0] = alert.raw();
    }

    return result;
}

fn signature_algorithm_prefs(
    target: *[MaxSignatureAlgorithmPrefs]u16,
    prefs: []const SslSignatureAlgorithm,
) BoringError![]const u16 {
    if (prefs.len == 0) return error.InvalidArgument;
    if (prefs.len > MaxSignatureAlgorithmPrefs) return error.InvalidArgument;

    for (prefs, 0..) |pref, index| {
        target[index] = pref.raw();
    }

    return target[0..prefs.len];
}

fn verify_callback_result(
    result: VerifyCallbackResult,
    out_alert: [*c]u8,
) sys.enum_ssl_verify_result_t {
    return switch (result) {
        .ok => @intCast(sys.ssl_verify_ok),
        .retry => @intCast(sys.ssl_verify_retry),
        .invalid => |alert| verify_callback_invalid_alert(out_alert, alert),
    };
}

fn verify_callback_invalid(out_alert: [*c]u8) sys.enum_ssl_verify_result_t {
    return verify_callback_invalid_alert(out_alert, .internalError);
}

fn verify_callback_invalid_alert(
    out_alert: [*c]u8,
    alert: SslAlert,
) sys.enum_ssl_verify_result_t {
    if (out_alert != null) {
        out_alert[0] = alert.raw();
    }

    return @intCast(sys.ssl_verify_invalid);
}

fn ssl_selected_alpn(ssl: *const sys.SSL) ?[]const u8 {
    var data: [*c]const u8 = null;
    var len: c_uint = 0;
    sys.SSL_get0_alpn_selected(ssl, &data, &len);

    if (len == 0) return null;
    if (data == null) return null;

    return data[0..len];
}

fn bounded_c_slice(ptr: [*c]const u8, len: usize, max_len: usize) ?[]const u8 {
    if (len == 0) return "";
    if (ptr == null) return null;
    if (len > max_len) return null;

    return ptr[0..len];
}

fn bounded_c_slice_mut(ptr: [*c]u8, len: usize, max_len: usize) ?[]u8 {
    if (ptr == null) return null;
    if (len > max_len) return null;

    return ptr[0..len];
}

fn bounded_c_slice_mut_capacity(ptr: [*c]u8, len: usize, max_len: usize) ?[]u8 {
    if (ptr == null) return null;

    return ptr[0..@min(len, max_len)];
}

fn c_string_or_null(ptr: [*c]const u8) ?[]const u8 {
    if (ptr == null) return null;

    return std.mem.span(ptr);
}

fn slice_contains(parent: []const u8, child: []const u8) bool {
    if (child.len > parent.len) return false;
    if (child.len == 0) return true;
    if (parent.len == 0) return false;

    const parent_start = @intFromPtr(parent.ptr);
    const child_start = @intFromPtr(child.ptr);
    const parent_end = pointer_add(parent_start, parent.len) orelse return false;
    const child_end = pointer_add(child_start, child.len) orelse return false;

    if (child_start < parent_start) return false;
    if (child_end > parent_end) return false;

    return true;
}

fn pointer_add(base: usize, len: usize) ?usize {
    if (base > std.math.maxInt(usize) - len) return null;

    return base + len;
}

fn ssl_result(ssl: *sys.SSL, result: c_int) BoringError!c_int {
    if (result > 0) return result;

    const code = sys.SSL_get_error(ssl, result);
    return switch (code) {
        sys.SSL_ERROR_NONE => 0,
        sys.SSL_ERROR_SSL => error.BoringSSL,
        sys.SSL_ERROR_WANT_READ => error.WantRead,
        sys.SSL_ERROR_WANT_WRITE => error.WantWrite,
        sys.SSL_ERROR_WANT_X509_LOOKUP => error.WantX509Lookup,
        sys.SSL_ERROR_SYSCALL => error.Syscall,
        sys.SSL_ERROR_ZERO_RETURN => error.ZeroReturn,
        sys.SSL_ERROR_WANT_CONNECT => error.WantConnect,
        sys.SSL_ERROR_WANT_ACCEPT => error.WantAccept,
        sys.SSL_ERROR_PENDING_SESSION => error.PendingSession,
        sys.SSL_ERROR_PENDING_CERTIFICATE => error.PendingCertificate,
        sys.SSL_ERROR_WANT_PRIVATE_KEY_OPERATION => error.WantPrivateKeyOperation,
        sys.SSL_ERROR_PENDING_TICKET => error.PendingTicket,
        sys.SSL_ERROR_EARLY_DATA_REJECTED => error.BoringSSL,
        sys.SSL_ERROR_WANT_CERTIFICATE_VERIFY => error.WantCertificateVerify,
        sys.SSL_ERROR_WANT_RENEGOTIATE => error.WantRenegotiate,
        else => error.BoringSSL,
    };
}

fn alpn_select_h2_http11(
    ssl: ?*sys.SSL,
    out: [*c][*c]const u8,
    out_len: [*c]u8,
    input: [*c]const u8,
    input_len: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = ssl;
    _ = arg;

    if (input == null) return sys.SSL_TLSEXT_ERR_NOACK;
    if (input_len > MaxAlpnWireBytes) return sys.SSL_TLSEXT_ERR_NOACK;

    const input_bytes = input[0..input_len];
    if (select_alpn(input_bytes, "h2")) |selected| {
        out.* = selected.ptr;
        out_len.* = @intCast(selected.len);
        return sys.SSL_TLSEXT_ERR_OK;
    }
    if (select_alpn(input_bytes, "http/1.1")) |selected| {
        out.* = selected.ptr;
        out_len.* = @intCast(selected.len);
        return sys.SSL_TLSEXT_ERR_OK;
    }

    return sys.SSL_TLSEXT_ERR_NOACK;
}

fn select_alpn(
    input: []const u8,
    protocol: []const u8,
) ?[]const u8 {
    std.debug.assert(protocol.len > 0);
    std.debug.assert(protocol.len <= MaxSingleAlpnProtocolBytes);
    std.debug.assert(input.len <= MaxAlpnWireBytes);

    var index: u32 = 0;
    while (index < input.len) {
        const protocol_len = input[index];
        const next_index = index + 1 + @as(u32, protocol_len);

        if (next_index > input.len) return null;

        if (protocol_len == protocol.len) {
            const candidate = input[index + 1 .. next_index];
            if (std.mem.eql(u8, candidate, protocol)) return candidate;
        }

        index = next_index;
    }

    return null;
}

fn CertificateCompressionCallbackContext(comptime ContextType: type) type {
    return struct {
        context: *ContextType,
        ssl_ref: SslRef,
    };
}

fn certificate_compression_context(
    comptime ContextType: type,
    index_slot: c_int,
    raw_ssl: ?*sys.SSL,
) ?CertificateCompressionCallbackContext(ContextType) {
    const ssl = raw_ssl orelse return null;
    if (index_slot < 0) return null;

    const raw_ctx = sys.SSL_get_SSL_CTX(ssl) orelse return null;
    const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
    const ctx = context_ex_data(raw_ctx, ContextType, index_value) orelse return null;

    return .{
        .context = ctx,
        .ssl_ref = SslRef.fromRaw(ssl),
    };
}

fn certificate_compression_compress_callback(
    comptime ContextType: type,
    comptime callbacks: CertificateCompressionCallbacks(ContextType),
    index_slot: c_int,
    raw_ssl: ?*sys.SSL,
    output: ?*sys.CBB,
    input: [*c]const u8,
    input_len: usize,
) c_int {
    const callback = callbacks.compress orelse return 0;
    if (output == null) return 0;
    const input_bytes = bounded_c_slice(
        input,
        input_len,
        std.math.maxInt(usize),
    ) orelse return 0;
    const callback_context = certificate_compression_context(
        ContextType,
        index_slot,
        raw_ssl,
    ) orelse return 0;
    var ssl_ref = callback_context.ssl_ref;
    var writer = CertificateCompressionWriter{ .ptr = output.? };

    callback(callback_context.context, &ssl_ref, input_bytes, &writer) catch return 0;
    return 1;
}

fn certificate_compression_decompress_callback(
    comptime ContextType: type,
    comptime callbacks: CertificateCompressionCallbacks(ContextType),
    index_slot: c_int,
    raw_ssl: ?*sys.SSL,
    output: [*c]?*sys.CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: [*c]const u8,
    input_len: usize,
) c_int {
    const callback = callbacks.decompress orelse return 0;
    if (output == null) return 0;
    const input_bytes = bounded_c_slice(
        input,
        input_len,
        std.math.maxInt(usize),
    ) orelse return 0;
    const callback_context = certificate_compression_context(
        ContextType,
        index_slot,
        raw_ssl,
    ) orelse return 0;
    var ssl_ref = callback_context.ssl_ref;

    var data: [*c]u8 = null;
    const buffer = sys.CRYPTO_BUFFER_alloc(&data, uncompressed_len) orelse return 0;
    if (uncompressed_len > 0) {
        if (data == null) {
            sys.CRYPTO_BUFFER_free(buffer);
            return 0;
        }
    }

    var empty: [0]u8 = .{};
    const output_bytes = if (uncompressed_len == 0) empty[0..] else data[0..uncompressed_len];
    callback(callback_context.context, &ssl_ref, input_bytes, output_bytes) catch {
        sys.CRYPTO_BUFFER_free(buffer);
        return 0;
    };
    output[0] = buffer;
    return 1;
}

fn certificate_compression_callback_bridge(
    comptime ContextType: type,
    comptime callbacks: CertificateCompressionCallbacks(ContextType),
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn compress_callback(
            raw_ssl: ?*sys.SSL,
            output: ?*sys.CBB,
            input: [*c]const u8,
            input_len: usize,
        ) callconv(.c) c_int {
            return certificate_compression_compress_callback(
                ContextType,
                callbacks,
                index_slot,
                raw_ssl,
                output,
                input,
                input_len,
            );
        }

        fn decompress_callback(
            raw_ssl: ?*sys.SSL,
            output: [*c]?*sys.CRYPTO_BUFFER,
            uncompressed_len: usize,
            input: [*c]const u8,
            input_len: usize,
        ) callconv(.c) c_int {
            return certificate_compression_decompress_callback(
                ContextType,
                callbacks,
                index_slot,
                raw_ssl,
                output,
                uncompressed_len,
                input,
                input_len,
            );
        }
    };
}

/// Bridge from a typed Zig ticket-key callback to the BoringSSL C ABI.
/// The user context is stored in ex-data.
/// The raw EVP_CIPHER_CTX and HMAC_CTX are wrapped in typed references.
fn ticket_key_callback_bridge(
    comptime ContextType: type,
    comptime callback: TicketKeyCallback(ContextType),
) type {
    return struct {
        var index_slot: c_int = -1;
        var index_mutex: std.atomic.Mutex = .unlocked;

        fn index() BoringError!ex_data_mod.Index(Context, ContextType) {
            spin_lock(&index_mutex);
            defer index_mutex.unlock();

            if (index_slot >= 0) {
                return ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            }

            const new_index = try context_ex_new_index(ContextType);
            index_slot = new_index.asRaw();

            return new_index;
        }

        fn raw_callback(
            raw_ssl: ?*sys.SSL,
            key_name: [*c]u8,
            iv: [*c]u8,
            evp_ctx: ?*sys.EVP_CIPHER_CTX,
            hmac_ctx: ?*sys.HMAC_CTX,
            encrypt: c_int,
        ) callconv(.c) c_int {
            const ssl = raw_ssl orelse return -1;
            if (index_slot < 0) return -1;
            if (key_name == null) return -1;
            if (iv == null) return -1;
            if (evp_ctx == null) return -1;
            if (hmac_ctx == null) return -1;

            const raw_ctx = sys.SSL_get_SSL_CTX(ssl) orelse return -1;
            const index_value = ex_data_mod.Index(Context, ContextType).fromRaw(index_slot);
            const context = context_ex_data(raw_ctx, ContextType, index_value) orelse {
                return -1;
            };

            const key_name_slice = key_name[0..sys.SSL_TICKET_KEY_NAME_LEN];
            const iv_slice = iv[0..sys.EVP_MAX_IV_LENGTH];

            if (encrypt == 1) {
                @memset(key_name_slice, 0);
                @memset(iv_slice, 0);
            }

            var cipher_ctx_ref = symm_mod.CipherCtxRef{ .ptr = evp_ctx.? };
            var hmac_ctx_ref = hmac_mod.HmacCtxRef{ .ptr = hmac_ctx.? };
            var ssl_ref = SslRef.fromRaw(ssl);

            return @intFromEnum(callback(
                context,
                &ssl_ref,
                key_name_slice,
                iv_slice,
                &cipher_ctx_ref,
                &hmac_ctx_ref,
                encrypt == 1,
            ));
        }
    };
}

comptime {
    std.debug.assert(MaxAlpnWireBytes >= 256);
    std.debug.assert(MaxBioPairCapacityBytes >= 4096);
    std.debug.assert(MaxClientHelloBytes >= MaxClientHelloExtensionBytes);
    std.debug.assert(MaxClientHelloExtensionBytes >= 4096);
    std.debug.assert(MaxSingleAlpnProtocolBytes >= 1);
    std.debug.assert(MaxSessionIdBytes >= 32);
    std.debug.assert(MaxSessionBytes >= 16 * 1024);
    std.debug.assert(MaxSessionCacheEntries >= 16);
    std.debug.assert(@intFromEnum(PrivateKeyResult.success) == 0);
    std.debug.assert(@intFromEnum(PrivateKeyResult.retry) == 1);
    std.debug.assert(@intFromEnum(PrivateKeyResult.failure) == 2);
    std.debug.assert(@intFromEnum(SelectCertificateResult.retry) == 0);
    std.debug.assert(@intFromEnum(SelectCertificateResult.success) == 1);
    std.debug.assert(@intFromEnum(SelectCertificateResult.failure) == -1);
    std.debug.assert(@intFromEnum(SelectCertificateResult.disableEch) == -2);
    std.debug.assert(@intFromEnum(VerifyResult.ok) == 0);
    std.debug.assert(@intFromEnum(VerifyResult.invalid) == 1);
    std.debug.assert(@intFromEnum(VerifyResult.retry) == 2);
    std.debug.assert(SslAlert.internalError.raw() == sys.SSL_AD_INTERNAL_ERROR);
}
