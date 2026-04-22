const std = @import("std");

const dh_mod = @import("dh.zig");
const internal = @import("internal.zig");
const ssl_mod = @import("ssl.zig");
const version_mod = @import("version.zig");
const BoringError = internal.BoringError;

const Ffdhe2048Pem =
    \\-----BEGIN DH PARAMETERS-----
    \\MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
    \\+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
    \\87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
    \\YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
    \\7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
    \\ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
    \\-----END DH PARAMETERS-----
    \\
;

fn base_context(method: ssl_mod.Method) BoringError!ssl_mod.ContextBuilder {
    var builder = try ssl_mod.ContextBuilder.init(method);
    errdefer builder.deinit();

    var options = ssl_mod.Options.none;
    options = options.combine(ssl_mod.Options.noTicket);
    options = options.combine(ssl_mod.Options.noQueryMtu);
    _ = builder.setOptions(options);

    var mode = ssl_mod.Mode.acceptMovingWriteBuffer;
    mode = mode.combine(ssl_mod.Mode.enablePartialWrite);
    _ = builder.setMode(mode);

    return builder;
}

fn setup_verify(builder: *ssl_mod.ContextBuilder) void {
    builder.setVerify(ssl_mod.VerifyMode.peer);
}

fn is_ip_address(domain: []const u8) bool {
    std.debug.assert(domain.len > 0);

    var octets: [16]u8 = undefined;
    _ = parse_ip_address(domain, &octets) catch return false;
    return true;
}

fn parse_ip_address(domain: []const u8, octets: *[16]u8) BoringError!usize {
    std.debug.assert(domain.len > 0);

    if (std.Io.net.IpAddress.parseIp4(domain, 0)) |addr| {
        switch (addr) {
            .ip4 => |ip4| {
                @memcpy(octets[0..4], &ip4.bytes);
                return 4;
            },
            .ip6 => unreachable,
        }
    } else |_| {}

    if (std.Io.net.IpAddress.parseIp6(domain, 0)) |addr| {
        switch (addr) {
            .ip4 => unreachable,
            .ip6 => |ip6| {
                @memcpy(octets[0..16], &ip6.bytes);
                return 16;
            },
        }
    } else |_| {}

    return error.InvalidArgument;
}

pub const SslConnector = struct {
    context: ssl_mod.Context,

    pub fn builder(method: ssl_mod.Method) BoringError!SslConnectorBuilder {
        var ctx = try base_context(method);
        errdefer ctx.deinit();

        ctx.setVerify(ssl_mod.VerifyMode.peer);
        try ctx.setDefaultVerifyPaths();
        try ctx.setCipherList(
            "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK",
        );

        return SslConnectorBuilder{ .builder = ctx };
    }

    pub fn deinit(self: *SslConnector) void {
        self.context.deinit();
    }

    pub fn connect(
        self: *SslConnector,
        domain: [:0]const u8,
        fd: c_int,
    ) BoringError!ssl_mod.Ssl {
        std.debug.assert(domain.len > 0);
        std.debug.assert(fd >= 0);

        var config = try self.configure();
        return config.intoSsl(domain, fd);
    }

    pub fn configure(self: *const SslConnector) BoringError!ConnectConfiguration {
        std.debug.assert(self.context.ptr != null);

        var ssl = try self.context.createSsl();
        errdefer ssl.deinit();

        return ConnectConfiguration{
            .ssl = ssl,
            .sni = true,
            .verify_hostname = true,
        };
    }
};

pub const SslConnectorBuilder = struct {
    builder: ssl_mod.ContextBuilder,

    pub fn deinit(self: *SslConnectorBuilder) void {
        self.builder.deinit();
    }

    pub fn build(self: *SslConnectorBuilder) SslConnector {
        return SslConnector{ .context = self.builder.build() };
    }

    pub fn contextBuilder(self: *SslConnectorBuilder) *ssl_mod.ContextBuilder {
        return &self.builder;
    }
};

pub const ConnectConfiguration = struct {
    ssl: ssl_mod.Ssl,
    sni: bool,
    verify_hostname: bool,

    pub fn deinit(self: *ConnectConfiguration) void {
        self.ssl.deinit();
    }

    pub fn setUseServerNameIndication(self: *ConnectConfiguration, use_sni: bool) void {
        self.sni = use_sni;
    }

    pub fn setVerifyHostname(self: *ConnectConfiguration, verify: bool) void {
        self.verify_hostname = verify;
    }

    pub fn intoSsl(
        self: *ConnectConfiguration,
        domain: [:0]const u8,
        fd: c_int,
    ) BoringError!ssl_mod.Ssl {
        std.debug.assert(domain.len > 0);
        std.debug.assert(fd >= 0);

        if (self.sni) {
            if (!is_ip_address(domain)) {
                try self.ssl.setHostname(domain);
            }
        }

        if (self.verify_hostname) {
            try self.ssl.setVerifyHostname(domain);
        }

        try self.ssl.setFd(fd);
        self.ssl.setConnectState();

        const result = self.ssl;
        self.ssl.ptr = null;
        return result;
    }
};

pub const SslAcceptor = struct {
    context: ssl_mod.Context,

    pub fn mozillaIntermediate(method: ssl_mod.Method) BoringError!SslAcceptorBuilder {
        var ctx = try base_context(method);
        errdefer ctx.deinit();

        var options = ssl_mod.Options.none;
        options = options.combine(ssl_mod.Options.cipherServerPreference);
        options = options.combine(ssl_mod.Options.noTlsV1_3);
        _ = ctx.setOptions(options);

        var dh = try dh_mod.Dh.paramsFromPem(Ffdhe2048Pem);
        defer dh.deinit();
        try ctx.setTmpDh(&dh);

        try ctx.setCipherList(
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" ++
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" ++
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" ++
                "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:" ++
                "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:" ++
                "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:" ++
                "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:" ++
                "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:" ++
                "DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:" ++
                "DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:" ++
                "ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:" ++
                "EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:" ++
                "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:" ++
                "DES-CBC3-SHA:!DSS",
        );

        return SslAcceptorBuilder{ .builder = ctx };
    }

    pub fn mozillaModern(method: ssl_mod.Method) BoringError!SslAcceptorBuilder {
        var ctx = try base_context(method);
        errdefer ctx.deinit();

        var options = ssl_mod.Options.none;
        options = options.combine(ssl_mod.Options.cipherServerPreference);
        options = options.combine(ssl_mod.Options.noTlsV1);
        options = options.combine(ssl_mod.Options.noTlsV1_1);
        options = options.combine(ssl_mod.Options.noTlsV1_3);
        _ = ctx.setOptions(options);

        try ctx.setCipherList(
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" ++
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" ++
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" ++
                "ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:" ++
                "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256",
        );

        return SslAcceptorBuilder{ .builder = ctx };
    }

    pub fn mozillaIntermediateV5(method: ssl_mod.Method) BoringError!SslAcceptorBuilder {
        var ctx = try base_context(method);
        errdefer ctx.deinit();

        var options = ssl_mod.Options.none;
        options = options.combine(ssl_mod.Options.noTlsV1);
        options = options.combine(ssl_mod.Options.noTlsV1_1);
        _ = ctx.setOptions(options);

        var dh = try dh_mod.Dh.paramsFromPem(Ffdhe2048Pem);
        defer dh.deinit();
        try ctx.setTmpDh(&dh);

        try ctx.setCipherList(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" ++
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" ++
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" ++
                "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        );

        return SslAcceptorBuilder{ .builder = ctx };
    }

    pub fn deinit(self: *SslAcceptor) void {
        self.context.deinit();
    }

    pub fn accept(self: *const SslAcceptor, fd: c_int) BoringError!ssl_mod.Ssl {
        std.debug.assert(fd >= 0);

        var ssl = try self.context.createSsl();
        errdefer ssl.deinit();

        try ssl.setFd(fd);
        ssl.setAcceptState();

        return ssl;
    }
};

pub const SslAcceptorBuilder = struct {
    builder: ssl_mod.ContextBuilder,

    pub fn deinit(self: *SslAcceptorBuilder) void {
        self.builder.deinit();
    }

    pub fn build(self: *SslAcceptorBuilder) SslAcceptor {
        return SslAcceptor{ .context = self.builder.build() };
    }

    pub fn contextBuilder(self: *SslAcceptorBuilder) *ssl_mod.ContextBuilder {
        return &self.builder;
    }
};

comptime {
    std.debug.assert(Ffdhe2048Pem.len > 0);
}
