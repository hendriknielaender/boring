const std = @import("std");
const boring = @import("boring");
const c = std.c;

const cert_pem = @embedFile("cert.pem");
const key_pem = @embedFile("key.pem");
const root_ca_pem = @embedFile("root-ca.pem");

const AF_INET: c_uint = c.AF.INET;
const SOCK_STREAM: c_uint = c.SOCK.STREAM;
const SOL_SOCKET: c_int = c.SOL.SOCKET;
const SO_REUSEADDR: c_uint = c.SO.REUSEADDR;

pub fn socket_addr(port: u16) c.sockaddr.in {
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
}

pub fn socket_addr_any(port: u16) c.sockaddr.in {
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = 0,
    };
}

pub fn errno_check(result: c_int) !void {
    if (result < 0) return error.SocketError;
}

pub const IoFn = *const fn (*boring.ssl.Ssl, c_int) void;
pub const SslFn = *const fn (*boring.ssl.Ssl) void;
pub const SslContextFn = *const fn (?*anyopaque, *boring.ssl.Ssl) void;

pub const Server = struct {
    thread: std.Thread,
    port: u16,

    pub fn builder() !Builder {
        return builderWithMethod(boring.ssl.Method.tls());
    }

    pub fn builderWithMethod(method: boring.ssl.Method) !Builder {
        var ctx_builder = try boring.ssl.ContextBuilder.init(method);
        errdefer ctx_builder.deinit();

        var cert = try boring.x509.X509.fromPem(cert_pem);
        defer cert.deinit();
        var key = try boring.pkey.PKey.fromPem(key_pem);
        defer key.deinit();

        try ctx_builder.useCertificate(&cert);
        try ctx_builder.usePrivateKey(&key);

        return .{
            .ctx_builder = ctx_builder,
            .should_error = false,
        };
    }

    pub fn deinit(self: *Server) void {
        self.thread.join();
    }

    pub fn client(self: *const Server) !ClientBuilder {
        return self.clientWithMethod(boring.ssl.Method.tls());
    }

    pub fn clientWithMethod(self: *const Server, method: boring.ssl.Method) !ClientBuilder {
        var ctx_builder = try boring.ssl.ContextBuilder.init(method);
        errdefer ctx_builder.deinit();

        return .{
            .ctx_builder = ctx_builder,
            .port = self.port,
        };
    }

    pub fn clientWithRootCa(self: *const Server) !ClientBuilder {
        var client_builder = try self.client();
        var ca = try boring.x509.X509.fromPem(root_ca_pem);
        defer ca.deinit();
        var store_builder = try boring.x509_store.X509StoreBuilder.init();
        defer store_builder.deinit();
        try store_builder.addCert(&ca);
        var store = store_builder.build();
        defer store.deinit();
        client_builder.ctx_builder.setVerify(boring.ssl.VerifyMode.peer);
        try client_builder.ctx_builder.setCertStore(&store);
        return client_builder;
    }

    pub fn connectFd(self: *const Server) !c_int {
        const fd = c.socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return error.SocketError;
        errdefer _ = c.close(fd);

        var addr = socket_addr(self.port);
        try errno_check(c.connect(fd, @ptrCast(&addr), @sizeOf(c.sockaddr.in)));

        return fd;
    }
};

pub const Builder = struct {
    ctx_builder: boring.ssl.ContextBuilder,
    should_error: bool,
    expected_connections_count: usize = 1,
    io_fn: ?IoFn = null,
    ssl_fn: ?SslFn = null,
    ssl_context_fn: ?SslContextFn = null,
    ssl_context: ?*anyopaque = null,

    pub fn deinit(self: *Builder) void {
        self.ctx_builder.deinit();
    }

    pub fn ctx(self: *Builder) *boring.ssl.ContextBuilder {
        return &self.ctx_builder;
    }

    pub fn shouldError(self: *Builder) void {
        self.should_error = true;
    }

    pub fn ioCb(self: *Builder, cb: IoFn) void {
        self.io_fn = cb;
    }

    pub fn sslCb(self: *Builder, cb: SslFn) void {
        self.ssl_fn = cb;
    }

    pub fn sslCbWithContext(self: *Builder, context: ?*anyopaque, cb: SslContextFn) void {
        self.ssl_context = context;
        self.ssl_context_fn = cb;
    }

    pub fn expectedConnectionsCount(self: *Builder, count: usize) void {
        self.expected_connections_count = count;
    }

    pub fn build(self: *Builder) !Server {
        var context = self.ctx_builder.build();
        errdefer context.deinit();

        const fd = c.socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return error.SocketError;
        defer _ = c.close(fd);

        const reuse: c_int = 1;
        _ = c.setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            @sizeOf(c_int),
        );

        var bind_addr = socket_addr_any(0);
        try errno_check(c.bind(fd, @ptrCast(&bind_addr), @sizeOf(c.sockaddr.in)));

        var addr_len: c.socklen_t = @sizeOf(c.sockaddr.in);
        try errno_check(c.getsockname(fd, @ptrCast(&bind_addr), &addr_len));
        const port = std.mem.bigToNative(u16, bind_addr.port);

        try errno_check(c.listen(fd, 1));

        const listen_fd = c.dup(fd);
        const thread = try std.Thread.spawn(.{}, server_thread, .{
            context,
            listen_fd,
            self.should_error,
            self.expected_connections_count,
            self.io_fn,
            self.ssl_fn,
            self.ssl_context_fn,
            self.ssl_context,
        });

        return .{
            .thread = thread,
            .port = port,
        };
    }
};

fn server_thread(
    context: boring.ssl.Context,
    listen_fd: c_int,
    should_error: bool,
    expected_connections_count: usize,
    io_fn: ?IoFn,
    ssl_fn: ?SslFn,
    ssl_context_fn: ?SslContextFn,
    ssl_context: ?*anyopaque,
) void {
    var ctx = context;
    defer ctx.deinit();
    defer _ = c.close(listen_fd);

    var remaining: usize = expected_connections_count;
    while (remaining > 0) {
        var client_addr: c.sockaddr.in = undefined;
        var addr_len: c.socklen_t = @sizeOf(c.sockaddr.in);
        const conn_fd = c.accept(listen_fd, @ptrCast(&client_addr), &addr_len);
        if (conn_fd < 0) return;

        var ssl = context.createSsl() catch {
            _ = c.close(conn_fd);
            return;
        };
        defer ssl.deinit();

        if (ssl_fn) |cb| cb(&ssl);
        if (ssl_context_fn) |cb| cb(ssl_context, &ssl);

        ssl.setFd(conn_fd) catch {
            _ = c.close(conn_fd);
            return;
        };
        ssl.setAcceptState();

        while (true) {
            const result = ssl.doHandshake();
            if (result) {
                break;
            } else |err| switch (err) {
                error.WantRead,
                error.WantWrite,
                error.WantX509Lookup,
                error.PendingSession,
                error.PendingCertificate,
                error.WantPrivateKeyOperation,
                error.WantCertificateVerify,
                error.PendingTicket,
                => continue,
                else => {
                    _ = c.close(conn_fd);
                    return;
                },
            }
        }

        if (!should_error) {
            var ready: [1]u8 = .{0};
            _ = ssl.write(&ready) catch {};

            if (io_fn) |cb| cb(&ssl, conn_fd);
        }

        _ = c.close(conn_fd);
        remaining -= 1;
    }
}

pub const Client = struct {
    ctx: boring.ssl.Context,
    port: u16,

    pub fn deinit(self: *Client) void {
        self.ctx.deinit();
    }

    pub fn builder(self: *Client) !SslBuilder {
        var ssl = try self.ctx.createSsl();
        errdefer ssl.deinit();

        const fd = c.socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return error.SocketError;
        errdefer _ = c.close(fd);

        var addr = socket_addr(self.port);
        try errno_check(c.connect(fd, @ptrCast(&addr), @sizeOf(c.sockaddr.in)));

        try ssl.setFd(fd);
        ssl.setConnectState();

        return .{
            .ssl = ssl,
            .fd = fd,
        };
    }
};

pub const SslBuilder = struct {
    ssl: boring.ssl.Ssl,
    fd: c_int,

    pub fn deinit(self: *SslBuilder) void {
        self.ssl.deinit();
        _ = c.close(self.fd);
    }

    pub fn sslPtr(self: *SslBuilder) *boring.ssl.Ssl {
        return &self.ssl;
    }

    pub fn connect(self: *SslBuilder) !ClientStream {
        while (true) {
            const result = self.ssl.doHandshake();
            if (result) {
                break;
            } else |err| switch (err) {
                error.WantRead,
                error.WantWrite,
                error.WantX509Lookup,
                error.PendingSession,
                error.PendingCertificate,
                error.WantPrivateKeyOperation,
                error.WantCertificateVerify,
                error.PendingTicket,
                => continue,
                else => return err,
            }
        }

        var buf: [1]u8 = undefined;
        _ = try self.ssl.read(&buf);

        const ssl = self.ssl;
        const fd = self.fd;
        self.ssl.ptr = null;
        self.fd = -1;

        return .{
            .ssl = ssl,
            .fd = fd,
        };
    }
};

pub const ClientStream = struct {
    ssl: boring.ssl.Ssl,
    fd: c_int,

    pub fn deinit(self: *ClientStream) void {
        self.ssl.deinit();
        _ = c.close(self.fd);
    }

    pub fn read(self: *ClientStream, buf: []u8) !usize {
        return self.ssl.read(buf);
    }

    pub fn write(self: *ClientStream, buf: []const u8) !usize {
        return self.ssl.write(buf);
    }

    pub fn sslRef(self: *ClientStream) !boring.ssl.SslRef {
        return self.ssl.ref();
    }

    pub fn shutdown(self: *ClientStream) !boring.ssl.ShutdownResult {
        return self.ssl.shutdown();
    }
};

pub const ClientBuilder = struct {
    ctx_builder: boring.ssl.ContextBuilder,
    port: u16,

    pub fn deinit(self: *ClientBuilder) void {
        self.ctx_builder.deinit();
    }

    pub fn ctx(self: *ClientBuilder) *boring.ssl.ContextBuilder {
        return &self.ctx_builder;
    }

    pub fn build(self: *ClientBuilder) !Client {
        var context = self.ctx_builder.build();
        errdefer context.deinit();

        return .{
            .ctx = context,
            .port = self.port,
        };
    }

    pub fn connect(self: *ClientBuilder) !ClientStream {
        var client = try self.build();
        defer client.deinit();

        var ssl_builder = try client.builder();
        defer ssl_builder.deinit();

        return try ssl_builder.connect();
    }
};
