const std = @import("std");
const boring = @import("boring");
const http2 = @import("http2");

pub const AlpnProtocol = "h2";
pub const TcpBufferSize: usize = boring.async.BioStreamBufferSize;
pub const TlsBufferSize: usize = boring.async.BioStreamBufferSize;

pub const ServeConnectionOptions = struct {
    dispatcher: http2.RequestDispatcher,
    stream_storage: ?*http2.Connection.StreamStorage = null,
};

pub const Acceptor = struct {
    tls_acceptor: boring.async.AsyncTlsAcceptor,

    pub fn init(method: boring.ssl.Method) boring.BoringError!Acceptor {
        var builder = try boring.ssl.ContextBuilder.init(method);
        errdefer builder.deinit();

        return initWithBuilder(&builder);
    }

    pub fn initWithBuilder(builder: *boring.ssl.ContextBuilder) Acceptor {
        builder.setServerAlpnH2Http11();
        return .{ .tls_acceptor = boring.async.AsyncTlsAcceptor.initWithBuilder(builder) };
    }

    pub fn deinit(self: *Acceptor) void {
        self.tls_acceptor.deinit();
    }

    pub fn context(self: *Acceptor) *boring.ssl.Context {
        return self.tls_acceptor.context();
    }

    pub fn accept(
        self: *Acceptor,
        target: *Connection,
        io: std.Io,
        tcp_stream: std.Io.net.Stream,
    ) !void {
        target.init_tcp(io, tcp_stream);
        errdefer target.deinit(io);

        target.tls_stream = try self.tls_acceptor.accept(
            io,
            &target.tcp_reader.interface,
            &target.tcp_writer.interface,
        );
        target.state = .tls;
        target.init_http2_interfaces();

        try require_h2(target.selectedAlpn());
    }
};

pub const Connection = struct {
    state: State = .empty,
    tcp_stream: std.Io.net.Stream = undefined,
    tcp_reader: std.Io.net.Stream.Reader = undefined,
    tcp_writer: std.Io.net.Stream.Writer = undefined,
    tls_stream: boring.async.AsyncTlsStream = undefined,
    tls_reader: boring.async.AsyncTlsStream.Reader = undefined,
    tls_writer: boring.async.AsyncTlsStream.Writer = undefined,
    tcp_reader_buffer: [TcpBufferSize]u8 = undefined,
    tcp_writer_buffer: [TcpBufferSize]u8 = undefined,
    tls_reader_buffer: [TlsBufferSize]u8 = undefined,
    tls_writer_buffer: [TlsBufferSize]u8 = undefined,

    const State = enum {
        empty,
        tcp,
        tls,
    };

    pub fn deinit(self: *Connection, io: std.Io) void {
        switch (self.state) {
            .empty => {},
            .tcp => self.tcp_stream.close(io),
            .tls => {
                self.tls_stream.deinit();
                self.tcp_stream.close(io);
            },
        }

        self.state = .empty;
    }

    pub fn serve(
        self: *Connection,
        allocator: std.mem.Allocator,
        options: ServeConnectionOptions,
    ) !u32 {
        std.debug.assert(self.state == .tls);

        return serveHttp2Connection(allocator, self.reader(), self.writer(), options);
    }

    pub fn read(self: *Connection, output: []u8) boring.BoringError!usize {
        std.debug.assert(self.state == .tls);
        return self.tls_stream.read(output);
    }

    pub fn write(self: *Connection, input: []const u8) boring.BoringError!usize {
        std.debug.assert(self.state == .tls);
        return self.tls_stream.write(input);
    }

    pub fn shutdown(self: *Connection) boring.BoringError!void {
        std.debug.assert(self.state == .tls);
        try self.tls_stream.shutdown();
    }

    pub fn selectedAlpn(self: *const Connection) ?[]const u8 {
        if (self.state != .tls) return null;
        return self.tls_stream.selectedAlpn();
    }

    pub fn sslRef(self: *Connection) boring.BoringError!boring.ssl.SslRef {
        std.debug.assert(self.state == .tls);
        return self.tls_stream.sslRef();
    }

    pub fn isHandshakeComplete(self: *const Connection) bool {
        if (self.state != .tls) return false;
        return self.tls_stream.isHandshakeComplete();
    }

    pub fn reader(self: *Connection) *std.Io.Reader {
        std.debug.assert(self.state == .tls);
        return &self.tls_reader.interface;
    }

    pub fn writer(self: *Connection) *std.Io.Writer {
        std.debug.assert(self.state == .tls);
        return &self.tls_writer.interface;
    }

    fn init_tcp(
        self: *Connection,
        io: std.Io,
        tcp_stream: std.Io.net.Stream,
    ) void {
        std.debug.assert(self.state == .empty);

        self.* = .{};
        self.tcp_stream = tcp_stream;
        self.tcp_reader = tcp_stream.reader(io, &self.tcp_reader_buffer);
        self.tcp_writer = tcp_stream.writer(io, &self.tcp_writer_buffer);
        self.state = .tcp;
    }

    fn init_http2_interfaces(self: *Connection) void {
        std.debug.assert(self.state == .tls);

        self.tls_reader = self.tls_stream.reader(&self.tls_reader_buffer);
        self.tls_writer = self.tls_stream.writer(&self.tls_writer_buffer);
    }
};

fn serveHttp2Connection(
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: ServeConnectionOptions,
) !u32 {
    if (@hasDecl(http2, "serveConnection")) {
        return http2.serveConnection(
            allocator,
            reader,
            writer,
            .{
                .dispatcher = options.dispatcher,
                .stream_storage = options.stream_storage,
            },
        );
    }

    var connection: http2.Connection = undefined;
    if (options.stream_storage) |stream_storage| {
        try http2.Connection.initServerInPlace(
            &connection,
            stream_storage,
            allocator,
            reader,
            writer,
        );
    } else {
        connection = try http2.Connection.init(allocator, reader, writer, true);
    }
    defer connection.deinit();

    connection.bindRequestDispatcher(options.dispatcher);
    try connection.handle_connection();
    return connection.takeCompletedResponses();
}

pub fn serveConnection(
    acceptor: *Acceptor,
    allocator: std.mem.Allocator,
    io: std.Io,
    tcp_stream: std.Io.net.Stream,
    options: ServeConnectionOptions,
) !u32 {
    var connection: Connection = .{};
    defer connection.deinit(io);

    try acceptor.accept(&connection, io, tcp_stream);
    return connection.serve(allocator, options);
}

pub fn isHttp2Alpn(selected_alpn: ?[]const u8) bool {
    if (selected_alpn) |protocol| {
        return std.mem.eql(u8, protocol, AlpnProtocol);
    }

    return false;
}

fn require_h2(selected_alpn: ?[]const u8) error{NoApplicationProtocol}!void {
    if (isHttp2Alpn(selected_alpn)) return;
    return error.NoApplicationProtocol;
}

comptime {
    std.debug.assert(AlpnProtocol.len == 2);
    std.debug.assert(TcpBufferSize >= 16 * 1024);
    std.debug.assert(TlsBufferSize >= 16 * 1024);
}
