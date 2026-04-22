const std = @import("std");

const async_mod = @import("async/async.zig");
const internal = @import("internal.zig");
const ssl_mod = @import("ssl.zig");
const BoringError = internal.BoringError;

pub const TcpBufferSize: usize = async_mod.BioStreamBufferSize;
pub const ConnectAddressError = BoringError || std.Io.net.IpAddress.ConnectError;
pub const ConnectError =
    ConnectAddressError ||
    std.Io.net.HostName.ConnectError ||
    std.Io.net.HostName.ValidateError;

pub const HttpsConnector = struct {
    tls_connector: async_mod.AsyncTlsConnector,

    pub fn init(method: ssl_mod.Method) BoringError!HttpsConnector {
        var builder = try ssl_mod.ContextBuilder.init(method);
        errdefer builder.deinit();

        builder.setVerify(ssl_mod.VerifyMode.peer);
        try builder.setDefaultVerifyPaths();
        builder.setServerAlpnH2Http11();

        return initWithBuilder(&builder);
    }

    pub fn initWithBuilder(builder: *ssl_mod.ContextBuilder) HttpsConnector {
        return .{ .tls_connector = async_mod.AsyncTlsConnector.initWithBuilder(builder) };
    }

    pub fn deinit(self: *HttpsConnector) void {
        self.tls_connector.deinit();
    }

    pub fn context(self: *HttpsConnector) *ssl_mod.Context {
        return self.tls_connector.context();
    }

    pub fn connect(
        self: *HttpsConnector,
        target: *HttpsConnection,
        io: std.Io,
        host: [:0]const u8,
        port: u16,
    ) ConnectError!void {
        const tcp_stream = try connect_tcp(io, host, port);
        try self.connectStream(target, io, tcp_stream, host);
    }

    pub fn connectAddress(
        self: *HttpsConnector,
        target: *HttpsConnection,
        io: std.Io,
        address: *const std.Io.net.IpAddress,
        host: [:0]const u8,
    ) ConnectAddressError!void {
        const tcp_stream = try address.connect(io, .{ .mode = .stream });
        try self.connectStream(target, io, tcp_stream, host);
    }

    pub fn connectStream(
        self: *HttpsConnector,
        target: *HttpsConnection,
        io: std.Io,
        tcp_stream: std.Io.net.Stream,
        host: [:0]const u8,
    ) BoringError!void {
        try internal.require_non_empty(host);
        target.init_tcp(io, tcp_stream);
        errdefer target.deinit(io);

        target.tls_stream = try self.tls_connector.connect(
            io,
            host,
            &target.tcp_reader.interface,
            &target.tcp_writer.interface,
        );
        target.state = .tls;
    }
};

pub const HttpsConnection = struct {
    state: State = .empty,
    tcp_stream: std.Io.net.Stream = undefined,
    tcp_reader: std.Io.net.Stream.Reader = undefined,
    tcp_writer: std.Io.net.Stream.Writer = undefined,
    tls_stream: async_mod.AsyncTlsStream = undefined,
    tcp_reader_buffer: [TcpBufferSize]u8 = undefined,
    tcp_writer_buffer: [TcpBufferSize]u8 = undefined,

    const State = enum {
        empty,
        tcp,
        tls,
    };

    pub fn deinit(self: *HttpsConnection, io: std.Io) void {
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

    pub fn read(self: *HttpsConnection, output: []u8) BoringError!usize {
        std.debug.assert(self.state == .tls);
        return self.tls_stream.read(output);
    }

    pub fn write(self: *HttpsConnection, input: []const u8) BoringError!usize {
        std.debug.assert(self.state == .tls);
        return self.tls_stream.write(input);
    }

    pub fn shutdown(self: *HttpsConnection) BoringError!void {
        std.debug.assert(self.state == .tls);
        try self.tls_stream.shutdown();
    }

    pub fn selectedAlpn(self: *const HttpsConnection) ?[]const u8 {
        if (self.state != .tls) return null;
        return self.tls_stream.selectedAlpn();
    }

    pub fn sslRef(self: *HttpsConnection) BoringError!ssl_mod.SslRef {
        std.debug.assert(self.state == .tls);
        return self.tls_stream.sslRef();
    }

    pub fn isHandshakeComplete(self: *const HttpsConnection) bool {
        if (self.state != .tls) return false;
        return self.tls_stream.isHandshakeComplete();
    }

    pub fn reader(self: *HttpsConnection, buffer: []u8) async_mod.AsyncTlsStream.Reader {
        std.debug.assert(self.state == .tls);
        return self.tls_stream.reader(buffer);
    }

    pub fn writer(self: *HttpsConnection, buffer: []u8) async_mod.AsyncTlsStream.Writer {
        std.debug.assert(self.state == .tls);
        return self.tls_stream.writer(buffer);
    }

    fn init_tcp(
        self: *HttpsConnection,
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
};

fn connect_tcp(io: std.Io, host: [:0]const u8, port: u16) ConnectError!std.Io.net.Stream {
    try internal.require_non_empty(host);

    if (std.Io.net.IpAddress.parse(host, port)) |address| {
        return address.connect(io, .{ .mode = .stream });
    } else |_| {}

    const host_name = try std.Io.net.HostName.init(host);
    return host_name.connect(io, port, .{ .mode = .stream });
}
