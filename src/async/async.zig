const std = @import("std");
const sys = @import("boringssl");

const internal = @import("../internal.zig");
const ssl_mod = @import("../ssl.zig");
const BoringError = internal.BoringError;

pub const MaxTlsRecordSize: u32 = 16 * 1024 + 5;
pub const MaxHandshakeIterations: u32 = 64;
pub const MaxShutdownIterations: u32 = 16;
pub const MaxWriterDataSlices: u32 = 8;
pub const BioStreamBufferSize: u32 = MaxTlsRecordSize;

const EmptyContext = struct {};

const TlsRetryState = enum {
    start,
    drain,
};

pub const AsyncTlsConnector = struct {
    tls_context: ssl_mod.Context,

    pub fn init(method: ssl_mod.Method) BoringError!AsyncTlsConnector {
        var builder = try ssl_mod.ContextBuilder.init(method);
        errdefer builder.deinit();

        builder.setVerify(ssl_mod.VerifyMode.none);
        builder.setServerAlpnH2Http11();

        return .{ .tls_context = builder.build() };
    }

    pub fn initWithBuilder(builder: *ssl_mod.ContextBuilder) AsyncTlsConnector {
        return .{ .tls_context = builder.build() };
    }

    pub fn deinit(self: *AsyncTlsConnector) void {
        self.tls_context.deinit();
    }

    pub fn context(self: *AsyncTlsConnector) *ssl_mod.Context {
        return &self.tls_context;
    }

    pub fn connect(
        self: *AsyncTlsConnector,
        io: std.Io,
        host: [:0]const u8,
        stream_reader: *std.Io.Reader,
        stream_writer: *std.Io.Writer,
    ) BoringError!AsyncTlsStream {
        var ssl = try self.tls_context.createSsl();
        errdefer ssl.deinit();

        try ssl.setConnectHostname(host);

        var bio = try AsyncBio.init(io, stream_reader, stream_writer);
        errdefer bio.deinit();

        ssl.setBio(bio.raw());
        bio.releaseOwnership();

        ssl.setConnectState();

        var stream = AsyncTlsStream{
            .ssl = ssl,
            .bio = bio,
        };
        try stream.doHandshake();

        return stream;
    }
};

pub const AsyncTlsAcceptor = struct {
    tls_context: ssl_mod.Context,

    pub fn init(method: ssl_mod.Method) BoringError!AsyncTlsAcceptor {
        var builder = try ssl_mod.ContextBuilder.init(method);
        errdefer builder.deinit();

        return .{ .tls_context = builder.build() };
    }

    pub fn initWithBuilder(builder: *ssl_mod.ContextBuilder) AsyncTlsAcceptor {
        return .{ .tls_context = builder.build() };
    }

    pub fn deinit(self: *AsyncTlsAcceptor) void {
        self.tls_context.deinit();
    }

    pub fn context(self: *AsyncTlsAcceptor) *ssl_mod.Context {
        return &self.tls_context;
    }

    pub fn accept(
        self: *AsyncTlsAcceptor,
        io: std.Io,
        stream_reader: *std.Io.Reader,
        stream_writer: *std.Io.Writer,
    ) BoringError!AsyncTlsStream {
        var ssl = try self.tls_context.createSsl();
        errdefer ssl.deinit();

        var bio = try AsyncBio.init(io, stream_reader, stream_writer);
        errdefer bio.deinit();

        ssl.setBio(bio.raw());
        bio.releaseOwnership();

        ssl.setAcceptState();

        var stream = AsyncTlsStream{
            .ssl = ssl,
            .bio = bio,
        };
        try stream.doHandshake();

        return stream;
    }
};

pub const AsyncTlsStream = struct {
    ssl: ssl_mod.Ssl,
    bio: AsyncBio,

    pub fn deinit(self: *AsyncTlsStream) void {
        self.ssl.deinit();
        self.bio.deinit();
    }

    pub fn doHandshake(self: *AsyncTlsStream) BoringError!void {
        var context: EmptyContext = .{};
        return self.tls_retry(
            EmptyContext,
            &context,
            void,
            MaxHandshakeIterations,
            tls_handshake_attempt,
        );
    }

    pub fn read(self: *AsyncTlsStream, output: []u8) BoringError!usize {
        var context = output;
        return self.tls_retry(
            []u8,
            &context,
            usize,
            MaxHandshakeIterations,
            tls_read_attempt,
        );
    }

    pub fn write(self: *AsyncTlsStream, input: []const u8) BoringError!usize {
        var context = input;
        return self.tls_retry(
            []const u8,
            &context,
            usize,
            MaxHandshakeIterations,
            tls_write_attempt,
        );
    }

    pub fn shutdown(self: *AsyncTlsStream) BoringError!void {
        var iterations: u32 = 0;

        state: switch (TlsRetryState.start) {
            .start => {
                if (iterations >= MaxShutdownIterations) return error.BoringSSL;
                iterations += 1;

                self.bio.sync_state();

                const ssl_ptr = try self.ssl.raw();
                const result = sys.SSL_shutdown(ssl_ptr);
                if (result > 0) return;
                if (result == 0) continue :state .drain;

                const code = sys.SSL_get_error(ssl_ptr, result);
                if (code == sys.SSL_ERROR_WANT_READ) continue :state .drain;
                if (code == sys.SSL_ERROR_WANT_WRITE) continue :state .drain;

                return error.BoringSSL;
            },
            .drain => {
                try self.bio.drain_writer();
                continue :state .start;
            },
        }
    }

    pub fn selectedAlpn(self: *const AsyncTlsStream) ?[]const u8 {
        return self.ssl.selectedAlpn();
    }

    pub fn sslRef(self: *AsyncTlsStream) BoringError!ssl_mod.SslRef {
        return self.ssl.ref();
    }

    pub fn isHandshakeComplete(self: *const AsyncTlsStream) bool {
        return self.ssl.isHandshakeComplete();
    }

    pub fn reader(self: *AsyncTlsStream, buffer: []u8) Reader {
        return .init(self, buffer);
    }

    pub fn writer(self: *AsyncTlsStream, buffer: []u8) Writer {
        return .init(self, buffer);
    }

    fn tls_retry(
        self: *AsyncTlsStream,
        comptime Context: type,
        context: *Context,
        comptime Result: type,
        comptime max_iterations: u32,
        comptime attempt: fn (*AsyncTlsStream, *Context) BoringError!Result,
    ) BoringError!Result {
        comptime std.debug.assert(max_iterations > 0);

        var iterations: u32 = 0;

        state: switch (TlsRetryState.start) {
            .start => {
                if (iterations >= max_iterations) return error.BoringSSL;
                iterations += 1;

                self.bio.sync_state();

                const result = attempt(self, context) catch |err| switch (err) {
                    error.WantRead => continue :state .drain,
                    error.WantWrite => continue :state .drain,
                    else => return err,
                };

                try self.bio.drain_writer();
                return result;
            },
            .drain => {
                try self.bio.drain_writer();
                continue :state .start;
            },
        }
    }

    fn tls_handshake_attempt(
        self: *AsyncTlsStream,
        context: *EmptyContext,
    ) BoringError!void {
        _ = context;
        return self.ssl.doHandshake();
    }

    fn tls_read_attempt(self: *AsyncTlsStream, output: *[]u8) BoringError!usize {
        return self.ssl.read(output.*);
    }

    fn tls_write_attempt(self: *AsyncTlsStream, input: *[]const u8) BoringError!usize {
        return self.ssl.write(input.*);
    }

    pub const Reader = struct {
        stream: *AsyncTlsStream,
        interface: std.Io.Reader,
        err: ?BoringError,

        pub fn init(stream: *AsyncTlsStream, buffer: []u8) Reader {
            std.debug.assert(buffer.len > 0);

            return .{
                .stream = stream,
                .interface = .{
                    .vtable = &.{
                        .stream = stream_read,
                    },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
                .err = null,
            };
        }

        fn stream_read(
            io_reader: *std.Io.Reader,
            io_writer: *std.Io.Writer,
            limit: std.Io.Limit,
        ) std.Io.Reader.StreamError!usize {
            std.debug.assert(limit.nonzero());

            const reader_adapter: *Reader = @alignCast(@fieldParentPtr("interface", io_reader));
            const writable = try io_writer.writableSliceGreedy(1);
            const output = limit.slice(writable);
            std.debug.assert(output.len > 0);

            const read_len = reader_adapter.stream.read(output) catch |err| {
                reader_adapter.err = err;
                return map_read_error(err);
            };
            if (read_len == 0) return error.EndOfStream;

            io_writer.advance(read_len);
            return read_len;
        }
    };

    pub const Writer = struct {
        stream: *AsyncTlsStream,
        interface: std.Io.Writer,
        err: ?BoringError,

        pub fn init(stream: *AsyncTlsStream, buffer: []u8) Writer {
            return .{
                .stream = stream,
                .interface = .{
                    .vtable = &.{
                        .drain = drain,
                        .sendFile = send_file,
                    },
                    .buffer = buffer,
                },
                .err = null,
            };
        }

        fn drain(
            io_writer: *std.Io.Writer,
            data: []const []const u8,
            splat: usize,
        ) std.Io.Writer.Error!usize {
            std.debug.assert(data.len > 0);
            std.debug.assert(data.len <= MaxWriterDataSlices);

            const writer_adapter: *Writer = @alignCast(@fieldParentPtr("interface", io_writer));
            const buffered = io_writer.buffered();
            if (buffered.len > 0) {
                const write_len = writer_adapter.stream.write(buffered) catch |err| {
                    writer_adapter.err = err;
                    return error.WriteFailed;
                };
                std.debug.assert(write_len > 0);
                return io_writer.consume(write_len);
            }

            const write_len = drain_data(writer_adapter.stream, data, splat) catch |err| {
                writer_adapter.err = err;
                return error.WriteFailed;
            };
            std.debug.assert(write_len <= std.Io.Writer.countSplat(data, splat));
            return write_len;
        }

        fn send_file(
            io_writer: *std.Io.Writer,
            file_reader: *std.Io.File.Reader,
            limit: std.Io.Limit,
        ) std.Io.Writer.FileError!usize {
            _ = io_writer;
            _ = file_reader;
            _ = limit;

            return error.Unimplemented;
        }
    };
};

pub const AsyncBio = struct {
    ptr: ?*sys.BIO,
    io: std.Io,
    stream_reader: *std.Io.Reader,
    stream_writer: *std.Io.Writer,
    state: BioState,
    owned: bool,

    pub fn init(
        io: std.Io,
        stream_reader: *std.Io.Reader,
        stream_writer: *std.Io.Writer,
    ) BoringError!AsyncBio {
        const method = get_or_create_bio_method() orelse return error.BoringSSL;

        const bio = sys.BIO_new(method) orelse return error.BoringSSL;

        var self = AsyncBio{
            .ptr = bio,
            .io = io,
            .stream_reader = stream_reader,
            .stream_writer = stream_writer,
            .state = .{
                .io = io,
                .stream_reader = stream_reader,
                .stream_writer = stream_writer,
            },
            .owned = true,
        };

        self.sync_state();
        sys.BIO_set_init(bio, 1);
        sys.BIO_set_shutdown(bio, 1);

        return self;
    }

    pub fn deinit(self: *AsyncBio) void {
        if (self.ptr) |bio| {
            if (self.owned) {
                _ = sys.BIO_free(bio);
            }
            self.ptr = null;
        }
    }

    pub fn raw(self: *AsyncBio) *sys.BIO {
        self.sync_state();
        return self.ptr orelse unreachable;
    }

    pub fn releaseOwnership(self: *AsyncBio) void {
        self.owned = false;
    }

    fn drain_writer(self: *AsyncBio) BoringError!void {
        self.io.checkCancel() catch return error.Syscall;
        self.stream_writer.flush() catch return error.Syscall;
    }

    fn sync_state(self: *AsyncBio) void {
        const bio = self.ptr orelse return;

        self.state = .{
            .io = self.io,
            .stream_reader = self.stream_reader,
            .stream_writer = self.stream_writer,
        };
        sys.BIO_set_data(bio, @ptrCast(&self.state));
    }
};

const BioState = struct {
    io: std.Io,
    stream_reader: *std.Io.Reader,
    stream_writer: *std.Io.Writer,
};

var bio_method: ?*sys.BIO_METHOD = null;

fn get_or_create_bio_method() ?*sys.BIO_METHOD {
    if (bio_method) |m| return m;

    const bio_type: c_int = sys.BIO_TYPE_SOURCE_SINK | 0x80;
    const method = sys.BIO_meth_new(bio_type, "zig_async_io") orelse return null;

    _ = sys.BIO_meth_set_write(method, bio_write_callback);
    _ = sys.BIO_meth_set_read(method, bio_read_callback);
    _ = sys.BIO_meth_set_puts(method, bio_puts_callback);
    _ = sys.BIO_meth_set_ctrl(method, bio_ctrl_callback);
    _ = sys.BIO_meth_set_create(method, bio_create_callback);
    _ = sys.BIO_meth_set_destroy(method, bio_destroy_callback);

    bio_method = method;

    return method;
}

fn bio_write_callback(bio: ?*sys.BIO, data: [*c]const u8, len: c_int) callconv(.c) c_int {
    if (bio == null) return -1;
    if (data == null) return -1;
    if (len <= 0) return 0;

    const state: *BioState = @ptrCast(@alignCast(
        sys.BIO_get_data(bio.?) orelse return -1,
    ));

    const bytes = data[0..@intCast(len)];
    state.io.checkCancel() catch return -1;
    state.stream_writer.writeAll(bytes) catch {
        return -1;
    };

    return len;
}

fn bio_read_callback(bio: ?*sys.BIO, data: [*c]u8, len: c_int) callconv(.c) c_int {
    if (bio == null) return -1;
    if (data == null) return -1;
    if (len <= 0) return 0;

    const state: *BioState = @ptrCast(@alignCast(
        sys.BIO_get_data(bio.?) orelse return -1,
    ));

    state.io.checkCancel() catch return -1;

    const output = data[0..@intCast(len)];
    const available = state.stream_reader.peekGreedy(1) catch |err| switch (err) {
        error.EndOfStream => return 0,
        error.ReadFailed => return -1,
    };
    std.debug.assert(available.len > 0);

    const copy_len = @min(available.len, output.len);
    @memcpy(output[0..copy_len], available[0..copy_len]);
    state.stream_reader.toss(copy_len);

    return @intCast(copy_len);
}

fn bio_puts_callback(bio: ?*sys.BIO, str: [*c]const u8) callconv(.c) c_int {
    if (bio == null) return -1;
    if (str == null) return -1;

    const len: usize = std.mem.len(str.?);
    if (len > std.math.maxInt(c_int)) return -1;

    return bio_write_callback(bio, str, @intCast(len));
}

fn bio_ctrl_callback(
    bio: ?*sys.BIO,
    cmd: c_int,
    larg: c_long,
    parg: ?*anyopaque,
) callconv(.c) c_long {
    _ = larg;
    _ = parg;

    if (bio == null) return 0;

    if (cmd == sys.BIO_CTRL_FLUSH) {
        const state: *BioState = @ptrCast(@alignCast(
            sys.BIO_get_data(bio.?) orelse return 0,
        ));
        state.stream_writer.flush() catch return 0;
        return 1;
    }

    if (cmd == sys.BIO_CTRL_RESET) {
        return 1;
    }

    return 0;
}

fn bio_create_callback(bio: ?*sys.BIO) callconv(.c) c_int {
    if (bio == null) return 0;

    sys.BIO_set_shutdown(bio.?, 1);
    sys.BIO_set_init(bio.?, 0);
    sys.BIO_set_data(bio.?, null);

    return 1;
}

fn bio_destroy_callback(bio: ?*sys.BIO) callconv(.c) c_int {
    if (bio == null) return 0;

    sys.BIO_set_data(bio.?, null);
    sys.BIO_set_init(bio.?, 0);

    return 1;
}

fn drain_data(
    stream: *AsyncTlsStream,
    data: []const []const u8,
    splat: usize,
) BoringError!usize {
    var index: u32 = 0;
    while (index < data.len - 1) : (index += 1) {
        const bytes = data[index];
        if (bytes.len > 0) return stream.write(bytes);
    }

    if (splat == 0) return 0;

    const bytes = data[data.len - 1];
    if (bytes.len == 0) return 0;

    return stream.write(bytes);
}

fn map_read_error(err: BoringError) std.Io.Reader.StreamError {
    return switch (err) {
        error.Closed => error.EndOfStream,
        error.ZeroReturn => error.EndOfStream,
        else => error.ReadFailed,
    };
}

test "async bio bridges std io reader and writer" {
    var input_reader: std.Io.Reader = .fixed("hello");
    var output_buffer: [16]u8 = undefined;
    var output_writer: std.Io.Writer = .fixed(&output_buffer);

    var bio = try AsyncBio.init(std.testing.io, &input_reader, &output_writer);
    defer bio.deinit();

    var read_buffer: [5]u8 = undefined;
    const read_len = sys.BIO_read(bio.raw(), &read_buffer, read_buffer.len);
    try std.testing.expectEqual(@as(c_int, read_buffer.len), read_len);
    try std.testing.expectEqualSlices(u8, "hello", &read_buffer);

    const write_len = sys.BIO_write(bio.raw(), "bye".ptr, 3);
    try std.testing.expectEqual(@as(c_int, 3), write_len);
    try std.testing.expectEqualSlices(u8, "bye", output_writer.buffered());
}

comptime {
    std.debug.assert(MaxTlsRecordSize >= 16384);
    std.debug.assert(MaxHandshakeIterations >= 8);
    std.debug.assert(MaxShutdownIterations >= 4);
    std.debug.assert(MaxWriterDataSlices >= 1);
}
