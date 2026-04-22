# http2-boring

Thin BoringSSL integration for `http2.zig`.

The package accepts an already-open TCP stream, completes the server-side TLS
handshake with `boring`, verifies that ALPN negotiated `h2`, and then hands the
decrypted `std.Io.Reader` and `std.Io.Writer` interfaces to `http2.zig`.

```zig
const http2_boring = @import("http2-boring");

var acceptor = http2_boring.Acceptor.initWithBuilder(&builder);
defer acceptor.deinit();

var connection: http2_boring.Connection = .{};
defer connection.deinit(io);

try acceptor.accept(&connection, io, tcp_stream);
try connection.serve(allocator, .{
    .dispatcher = dispatcher,
});
```

`Acceptor.initWithBuilder` installs the server ALPN selector before consuming
the `boring.ssl.ContextBuilder`. Connections that do not negotiate `h2` return
`error.NoApplicationProtocol`.

Keep `Connection` at a stable address after `accept`; its reader and writer
interfaces point into the in-place TLS stream.
