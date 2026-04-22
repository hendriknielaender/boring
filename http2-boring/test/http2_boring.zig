const std = @import("std");
const http2_boring = @import("http2-boring");

test "alpn h2 accepted" {
    try std.testing.expect(http2_boring.isHttp2Alpn("h2"));
}

test "alpn non h2 rejected" {
    try std.testing.expect(!http2_boring.isHttp2Alpn(null));
    try std.testing.expect(!http2_boring.isHttp2Alpn(""));
    try std.testing.expect(!http2_boring.isHttp2Alpn("http/1.1"));
}

test "public declarations compile" {
    std.testing.refAllDecls(http2_boring);
}
