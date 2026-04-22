const std = @import("std");
const sys = @import("boringssl");

const BoringError = @import("internal.zig").BoringError;

pub fn encodedLen(input_len: usize) BoringError!usize {
    const blocks = input_len / 3;
    var len = try std.math.mul(usize, blocks, 4);

    if (input_len % 3 != 0) {
        len = try std.math.add(usize, len, 4);
    }

    return len;
}

pub fn encodeBlock(output: []u8, input: []const u8) BoringError!usize {
    const len = try encodedLen(input.len);
    if (output.len < len + 1) return error.InvalidArgument;

    const output_len = sys.EVP_EncodeBlock(output.ptr, input.ptr, input.len);
    std.debug.assert(output_len == len);

    return output_len;
}

pub fn decodedLenMax(input_len: usize) BoringError!usize {
    const blocks = input_len / 4;
    var len = try std.math.mul(usize, blocks, 3);

    if (input_len % 4 != 0) {
        len = try std.math.add(usize, len, 3);
    }

    return len;
}

pub fn decodeBlock(output: []u8, input: []const u8) BoringError!usize {
    const input_trimmed = std.mem.trim(u8, input, &std.ascii.whitespace);
    if (input_trimmed.len == 0) return 0;

    const len_max = try decodedLenMax(input_trimmed.len);
    if (output.len < len_max) return error.InvalidArgument;

    const result = sys.EVP_DecodeBlock(output.ptr, input_trimmed.ptr, input_trimmed.len);
    if (result < 0) return error.BoringSSL;

    var output_len: usize = @intCast(result);
    if (std.mem.endsWith(u8, input_trimmed, "=")) output_len -= 1;
    if (std.mem.endsWith(u8, input_trimmed, "==")) output_len -= 1;

    return output_len;
}

comptime {
    std.debug.assert(@sizeOf(usize) >= 4);
}
