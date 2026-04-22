const std = @import("std");
const sys = @import("boringssl");

const BoringError = @import("internal.zig").BoringError;

pub const BlockSize: usize = sys.AES_BLOCK_SIZE;
pub const Block = [BlockSize]u8;

pub const Key = struct {
    value: sys.AES_KEY,

    pub fn initEncrypt(key: []const u8) BoringError!Key {
        return init(key, .encrypt);
    }

    pub fn initDecrypt(key: []const u8) BoringError!Key {
        return init(key, .decrypt);
    }

    pub fn encryptBlock(self: *const Key, input: *const Block) Block {
        var output: Block = undefined;
        sys.AES_encrypt(input, &output, &self.value);

        return output;
    }

    pub fn decryptBlock(self: *const Key, input: *const Block) Block {
        var output: Block = undefined;
        sys.AES_decrypt(input, &output, &self.value);

        return output;
    }

    pub fn cbcEncrypt(
        self: *const Key,
        output: []u8,
        input: []const u8,
        iv: *Block,
    ) BoringError!void {
        if (input.len % BlockSize != 0) return error.InvalidArgument;
        if (output.len < input.len) return error.InvalidArgument;

        sys.AES_cbc_encrypt(input.ptr, output.ptr, input.len, &self.value, iv, sys.AES_ENCRYPT);
    }

    pub fn cbcDecrypt(
        self: *const Key,
        output: []u8,
        input: []const u8,
        iv: *Block,
    ) BoringError!void {
        if (input.len % BlockSize != 0) return error.InvalidArgument;
        if (output.len < input.len) return error.InvalidArgument;

        sys.AES_cbc_encrypt(input.ptr, output.ptr, input.len, &self.value, iv, sys.AES_DECRYPT);
    }

    fn init(key: []const u8, mode: Mode) BoringError!Key {
        const bits = key_bits(key.len) orelse return error.InvalidArgument;
        var self: Key = undefined;
        const result = switch (mode) {
            .encrypt => sys.AES_set_encrypt_key(key.ptr, bits, &self.value),
            .decrypt => sys.AES_set_decrypt_key(key.ptr, bits, &self.value),
        };
        if (result != 0) return error.BoringSSL;

        return self;
    }
};

pub fn wrapKey(
    key: *const Key,
    iv: ?*const [8]u8,
    output: []u8,
    input: []const u8,
) BoringError!usize {
    if (input.len % 8 != 0) return error.InvalidArgument;
    if (output.len < input.len + 8) return error.InvalidArgument;

    const result = sys.AES_wrap_key(&key.value, optional_iv(iv), output.ptr, input.ptr, input.len);
    if (result <= 0) return error.BoringSSL;

    return @intCast(result);
}

pub fn unwrapKey(
    key: *const Key,
    iv: ?*const [8]u8,
    output: []u8,
    input: []const u8,
) BoringError!usize {
    if (input.len % 8 != 0) return error.InvalidArgument;
    if (input.len < 16) return error.InvalidArgument;
    if (output.len + 8 < input.len) return error.InvalidArgument;

    const result = sys.AES_unwrap_key(
        &key.value,
        optional_iv(iv),
        output.ptr,
        input.ptr,
        input.len,
    );
    if (result <= 0) return error.BoringSSL;

    return @intCast(result);
}

fn optional_iv(iv: ?*const [8]u8) [*c]const u8 {
    if (iv) |value| {
        return value;
    } else {
        return null;
    }
}

fn key_bits(key_len: usize) ?c_uint {
    return switch (key_len) {
        16 => 128,
        24 => 192,
        32 => 256,
        else => null,
    };
}

const Mode = enum {
    encrypt,
    decrypt,
};

comptime {
    std.debug.assert(BlockSize == 16);
}
