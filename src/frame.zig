const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const Io = std.Io;

/// The 4-byte masking key used to mask/unmask WebSocket frame payloads (RFC 6455 Section 5.3).
pub const MaskKey = [4]u8;
/// 28-byte buffer for the base64-encoded `Sec-WebSocket-Accept` header value.
pub const AcceptKey = [28]u8;

pub fn BoundedBuffer(comptime max_capacity: comptime_int) type {
    return struct {
        /// Unsigned integer type that fits the range `0..max_capacity`.
        pub const LenType = std.math.IntFittingRange(0, max_capacity);

        data: [max_capacity]u8,
        len: LenType,

        const Self = @This();

        /// An empty buffer with zero length.
        pub const empty: Self = .{ .data = undefined, .len = 0 };
        /// The maximum number of bytes this buffer can hold.
        pub const capacity: LenType = max_capacity;

        /// Returns the populated portion of the buffer as a slice.
        pub fn constSlice(self: *const Self) []const u8 {
            return self.data[0..self.len];
        }

        /// Appends `bytes` to the buffer. Returns `error.OutOfMemory` if
        /// the buffer does not have enough remaining capacity.
        pub fn appendSlice(self: *Self, bytes: []const u8) error{OutOfMemory}!void {
            if (self.len + bytes.len > max_capacity) return error.OutOfMemory;
            self.appendSliceAssumeCapacity(bytes);
        }

        /// Appends a single byte. Asserts that the buffer is not full.
        pub fn appendAssumeCapacity(self: *Self, byte: u8) void {
            assert(self.len < max_capacity);
            self.data[self.len] = byte;
            self.len += 1;
        }

        /// Appends `bytes` to the buffer. Asserts that there is enough remaining capacity.
        pub fn appendSliceAssumeCapacity(self: *Self, bytes: []const u8) void {
            const old_len = self.len;
            const new_len = old_len + bytes.len;
            assert(new_len <= max_capacity);
            self.len = @intCast(new_len);
            @memcpy(self.data[old_len..][0..bytes.len], bytes);
        }

        /// Appends an integer as big-endian bytes. Returns
        /// `error.OutOfMemory` if there is not enough remaining capacity.
        pub fn appendInt(self: *Self, comptime T: type, value: T) error{OutOfMemory}!void {
            const len = @divExact(@typeInfo(T).int.bits, 8);
            if (self.len + len > max_capacity) return error.OutOfMemory;
            self.appendIntAssumeCapacity(T, value);
        }

        /// Appends an integer as big-endian bytes. Asserts that
        /// there is enough remaining capacity.
        pub fn appendIntAssumeCapacity(self: *Self, comptime T: type, value: T) void {
            const len = @divExact(@typeInfo(T).int.bits, 8);
            const old_len = self.len;
            const new_len = old_len + len;
            assert(new_len <= max_capacity);
            const slice = self.data[old_len..][0..len];
            self.len = @intCast(new_len);
            writeInt(T, slice, value);
        }

        /// Resets the length to zero, logically clearing the buffer.
        pub fn reset(self: *Self) void {
            self.len = 0;
        }

        /// Writes the populated portion of the buffer to `writer`.
        pub fn write(self: *const Self, writer: *Io.Writer) Io.Writer.Error!void {
            try writer.writeAll(self.constSlice());
        }
    };
}

/// Maximum size of a WebSocket frame header (2 + 8 + 4 = 14 bytes).
pub const max_header_len = 14;
pub const HeaderBuffer = BoundedBuffer(max_header_len);

const max_control_payload_len = 125;
/// Fixed-capacity buffer for accumulating control frame payloads (max 125 bytes per RFC 6455).
pub const ControlBuffer = BoundedBuffer(max_control_payload_len);

/// WebSocket frame opcode (RFC 6455 Section 5.2).
pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    // 0x3-0x7 reserved for non-control
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    // 0xB-0xF reserved for control
    _,

    /// Returns true for opcodes 0x8–0xF (control frames: close, ping, pong, and reserved).
    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }

    /// Returns true for opcodes not defined by RFC 6455 (i.e. not
    /// continuation, text, binary, close, ping, or pong).
    pub fn isReserved(self: Opcode) bool {
        return switch (self) {
            .continuation, .text, .binary, .close, .ping, .pong => false,
            else => true,
        };
    }
};

/// The three RSV bits from the frame header (RFC 6455 Section 5.2).
/// Reserved for extensions; must be zero unless an extension is negotiated.
pub const RsvBits = packed struct(u3) {
    rsv3: bool = false,
    rsv2: bool = false,
    rsv1: bool = false,

    /// All bits unset (the default for frames without extensions).
    pub const empty: RsvBits = .{};

    /// Returns true if any RSV bit is set.
    pub fn areSet(self: RsvBits) bool {
        return @as(u3, @bitCast(self)) != 0;
    }
};

/// Decoded WebSocket frame header (RFC 6455 Section 5.2).
pub const FrameHeader = struct {
    /// True if this is the final fragment in a message.
    fin: bool = true,
    /// Reserved bits for extensions.
    rsv: RsvBits = .empty,
    /// The frame opcode.
    opcode: Opcode,
    /// Length of the payload data in bytes.
    payload_len: u64,
    /// The masking key, or null for unmasked frames.
    mask_key: ?MaskKey = null,

    /// A serialized frame header ready to write to the wire.
    pub const Buffer = struct {
        buf: HeaderBuffer,

        /// Serialize a `FrameHeader` into its wire representation.
        // ziglint-ignore: Z012
        pub fn init(header: FrameHeader) Buffer {
            var b: HeaderBuffer = .empty;

            // Byte 0: FIN(1) | RSV(3) | Opcode(4)
            const rsv_bits: u8 = @as(u3, @bitCast(header.rsv));
            var byte0: u8 = @intFromEnum(header.opcode) | (rsv_bits << 4);
            if (header.fin) byte0 |= 0x80;
            b.appendAssumeCapacity(byte0);

            // Byte 1: MASK(1) | Payload len(7)
            const mask_bit: u8 = if (header.mask_key != null) 0x80 else 0;

            if (header.payload_len <= 125) {
                b.appendAssumeCapacity(mask_bit | @as(u8, @intCast(header.payload_len)));
            } else if (header.payload_len <= 65535) {
                b.appendAssumeCapacity(mask_bit | 126);
                b.appendIntAssumeCapacity(u16, @intCast(header.payload_len));
            } else {
                b.appendAssumeCapacity(mask_bit | 127);
                b.appendIntAssumeCapacity(u64, header.payload_len);
            }

            if (header.mask_key) |key| {
                b.appendSliceAssumeCapacity(&key);
            }

            assert(b.len >= 2);
            assert(b.len <= max_header_len);
            return .{ .buf = b };
        }

        /// Returns the serialized header bytes.
        pub fn constSlice(self: *const Buffer) []const u8 {
            return self.buf.constSlice();
        }

        /// Writes the serialized header to `writer`.
        pub fn write(self: *const Buffer, writer: *Io.Writer) Io.Writer.Error!void {
            return self.buf.write(writer);
        }
    };

    /// Returns the total wire size of this header (2..14 bytes).
    pub fn encodedLen(self: FrameHeader) usize {
        var len: usize = 2;
        if (self.payload_len > 65535) {
            len += 8;
        } else if (self.payload_len > 125) {
            len += 2;
        }
        if (self.mask_key != null) len += 4;
        return len;
    }
};

/// Events emitted by `ServerParser.feed` / `ClientParser.feed`.
/// The caller must loop on `feed`, advancing the input by `consumed` bytes,
/// until `need_more` is returned or the input is exhausted.
pub const Event = union(enum) {
    /// A complete frame header has been parsed.
    frame_header: FrameHeader,
    /// A chunk of payload data (a slice into the caller's input buffer, already unmasked).
    payload: []u8,
    /// The current frame is complete. The parser is ready for the next frame.
    frame_end,
    /// More input is needed before the next event can be produced.
    need_more,
};

/// Errors returned by `ServerParser.feed` / `ClientParser.feed` for
/// protocol violations detected during frame parsing.
pub const ParseError = error{
    ReservedRsvBit,
    ReservedOpcode,
    ControlFrameTooLong,
    ControlFrameFragmented,
    InvalidPayloadLength,
    MaskRequired,
    MaskNotAllowed,
};

/// Stateful XOR masker for WebSocket payloads (RFC 6455 Section 5.3).
/// Tracks the 4-byte key and the current rotation offset so that
/// payloads can be masked/unmasked incrementally across chunks.
pub const Mask = struct {
    key: MaskKey,
    offset: u2,

    /// A no-op mask (all-zero key). XOR with zero leaves data unchanged.
    pub const none: Mask = .{ .key = @splat(0), .offset = 0 };

    /// Create a mask from `key` with the offset starting at zero.
    pub fn init(key: MaskKey) Mask {
        return .{ .key = key, .offset = 0 };
    }

    /// Apply the mask to `payload` in-place, advancing the internal offset.
    /// If the key is all zeros (unmasked), the XOR is a no-op.
    pub fn apply(self: *Mask, payload: []u8) void {
        const vec_len = 16;
        const Chunk = [vec_len]u8; // ziglint-ignore: Z006
        const ChunkVec = @Vector(vec_len, u8); // ziglint-ignore: Z006

        // Rotate mask to align with offset, then tile to fill the vector.
        var rotated: MaskKey = undefined;
        for (0..4) |k| rotated[k] = self.key[(k + self.offset) % 4];
        const mask_vec: ChunkVec = rotated ** (vec_len / 4);

        var i: usize = 0;
        while (payload.len - i >= vec_len) : (i += vec_len) {
            const chunk: *Chunk = payload[i..][0..vec_len];
            const chunk_vec: ChunkVec = chunk.*;
            chunk.* = chunk_vec ^ mask_vec;
        }

        // Scalar tail for remaining 0-15 bytes.
        while (i < payload.len) : (i += 1) {
            payload[i] ^= self.key[self.offset];
            self.offset +%= 1;
        }
    }
};

pub inline fn readInt(comptime T: type, buffer: *const [@divExact(@typeInfo(T).int.bits, 8)]u8) T {
    return mem.readInt(T, buffer, .big);
}

pub inline fn writeInt(
    comptime T: type,
    buffer: *[@divExact(@typeInfo(T).int.bits, 8)]u8,
    value: T,
) void {
    return mem.writeInt(T, buffer, value, .big);
}

const TestBuffer = BoundedBuffer(8);

test "BoundedBuffer: empty has zero length" {
    const b: TestBuffer = .empty;
    try testing.expectEqual(@as(TestBuffer.LenType, 0), b.len);
    try testing.expectEqual(@as(usize, 0), b.constSlice().len);
}

test "BoundedBuffer: capacity" {
    try testing.expectEqual(
        @as(TestBuffer.LenType, 8),
        TestBuffer.capacity,
    );
}

test "BoundedBuffer: appendAssumeCapacity" {
    var b: TestBuffer = .empty;
    b.appendAssumeCapacity(0xAA);
    b.appendAssumeCapacity(0xBB);
    try testing.expectEqual(@as(TestBuffer.LenType, 2), b.len);
    try testing.expectEqualSlices(
        u8,
        &.{ 0xAA, 0xBB },
        b.constSlice(),
    );
}

test "BoundedBuffer: appendSliceAssumeCapacity" {
    var b: TestBuffer = .empty;
    b.appendSliceAssumeCapacity("hello");
    try testing.expectEqualSlices(u8, "hello", b.constSlice());
    b.appendSliceAssumeCapacity("!!!");
    try testing.expectEqualSlices(u8, "hello!!!", b.constSlice());
}

test "BoundedBuffer: appendSlice success" {
    var b: TestBuffer = .empty;
    try b.appendSlice("abcd");
    try testing.expectEqualSlices(u8, "abcd", b.constSlice());
}

test "BoundedBuffer: appendSlice overflow" {
    var b: TestBuffer = .empty;
    try b.appendSlice("12345678");
    try testing.expectError(
        error.OutOfMemory,
        b.appendSlice("x"),
    );
    // Buffer unchanged after failed append.
    try testing.expectEqualSlices(
        u8,
        "12345678",
        b.constSlice(),
    );
}

test "BoundedBuffer: appendIntAssumeCapacity u16" {
    var b: TestBuffer = .empty;
    b.appendIntAssumeCapacity(u16, 0x0102);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x02 },
        b.constSlice(),
    );
}

test "BoundedBuffer: appendIntAssumeCapacity u32" {
    var b: TestBuffer = .empty;
    b.appendIntAssumeCapacity(u32, 0xDEADBEEF);
    try testing.expectEqualSlices(
        u8,
        &.{ 0xDE, 0xAD, 0xBE, 0xEF },
        b.constSlice(),
    );
}

test "BoundedBuffer: appendInt overflow" {
    var b: TestBuffer = .empty;
    try b.appendSlice("1234567"); // 7 of 8 used
    try testing.expectError(
        error.OutOfMemory,
        b.appendInt(u16, 0x0000),
    );
    try testing.expectEqualSlices(u8, "1234567", b.constSlice());
}

test "BoundedBuffer: reset clears length" {
    var b: TestBuffer = .empty;
    b.appendSliceAssumeCapacity("data");
    b.reset();
    try testing.expectEqual(@as(TestBuffer.LenType, 0), b.len);
    try testing.expectEqual(@as(usize, 0), b.constSlice().len);
}

test "BoundedBuffer: mixed append sequence" {
    var b: TestBuffer = .empty;
    b.appendAssumeCapacity(0xFF);
    b.appendIntAssumeCapacity(u16, 0x0100);
    b.appendSliceAssumeCapacity("hi");
    try testing.expectEqualSlices(
        u8,
        &.{ 0xFF, 0x01, 0x00, 'h', 'i' },
        b.constSlice(),
    );
}

test "Opcode.isControl" {
    try testing.expect(!Opcode.text.isControl());
    try testing.expect(!Opcode.binary.isControl());
    try testing.expect(Opcode.close.isControl());
    try testing.expect(Opcode.ping.isControl());
    try testing.expect(Opcode.pong.isControl());
}

test "Opcode.isReserved" {
    try testing.expect(!Opcode.text.isReserved());
    try testing.expect(!Opcode.close.isReserved());
    try testing.expect((@as(Opcode, @enumFromInt(0x3))).isReserved());
    try testing.expect((@as(Opcode, @enumFromInt(0xF))).isReserved());
}

test "FrameHeader.encodedLen" {
    const h: FrameHeader = .{
        .fin = true,
        .rsv = .empty,
        .opcode = .text,
        .payload_len = 100,
        .mask_key = null,
    };
    try testing.expectEqual(2, h.encodedLen());

    var h2 = h;
    h2.payload_len = 200;
    try testing.expectEqual(4, h2.encodedLen()); // 2 + 2-byte extended

    h2.payload_len = 70000;
    try testing.expectEqual(10, h2.encodedLen()); // 2 + 8-byte extended

    h2.mask_key = @splat(0);
    try testing.expectEqual(14, h2.encodedLen()); // 2 + 8 + 4
}

test "FrameHeader.Buffer: minimal unmasked frame (small payload)" {
    const header: FrameHeader.Buffer = .init(.{ .opcode = .text, .payload_len = 5 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 2), bytes.len);
    // FIN=1, RSV=000, opcode=0x1 -> 0x81
    try testing.expectEqual(@as(u8, 0x81), bytes[0]);
    // MASK=0, len=5
    try testing.expectEqual(@as(u8, 0x05), bytes[1]);
}

test "FrameHeader.Buffer: zero-length payload" {
    const header: FrameHeader.Buffer = .init(.{ .opcode = .ping, .payload_len = 0 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 2), bytes.len);
    try testing.expectEqual(@as(u8, 0x89), bytes[0]); // FIN=1, opcode=0x9
    try testing.expectEqual(@as(u8, 0x00), bytes[1]);
}

test "FrameHeader.Buffer: 125-byte payload (max 7-bit)" {
    const header: FrameHeader.Buffer = .init(.{ .opcode = .binary, .payload_len = 125 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 2), bytes.len);
    try testing.expectEqual(@as(u8, 0x82), bytes[0]); // FIN=1, opcode=0x2
    try testing.expectEqual(@as(u8, 125), bytes[1]);
}

test "FrameHeader.Buffer: 126-byte payload (16-bit extended)" {
    const header: FrameHeader.Buffer = .init(.{ .opcode = .text, .payload_len = 126 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 4), bytes.len);
    try testing.expectEqual(@as(u8, 0x81), bytes[0]);
    try testing.expectEqual(@as(u8, 126), bytes[1]); // extended length marker
    // 126 in big-endian u16 = 0x00 0x7E
    try testing.expectEqual(@as(u8, 0x00), bytes[2]);
    try testing.expectEqual(@as(u8, 0x7E), bytes[3]);
}

test "FrameHeader.Buffer: 65535-byte payload (max 16-bit)" {
    const header: FrameHeader.Buffer = .init(.{ .opcode = .binary, .payload_len = 65535 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 4), bytes.len);
    try testing.expectEqual(@as(u8, 126), bytes[1]);
    try testing.expectEqual(@as(u8, 0xFF), bytes[2]);
    try testing.expectEqual(@as(u8, 0xFF), bytes[3]);
}

test "FrameHeader.Buffer: 65536-byte payload (64-bit extended)" {
    const header: FrameHeader.Buffer = .init(.{ .opcode = .text, .payload_len = 65536 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 10), bytes.len);
    try testing.expectEqual(@as(u8, 0x81), bytes[0]);
    try testing.expectEqual(@as(u8, 127), bytes[1]); // 64-bit extended marker
    // 65536 = 0x00_00_00_00_00_01_00_00 big-endian
    const expected_len = [8]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    try testing.expectEqualSlices(u8, &expected_len, bytes[2..10]);
}

test "FrameHeader.Buffer: masked frame adds 4 bytes" {
    const mask = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };
    const header: FrameHeader.Buffer = .init(.{
        .opcode = .text,
        .payload_len = 5,
        .mask_key = mask,
    });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 6), bytes.len); // 2 base + 4 mask
    try testing.expectEqual(@as(u8, 0x81), bytes[0]);
    // MASK bit set: 0x80 | 5 = 0x85
    try testing.expectEqual(@as(u8, 0x85), bytes[1]);
    try testing.expectEqualSlices(u8, &mask, bytes[2..6]);
}

test "FrameHeader.Buffer: masked frame with 16-bit extended length" {
    const mask = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const header: FrameHeader.Buffer = .init(.{
        .opcode = .binary,
        .payload_len = 1000,
        .mask_key = mask,
    });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 8), bytes.len); // 2 + 2 ext + 4 mask
    try testing.expectEqual(@as(u8, 126), bytes[1] & 0x7F);
    try testing.expect(bytes[1] & 0x80 != 0); // mask bit set
    // 1000 = 0x03E8 big-endian
    try testing.expectEqual(@as(u8, 0x03), bytes[2]);
    try testing.expectEqual(@as(u8, 0xE8), bytes[3]);
    try testing.expectEqualSlices(u8, &mask, bytes[4..8]);
}

test "FrameHeader.Buffer: masked frame with 64-bit extended length" {
    const mask = [4]u8{ 0x01, 0x02, 0x03, 0x04 };
    const header: FrameHeader.Buffer = .init(.{
        .opcode = .text,
        .payload_len = 100000,
        .mask_key = mask,
    });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 14), bytes.len); // 2 + 8 ext + 4 mask = max
    try testing.expectEqual(@as(u8, 127), bytes[1] & 0x7F);
    try testing.expect(bytes[1] & 0x80 != 0);
    try testing.expectEqualSlices(u8, &mask, bytes[10..14]);
}

test "FrameHeader.Buffer: all opcodes" {
    const opcodes = [_]Opcode{ .continuation, .text, .binary, .close, .ping, .pong };
    const expected_nibbles = [_]u8{ 0x0, 0x1, 0x2, 0x8, 0x9, 0xA };
    for (opcodes, expected_nibbles) |op, nibble| {
        const header: FrameHeader.Buffer = .init(.{ .opcode = op, .payload_len = 0 });
        try testing.expectEqual(0x80 | nibble, header.constSlice()[0]);
    }
}

test "FrameHeader.Buffer: FIN=false (continuation)" {
    const header: FrameHeader.Buffer = .init(.{ .fin = false, .opcode = .text, .payload_len = 10 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 2), bytes.len);
    // FIN=0, opcode=0x1 -> 0x01
    try testing.expectEqual(@as(u8, 0x01), bytes[0]);
    try testing.expectEqual(@as(u8, 10), bytes[1]);
}

test "FrameHeader.Buffer: RSV bits set" {
    // RFC 6455: byte 0 = FIN(bit7) RSV1(bit6) RSV2(bit5) RSV3(bit4) Opcode(bits3:0)
    {
        const h: FrameHeader.Buffer = .init(.{
            .rsv = .{ .rsv1 = true },
            .opcode = .text,
            .payload_len = 0,
        });
        try testing.expectEqual(@as(u8, 0x80 | 0x40 | 0x01), h.constSlice()[0]);
    }
    {
        const h: FrameHeader.Buffer = .init(.{
            .rsv = .{ .rsv2 = true },
            .opcode = .text,
            .payload_len = 0,
        });
        try testing.expectEqual(@as(u8, 0x80 | 0x20 | 0x01), h.constSlice()[0]);
    }
    {
        const h: FrameHeader.Buffer = .init(.{
            .rsv = .{ .rsv3 = true },
            .opcode = .text,
            .payload_len = 0,
        });
        try testing.expectEqual(@as(u8, 0x80 | 0x10 | 0x01), h.constSlice()[0]);
    }
    // All RSV bits
    {
        const header: FrameHeader.Buffer = .init(.{
            .rsv = .{ .rsv1 = true, .rsv2 = true, .rsv3 = true },
            .opcode = .binary,
            .payload_len = 0,
        });
        try testing.expectEqual(@as(u8, 0x80 | 0x70 | 0x02), header.constSlice()[0]);
    }
}

test "FrameHeader.Buffer: RFC 6455 Section 5.7 - unmasked text 'Hello'" {
    // RFC example: A single-frame unmasked text message containing "Hello"
    // 0x81 0x05 followed by the payload
    const header: FrameHeader.Buffer = .init(.{ .opcode = .text, .payload_len = 5 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 2), bytes.len);
    try testing.expectEqual(@as(u8, 0x81), bytes[0]);
    try testing.expectEqual(@as(u8, 0x05), bytes[1]);
}

test "FrameHeader.Buffer: RFC 6455 Section 5.7 - masked text 'Hello'" {
    // RFC example: A single-frame masked text message containing "Hello"
    // 0x81 0x85 + mask key 0x37 0xfa 0x21 0x3d
    const mask = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };
    const header: FrameHeader.Buffer = .init(.{
        .opcode = .text,
        .payload_len = 5,
        .mask_key = mask,
    });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 6), bytes.len);
    try testing.expectEqual(@as(u8, 0x81), bytes[0]);
    try testing.expectEqual(@as(u8, 0x85), bytes[1]);
    try testing.expectEqual(@as(u8, 0x37), bytes[2]);
    try testing.expectEqual(@as(u8, 0xfa), bytes[3]);
    try testing.expectEqual(@as(u8, 0x21), bytes[4]);
    try testing.expectEqual(@as(u8, 0x3d), bytes[5]);
}

test "FrameHeader.Buffer: RFC 6455 Section 5.7 - unmasked ping" {
    // A Ping frame with "Hello" payload: 0x89 0x05
    const header: FrameHeader.Buffer = .init(.{ .opcode = .ping, .payload_len = 5 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 2), bytes.len);
    try testing.expectEqual(@as(u8, 0x89), bytes[0]);
    try testing.expectEqual(@as(u8, 0x05), bytes[1]);
}

test "FrameHeader.Buffer: RFC 6455 Section 5.7 - 256-byte unmasked binary" {
    // 256 bytes binary, unmasked: 0x82 0x7E 0x01 0x00
    const header: FrameHeader.Buffer = .init(.{ .opcode = .binary, .payload_len = 256 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 4), bytes.len);
    try testing.expectEqual(@as(u8, 0x82), bytes[0]);
    try testing.expectEqual(@as(u8, 0x7E), bytes[1]);
    try testing.expectEqual(@as(u8, 0x01), bytes[2]);
    try testing.expectEqual(@as(u8, 0x00), bytes[3]);
}

test "FrameHeader.Buffer: RFC 6455 Section 5.7 - 64KiB unmasked binary" {
    // 65536 bytes binary, unmasked: 0x82 0x7F + 8-byte length
    const header: FrameHeader.Buffer = .init(.{ .opcode = .binary, .payload_len = 65536 });
    const bytes = header.constSlice();
    try testing.expectEqual(@as(usize, 10), bytes.len);
    try testing.expectEqual(@as(u8, 0x82), bytes[0]);
    try testing.expectEqual(@as(u8, 0x7F), bytes[1]);
    const expected = [8]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    try testing.expectEqualSlices(u8, &expected, bytes[2..10]);
}

test "FrameHeader.Buffer: round-trip with FrameHeader.encodedLen" {
    const cases = [_]struct { len: u64, mask_key: ?MaskKey }{
        .{ .len = 0, .mask_key = null },
        .{ .len = 1, .mask_key = null },
        .{ .len = 125, .mask_key = null },
        .{ .len = 126, .mask_key = null },
        .{ .len = 65535, .mask_key = null },
        .{ .len = 65536, .mask_key = null },
        .{ .len = 100000, .mask_key = null },
        .{ .len = 0, .mask_key = .{ 0x11, 0x22, 0x33, 0x44 } },
        .{ .len = 125, .mask_key = .{ 0x11, 0x22, 0x33, 0x44 } },
        .{ .len = 126, .mask_key = .{ 0x11, 0x22, 0x33, 0x44 } },
        .{ .len = 65535, .mask_key = .{ 0x11, 0x22, 0x33, 0x44 } },
        .{ .len = 65536, .mask_key = .{ 0x11, 0x22, 0x33, 0x44 } },
    };

    for (cases) |c| {
        const encoded: FrameHeader.Buffer = .init(.{
            .opcode = .text,
            .payload_len = c.len,
            .mask_key = c.mask_key,
        });

        const hdr: FrameHeader = .{
            .fin = true,
            .rsv = .empty,
            .opcode = .text,
            .payload_len = c.len,
            .mask_key = c.mask_key,
        };
        try testing.expectEqual(hdr.encodedLen(), encoded.constSlice().len);
    }
}

test "Mask.apply: empty payload preserves offset" {
    var buf: [0]u8 = .{};
    var m: Mask = .{ .key = .{ 0xAA, 0xBB, 0xCC, 0xDD }, .offset = 0 };
    m.apply(&buf);
    try testing.expectEqual(@as(u2, 0), m.offset);

    m.offset = 2;
    m.apply(&buf);
    try testing.expectEqual(@as(u2, 2), m.offset);
}

test "Mask.apply: single byte" {
    var m: Mask = .init(.{ 0x37, 0xFA, 0x21, 0x3D });
    var buf = [_]u8{0x48}; // 'H'
    m.apply(&buf);
    try testing.expectEqual(@as(u8, 0x48 ^ 0x37), buf[0]);
    try testing.expectEqual(@as(u2, 1), m.offset);
}

test "Mask.apply: exactly 4 bytes (full mask cycle)" {
    var m: Mask = .init(.{ 0x37, 0xFA, 0x21, 0x3D });
    var buf = [_]u8{ 0x48, 0x65, 0x6C, 0x6C }; // "Hell"
    m.apply(&buf);
    try testing.expectEqual(@as(u8, 0x48 ^ 0x37), buf[0]);
    try testing.expectEqual(@as(u8, 0x65 ^ 0xFA), buf[1]);
    try testing.expectEqual(@as(u8, 0x6C ^ 0x21), buf[2]);
    try testing.expectEqual(@as(u8, 0x6C ^ 0x3D), buf[3]);
    try testing.expectEqual(@as(u2, 0), m.offset); // wraps back to 0
}

test "Mask.apply: offset > 0 (partial mask rotation)" {
    var m: Mask = .{ .key = .{ 0xAA, 0xBB, 0xCC, 0xDD }, .offset = 2 };
    var buf = [_]u8{ 0x11, 0x22, 0x33 };

    // Starting at offset 2: mask bytes used are CC, DD, AA
    m.apply(&buf);
    try testing.expectEqual(@as(u8, 0x11 ^ 0xCC), buf[0]);
    try testing.expectEqual(@as(u8, 0x22 ^ 0xDD), buf[1]);
    try testing.expectEqual(@as(u8, 0x33 ^ 0xAA), buf[2]);
    try testing.expectEqual(@as(u2, 1), m.offset);
}

test "Mask.apply: round-trip (mask then unmask)" {
    const original = "Hello, WebSocket!";
    var buf: [original.len]u8 = undefined;
    @memcpy(&buf, original);

    // Mask
    var m: Mask = .init(.{ 0x37, 0xFA, 0x21, 0x3D });
    m.apply(&buf);
    // Verify it actually changed
    try testing.expect(!mem.eql(u8, &buf, original));
    // Unmask with same starting offset (0) — XOR is its own inverse
    m = .init(m.key);
    m.apply(&buf);
    try testing.expectEqualSlices(u8, original, &buf);
}

test "Mask.apply: chunked processing equals all-at-once" {
    const key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    const data = "The quick brown fox jumps";

    // All at once
    var all_at_once: [data.len]u8 = undefined;
    @memcpy(&all_at_once, data);
    var m: Mask = .init(key);
    m.apply(&all_at_once);

    // In chunks of varying sizes
    var chunked: [data.len]u8 = undefined;
    @memcpy(&chunked, data);

    const splits = [_]usize{ 3, 7, 1, 5, data.len - 16 };
    var pos: usize = 0;
    m = .init(key);
    for (splits) |chunk_len| {
        m.apply(chunked[pos..][0..chunk_len]);
        pos += chunk_len;
    }

    try testing.expectEqualSlices(u8, &all_at_once, &chunked);
}

test "Mask.apply: offset wraps correctly at u2 boundary" {
    var m: Mask = .{ .key = .{ 0xFF, 0x00, 0xFF, 0x00 }, .offset = 3 };
    var buf = [_]u8{ 0xAB, 0xCD };

    // Start at offset 3: mask bytes used are 00, FF
    m.apply(&buf);
    try testing.expectEqual(@as(u8, 0xAB ^ 0x00), buf[0]);
    try testing.expectEqual(@as(u8, 0xCD ^ 0xFF), buf[1]);
    try testing.expectEqual(@as(u2, 1), m.offset);
}

test "Mask.apply: SIMD boundary sizes" {
    const key = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    // Test sizes around the 16-byte SIMD boundary
    const sizes = [_]usize{ 1, 4, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 256 };
    for (sizes) |size| {
        // Prepare test data
        var data: [256]u8 = undefined;
        for (0..size) |i| {
            data[i] = @truncate(i);
        }
        var expected: [256]u8 = undefined;
        @memcpy(expected[0..size], data[0..size]);

        // Mask with byte-at-a-time reference implementation
        for (0..size) |i| {
            expected[i] ^= key[i % 4];
        }

        // Mask with our (potentially SIMD) implementation
        var m: Mask = .init(key);
        m.apply(data[0..size]);
        try testing.expectEqualSlices(u8, expected[0..size], data[0..size]);
    }
}
