const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;

const close = @import("close.zig");
const CloseCode = close.CloseCode;
const parseClosePayload = close.parseClosePayload;
const frame = @import("frame.zig");
const Opcode = frame.Opcode;
const RsvBits = frame.RsvBits;
const FrameHeader = frame.FrameHeader;
const MaskKey = frame.MaskKey;
const Mask = frame.Mask;
const Event = frame.Event;
const ParseError = frame.ParseError;
const HeaderBuffer = frame.HeaderBuffer;
const ControlBuffer = frame.ControlBuffer;
const max_header_len = frame.max_header_len;
const readInt = frame.readInt;
const writeInt = frame.writeInt;

/// Tracks fragmented message state across frames. Call `check` with each
/// frame_header event to validate RFC 6455 Section 5.4 fragmentation rules.
/// Optional — callers who don't need fragmentation validation can skip this.
pub const MessageValidator = struct {
    state: State,

    const State = enum { idle, in_fragment };

    /// Initial state, ready for the first data frame.
    pub const init: MessageValidator = .{ .state = .idle };

    /// Errors returned by `check` for fragmentation protocol violations.
    pub const ValidationError = error{
        /// Continuation frame received with no message in progress.
        UnexpectedContinuation,
        /// Text/binary frame received while a fragmented message is in progress.
        ExpectedContinuation,
    };

    /// Validate a frame header against fragmentation rules.
    /// Control frames are always allowed (they can be interleaved mid-fragment).
    pub fn check(self: *MessageValidator, header: FrameHeader) ValidationError!void {
        if (header.opcode.isControl()) return;

        switch (self.state) {
            .idle => switch (header.opcode) {
                .continuation => return error.UnexpectedContinuation,
                else => if (!header.fin) {
                    self.state = .in_fragment;
                },
            },
            .in_fragment => switch (header.opcode) {
                .continuation => if (header.fin) {
                    self.state = .idle;
                },
                else => return error.ExpectedContinuation,
            },
        }
    }
};

/// Streaming frame parser for server connections (expects masked frames from clients).
pub const ServerParser = Parser(true);
/// Streaming frame parser for client connections (expects unmasked frames from servers).
pub const ClientParser = Parser(false);

fn Parser(comptime is_server: bool) type {
    return struct {
        const Self = @This();

        state: State,

        const State = union(enum) {
            header: HeaderBuffer,
            payload: struct {
                remaining: u64,
                mask: Mask,
            },
            frame_end,
        };

        /// Initial parser state, ready for the first frame.
        pub const init: Self = .{
            .state = .{ .header = .empty },
        };

        /// The return value of `feed`: how many input bytes were consumed and the resulting event.
        pub const FeedResult = struct {
            consumed: usize,
            event: Event,
        };

        /// Feed raw bytes into the parser and get the next event.
        /// Caller must loop, advancing `input` by `consumed` bytes,
        /// until `.need_more` is returned or the input is exhausted.
        pub fn feed(self: *Self, input: []u8) ParseError!FeedResult {
            switch (self.state) {
                .header => |*header| {
                    var total_consumed: usize = 0;

                    while (true) {
                        const required = requiredHeaderLen(header.constSlice());
                        if (header.len >= required) break;

                        const need = required - header.len;
                        const remaining_input = input[total_consumed..];
                        const available = @min(remaining_input.len, need);
                        if (available == 0) {
                            return .{ .consumed = total_consumed, .event = .need_more };
                        }
                        header.appendSliceAssumeCapacity(remaining_input[0..available]);
                        total_consumed += available;
                    }
                    const available = total_consumed;
                    const required_len = requiredHeaderLen(header.constSlice());
                    assert(header.len == required_len);

                    const hdr_bytes = header.constSlice();
                    const byte0 = hdr_bytes[0];
                    const byte1 = hdr_bytes[1];

                    const fin = (byte0 & 0x80) != 0;
                    const rsv: RsvBits = @bitCast(@as(u3, @truncate(byte0 >> 4)));
                    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(byte0)));
                    const masked = (byte1 & 0x80) != 0;
                    const len7: u7 = @truncate(byte1);

                    if (rsv.areSet()) return error.ReservedRsvBit;
                    if (opcode.isReserved()) return error.ReservedOpcode;

                    var idx: usize = 2;
                    const payload_len: u64 = if (len7 <= 125)
                        len7
                    else if (len7 == 126) blk: {
                        const val = readInt(u16, hdr_bytes[2..4]);
                        idx = 4;
                        break :blk val;
                    } else blk: {
                        // len7 == 127
                        const val = readInt(u64, hdr_bytes[2..10]);
                        idx = 10;
                        break :blk val;
                    };

                    // RFC 6455 Section 5.2: payload length must use minimal encoding,
                    // and the most significant bit of 64-bit lengths must be 0.
                    if (len7 == 126 and payload_len < 126) return error.InvalidPayloadLength;
                    if (len7 == 127 and payload_len < 65536) return error.InvalidPayloadLength;
                    if (len7 == 127 and payload_len >> 63 != 0) return error.InvalidPayloadLength;

                    if (opcode.isControl()) {
                        if (payload_len > 125) return error.ControlFrameTooLong;
                        if (!fin) return error.ControlFrameFragmented;
                    }

                    if (is_server and !masked) return error.MaskRequired;
                    if (!is_server and masked) return error.MaskNotAllowed;

                    const mask_key: ?MaskKey = if (masked) hdr_bytes[idx..][0..4].* else null;

                    const frame_header: FrameHeader = .{
                        .fin = fin,
                        .rsv = rsv,
                        .opcode = opcode,
                        .payload_len = payload_len,
                        .mask_key = mask_key,
                    };

                    const mask: Mask = if (mask_key) |key| .init(key) else .none;

                    if (payload_len == 0) {
                        self.state = .frame_end;
                    } else {
                        self.state = .{ .payload = .{
                            .remaining = payload_len,
                            .mask = mask,
                        } };
                    }

                    return .{ .consumed = available, .event = .{ .frame_header = frame_header } };
                },
                .payload => |*payload| {
                    assert(payload.remaining > 0);
                    if (input.len == 0) {
                        return .{ .consumed = 0, .event = .need_more };
                    }

                    const chunk_len: usize = @intCast(@min(input.len, payload.remaining));
                    const chunk = input[0..chunk_len];

                    // Unmask in-place (if mask key is all zeros, XOR is a no-op).
                    payload.mask.apply(chunk);

                    payload.remaining -= chunk_len;
                    if (payload.remaining == 0) {
                        self.state = .frame_end;
                    }

                    return .{ .consumed = chunk_len, .event = .{ .payload = chunk } };
                },
                .frame_end => {
                    self.state = .{ .header = .empty };
                    return .{ .consumed = 0, .event = .frame_end };
                },
            }
        }

        fn requiredHeaderLen(buf: []const u8) u8 {
            if (buf.len < 2) return 2;
            const len7: u7 = @truncate(buf[1]);
            const masked = (buf[1] & 0x80) != 0;
            var required: u8 = 2;
            if (len7 == 126) {
                required += 2;
            } else if (len7 == 127) {
                required += 8;
            }
            if (masked) required += 4;
            assert(required >= 2);
            assert(required <= max_header_len);
            return required;
        }

        /// Reset the parser to its initial state, ready for a new
        /// frame sequence.
        pub fn reset(self: *Self) void {
            self.* = init;
        }
    };
}

/// Higher-level frame handler for server connections. Wraps `ServerParser` with
/// fragmentation validation, control frame accumulation, and message-level events.
pub const ServerFrameHandler = FrameHandler(true);
/// Higher-level frame handler for client connections. Wraps `ClientParser` with
/// fragmentation validation, control frame accumulation, and message-level events.
pub const ClientFrameHandler = FrameHandler(false);

/// Wraps a `Parser` and `MessageValidator` to handle the control-frame
/// accumulation and fragmentation tracking that every consumer needs.
/// Transforms the low-level `Event` stream into a higher-level `Message`
/// stream: data chunks, complete control frames (ping/pong/close), and
/// message boundaries.
///
/// Zero allocations — data payloads pass through as slices into the caller's
/// input buffer. Control payloads are accumulated in an internal 125-byte buffer.
///
/// ```
/// var handler: websocket.ServerFrameHandler = .init;
/// while (true) {
///     const result = try handler.feed(buf);
///     buf = buf[result.consumed..];
///     switch (result.message) {
///         .data => |payload| { /* accumulate */ },
///         .data_end => |end| { /* complete message, opcode = end.opcode */ },
///         .ping => |payload| { /* send pong */ },
///         .pong => {},
///         .close => |close| { /* echo close, shut down */ },
///         .need_more => break,
///     }
/// }
/// ```
fn FrameHandler(comptime is_server: bool) type {
    return struct {
        const Self = @This();

        parser: Parser(is_server),
        validator: MessageValidator,
        ctrl: ControlBuffer,
        msg_opcode: Opcode,
        cur_opcode: Opcode,
        cur_fin: bool,

        /// Initial state, ready for the first frame.
        pub const init: Self = .{
            .parser = .init,
            .validator = .init,
            .ctrl = .empty,
            .msg_opcode = .continuation,
            .cur_opcode = .continuation,
            .cur_fin = false,
        };

        /// High-level message produced by `feed`.
        pub const Message = union(enum) {
            /// A chunk of data payload (slice into the caller's input buffer,
            /// already unmasked). Delivered one or more times per message.
            data: []u8,
            /// The current data message is complete (final fragment received).
            data_end: DataEnd,
            /// A complete ping frame. Payload is valid until the next `feed` call.
            ping: []const u8,
            /// A complete pong frame. Payload is valid until the next `feed` call.
            pong: []const u8,
            /// A complete close frame was received. The raw payload can be parsed
            /// with `parseClosePayload` and echoed back to complete the closing handshake.
            close: []const u8,
            /// More input bytes are needed.
            need_more,

            pub const DataEnd = struct {
                /// The opcode from the first frame of the message (`.text` or `.binary`).
                opcode: Opcode,
            };
        };

        pub const Error =
            ParseError || MessageValidator.ValidationError;

        /// The return value of `feed`: how many bytes were consumed
        /// and the resulting message.
        pub const FeedResult = struct {
            consumed: usize,
            message: Message,
        };

        /// Feed raw bytes and get the next actionable message.
        /// Internal bookkeeping (header parsing, control payload accumulation,
        /// non-final frame boundaries) is handled automatically — only
        /// messages the caller needs to act on are returned.
        ///
        /// The caller must loop, advancing `input` by `consumed` bytes,
        /// until `.need_more` is returned or the input is exhausted.
        pub fn feed(self: *Self, input: []u8) Error!FeedResult {
            var data = input;
            while (true) {
                const result = try self.parser.feed(data);
                data = data[result.consumed..];

                switch (result.event) {
                    .frame_header => |hdr| {
                        try self.validator.check(hdr);
                        self.cur_opcode = hdr.opcode;
                        self.cur_fin = hdr.fin;
                        if (hdr.opcode == .text or hdr.opcode == .binary) {
                            self.msg_opcode = hdr.opcode;
                        } else if (hdr.opcode.isControl()) {
                            self.ctrl.reset();
                        }
                        continue;
                    },
                    .payload => |payload| {
                        if (self.cur_opcode.isControl()) {
                            // Parser guarantees control payloads <= 125 bytes.
                            self.ctrl.appendSliceAssumeCapacity(payload);
                            continue;
                        }
                        return .{
                            .consumed = input.len - data.len,
                            .message = .{ .data = payload },
                        };
                    },
                    .frame_end => {
                        if (self.cur_opcode.isControl()) {
                            const ctrl_payload = self.ctrl.constSlice();
                            const message: Message = switch (self.cur_opcode) {
                                .ping => .{ .ping = ctrl_payload },
                                .pong => .{ .pong = ctrl_payload },
                                .close => .{ .close = ctrl_payload },
                                else => continue,
                            };
                            return .{
                                .consumed = input.len - data.len,
                                .message = message,
                            };
                        }
                        if (self.cur_fin) {
                            return .{
                                .consumed = input.len - data.len,
                                .message = .{ .data_end = .{ .opcode = self.msg_opcode } },
                            };
                        }
                        // Non-final data frame — keep going.
                        continue;
                    },
                    .need_more => {
                        return .{
                            .consumed = input.len - data.len,
                            .message = .need_more,
                        };
                    },
                }
            }
        }

        /// Reset to initial state.
        pub fn reset(self: *Self) void {
            self.* = init;
        }
    };
}

test "Parser.init and reset" {
    var p: ServerParser = .init;
    try testing.expect(p.state == .header);
    try testing.expectEqual(0, p.state.header.len);

    p.state = .{ .payload = .{ .remaining = 10, .mask = .none } };
    p.reset();
    try testing.expect(p.state == .header);
    try testing.expectEqual(0, p.state.header.len);
}

test "feed: complete unmasked text frame in one call" {
    // Client parser (is_server=false) expects unmasked frames.
    var p: ClientParser = .init;
    // Build a simple text frame: FIN=1, opcode=text, payload="Hello"
    var buf: [7]u8 = undefined;
    buf[0] = 0x81; // FIN + text opcode
    buf[1] = 5; // payload length = 5, no mask
    @memcpy(buf[2..7], "Hello");

    // First feed: should get frame_header.
    var result = try p.feed(&buf);
    try testing.expectEqual(2, result.consumed);
    switch (result.event) {
        .frame_header => |hdr| {
            try testing.expect(hdr.fin);
            try testing.expectEqual(Opcode.text, hdr.opcode);
            try testing.expectEqual(5, hdr.payload_len);
            try testing.expect(hdr.mask_key == null);
        },
        else => return error.ReservedOpcode, // unexpected
    }

    // Second feed: payload.
    result = try p.feed(buf[result.consumed..]);
    try testing.expectEqual(5, result.consumed);
    try testing.expectEqualSlices(u8, "Hello", result.event.payload);

    // Third feed: frame_end.
    result = try p.feed(buf[7..]);
    try testing.expectEqual(0, result.consumed);
    try testing.expectEqual(Event.frame_end, result.event);
}

test "feed: masked frame (verify unmasking)" {
    // Server parser expects masked frames.
    var p = ServerParser.init;
    const mask_key = [4]u8{ 0x37, 0xFA, 0x21, 0x3D };
    const payload_text = "Hello";

    // Build masked frame.
    var buf: [2 + 4 + 5]u8 = undefined;
    buf[0] = 0x81; // FIN + text
    buf[1] = 0x80 | 5; // masked, length 5
    buf[2..6].* = mask_key;
    @memcpy(buf[6..11], payload_text);
    // Mask the payload.
    var m: Mask = .init(mask_key);
    m.apply(buf[6..11]);

    // Feed header.
    var result = try p.feed(&buf);
    try testing.expectEqual(6, result.consumed); // 2 base + 4 mask key
    switch (result.event) {
        .frame_header => |hdr| {
            try testing.expect(hdr.mask_key != null);
            try testing.expectEqual(mask_key, hdr.mask_key.?);
        },
        else => return error.ReservedOpcode,
    }

    // Feed payload — should be unmasked.
    result = try p.feed(buf[6..]);
    try testing.expectEqual(5, result.consumed);
    try testing.expectEqualSlices(u8, "Hello", result.event.payload);
}

test "feed: byte-at-a-time" {
    var p: ClientParser = .init;
    // Unmasked text frame "Hi" (2 bytes header + 2 bytes payload).
    var buf = [_]u8{ 0x81, 0x02, 'H', 'i' };

    var pos: usize = 0;
    var got_header = false;
    var got_payload = false;
    var got_end = false;

    while (pos < buf.len or !got_end) {
        const remaining = buf[pos..];
        const slice = if (remaining.len > 0) remaining[0..1] else remaining[0..0];
        const result = try p.feed(slice);
        pos += result.consumed;

        switch (result.event) {
            .frame_header => |hdr| {
                got_header = true;
                try testing.expectEqual(Opcode.text, hdr.opcode);
                try testing.expectEqual(2, hdr.payload_len);
            },
            .payload => |data| {
                got_payload = true;
                try testing.expectEqual(1, data.len);
            },
            .frame_end => {
                got_end = true;
            },
            .need_more => {},
        }
    }

    try testing.expect(got_header);
    try testing.expect(got_payload);
    try testing.expect(got_end);
}

test "feed: 126-byte extended length" {
    var p: ClientParser = .init;
    const payload_len: u16 = 200;

    // Header: 2 base + 2 extended = 4 bytes.
    var header_buf: [4]u8 = undefined;
    header_buf[0] = 0x82; // FIN + binary
    header_buf[1] = 126; // extended 16-bit length
    writeInt(u16, header_buf[2..4], payload_len);

    const result = try p.feed(&header_buf);
    try testing.expectEqual(4, result.consumed);
    switch (result.event) {
        .frame_header => |hdr| {
            try testing.expectEqual(200, hdr.payload_len);
            try testing.expectEqual(Opcode.binary, hdr.opcode);
        },
        else => return error.ReservedOpcode,
    }
}

test "feed: 127-byte (64-bit) extended length" {
    var p: ClientParser = .init;
    const payload_len: u64 = 70000;

    // Header: 2 base + 8 extended = 10 bytes.
    var header_buf: [10]u8 = undefined;
    header_buf[0] = 0x82; // FIN + binary
    header_buf[1] = 127; // extended 64-bit length
    writeInt(u64, header_buf[2..10], payload_len);

    const result = try p.feed(&header_buf);
    try testing.expectEqual(10, result.consumed);
    switch (result.event) {
        .frame_header => |hdr| {
            try testing.expectEqual(70000, hdr.payload_len);
        },
        else => return error.ReservedOpcode,
    }
}

test "feed: zero-length payload" {
    var p: ClientParser = .init;
    // Ping with no payload.
    var buf = [_]u8{ 0x89, 0x00 }; // FIN + ping, length 0

    var result = try p.feed(&buf);
    try testing.expectEqual(2, result.consumed);
    switch (result.event) {
        .frame_header => |hdr| {
            try testing.expectEqual(Opcode.ping, hdr.opcode);
            try testing.expectEqual(0, hdr.payload_len);
        },
        else => return error.ReservedOpcode,
    }

    // Next feed should immediately yield frame_end.
    var empty: [0]u8 = .{};
    result = try p.feed(&empty);
    try testing.expectEqual(0, result.consumed);
    try testing.expectEqual(Event.frame_end, result.event);
}

test "feed: multiple frames back to back" {
    var p: ClientParser = .init;
    // Two frames: ping (no payload) + text "AB".
    var buf = [_]u8{
        0x89, 0x00, // ping, len 0
        0x81, 0x02, 'A', 'B', // text, len 2
    };

    // Frame 1: header.
    var result = try p.feed(&buf);
    try testing.expectEqual(2, result.consumed);
    try testing.expectEqual(Opcode.ping, result.event.frame_header.opcode);

    // Frame 1: frame_end (zero payload).
    result = try p.feed(buf[2..]);
    try testing.expectEqual(0, result.consumed);
    try testing.expectEqual(Event.frame_end, result.event);

    // Frame 2: header.
    result = try p.feed(buf[2..]);
    try testing.expectEqual(2, result.consumed);
    try testing.expectEqual(Opcode.text, result.event.frame_header.opcode);

    // Frame 2: payload.
    result = try p.feed(buf[4..]);
    try testing.expectEqual(2, result.consumed);
    try testing.expectEqualSlices(u8, "AB", result.event.payload);

    // Frame 2: frame_end.
    result = try p.feed(buf[6..]);
    try testing.expectEqual(0, result.consumed);
    try testing.expectEqual(Event.frame_end, result.event);
}

test "feed: control frame too long" {
    var p: ClientParser = .init;
    // Ping with payload_len = 126 (via extended length) -- too long for control frame.
    var buf = [_]u8{ 0x89, 126, 0x00, 126 }; // ping, extended len = 126
    const result = p.feed(&buf);
    try testing.expectError(error.ControlFrameTooLong, result);
}

test "feed: control frame fragmented" {
    var p: ClientParser = .init;
    // Ping with FIN=0 — fragmented control frame.
    var buf = [_]u8{ 0x09, 0x00 }; // no FIN (0x09 not 0x89), ping, len 0
    const result = p.feed(&buf);
    try testing.expectError(error.ControlFrameFragmented, result);
}

test "feed: reserved opcode" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x83, 0x00 }; // FIN + reserved opcode 3
    const result = p.feed(&buf);
    try testing.expectError(error.ReservedOpcode, result);
}

test "feed: reserved RSV bit" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0xC1, 0x00 }; // FIN + RSV1 + text
    const result = p.feed(&buf);
    try testing.expectError(error.ReservedRsvBit, result);
}

test "feed: mask required (server expects mask)" {
    var p = ServerParser.init;
    var buf = [_]u8{ 0x81, 0x00 }; // FIN + text, no mask bit
    const result = p.feed(&buf);
    try testing.expectError(error.MaskRequired, result);
}

test "feed: mask not allowed (client rejects mask)" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x81, 0x80, 0, 0, 0, 0 }; // FIN + text, mask bit set
    const result = p.feed(&buf);
    try testing.expectError(error.MaskNotAllowed, result);
}

test "feed: partial header across multiple feeds" {
    var p: ClientParser = .init;

    // Text frame with 200-byte payload (extended length).
    // Full header: 0x82, 126, 0x00, 0xC8 (4 bytes).
    var hdr = [_]u8{ 0x82, 126, 0x00, 0xC8 };

    // Feed first byte.
    var result = try p.feed(hdr[0..1]);
    try testing.expectEqual(1, result.consumed);
    try testing.expectEqual(Event.need_more, result.event);

    // Feed second byte.
    result = try p.feed(hdr[1..2]);
    try testing.expectEqual(1, result.consumed);
    try testing.expectEqual(Event.need_more, result.event);

    // Feed remaining two bytes.
    result = try p.feed(hdr[2..4]);
    try testing.expectEqual(2, result.consumed);
    switch (result.event) {
        .frame_header => |h| {
            try testing.expectEqual(200, h.payload_len);
        },
        else => return error.ReservedOpcode,
    }
}

test "feed: all reserved non-control opcodes rejected (0x3-0x7)" {
    const reserved = [_]u8{ 0x3, 0x4, 0x5, 0x6, 0x7 };
    for (reserved) |opcode| {
        var p: ClientParser = .init;
        var buf = [_]u8{ 0x80 | opcode, 0x00 }; // FIN + reserved opcode
        try testing.expectError(error.ReservedOpcode, p.feed(&buf));
    }
}

test "feed: all reserved control opcodes rejected (0xB-0xF)" {
    const reserved = [_]u8{ 0xB, 0xC, 0xD, 0xE, 0xF };
    for (reserved) |opcode| {
        var p: ClientParser = .init;
        var buf = [_]u8{ 0x80 | opcode, 0x00 }; // FIN + reserved opcode
        try testing.expectError(error.ReservedOpcode, p.feed(&buf));
    }
}

test "feed: RSV1 alone rejected" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x80 | 0x40 | 0x01, 0x00 }; // FIN + RSV1 + text
    try testing.expectError(error.ReservedRsvBit, p.feed(&buf));
}

test "feed: RSV2 alone rejected" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x80 | 0x20 | 0x01, 0x00 }; // FIN + RSV2 + text
    try testing.expectError(error.ReservedRsvBit, p.feed(&buf));
}

test "feed: RSV3 alone rejected" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x80 | 0x10 | 0x01, 0x00 }; // FIN + RSV3 + text
    try testing.expectError(error.ReservedRsvBit, p.feed(&buf));
}

test "feed: all RSV bits set rejected" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x80 | 0x70 | 0x01, 0x00 }; // FIN + RSV1+2+3 + text
    try testing.expectError(error.ReservedRsvBit, p.feed(&buf));
}

test "feed: payload length exactly 125 (max 7-bit)" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x82, 125 }; // FIN + binary, len=125
    const result = try p.feed(&buf);
    try testing.expectEqual(@as(u64, 125), result.event.frame_header.payload_len);
}

test "feed: payload length exactly 126 uses 16-bit extended" {
    var p: ClientParser = .init;
    var buf: [4]u8 = undefined;
    buf[0] = 0x82; // FIN + binary
    buf[1] = 126;
    writeInt(u16, buf[2..4], 126);
    const result = try p.feed(&buf);
    try testing.expectEqual(@as(u64, 126), result.event.frame_header.payload_len);
}

test "feed: payload length exactly 65535 (max 16-bit)" {
    var p: ClientParser = .init;
    var buf: [4]u8 = undefined;
    buf[0] = 0x82;
    buf[1] = 126;
    writeInt(u16, buf[2..4], 65535);
    const result = try p.feed(&buf);
    try testing.expectEqual(@as(u64, 65535), result.event.frame_header.payload_len);
}

test "feed: payload length exactly 65536 uses 64-bit extended" {
    var p: ClientParser = .init;
    var buf: [10]u8 = undefined;
    buf[0] = 0x82;
    buf[1] = 127;
    writeInt(u64, buf[2..10], 65536);
    const result = try p.feed(&buf);
    try testing.expectEqual(@as(u64, 65536), result.event.frame_header.payload_len);
}

test "feed: reject non-minimal 16-bit encoding for length 125" {
    // 125 fits in 7 bits, must not use 16-bit extended
    var p: ClientParser = .init;
    var buf: [4]u8 = undefined;
    buf[0] = 0x82;
    buf[1] = 126; // claims 16-bit extended
    writeInt(u16, buf[2..4], 125); // but value fits in 7 bits
    try testing.expectError(error.InvalidPayloadLength, p.feed(&buf));
}

test "feed: reject non-minimal 16-bit encoding for length 0" {
    var p: ClientParser = .init;
    var buf: [4]u8 = undefined;
    buf[0] = 0x82;
    buf[1] = 126;
    writeInt(u16, buf[2..4], 0);
    try testing.expectError(error.InvalidPayloadLength, p.feed(&buf));
}

test "feed: reject non-minimal 64-bit encoding for length 125" {
    var p: ClientParser = .init;
    var buf: [10]u8 = undefined;
    buf[0] = 0x82;
    buf[1] = 127;
    writeInt(u64, buf[2..10], 125);
    try testing.expectError(error.InvalidPayloadLength, p.feed(&buf));
}

test "feed: reject non-minimal 64-bit encoding for length 65535" {
    // 65535 fits in 16 bits, must not use 64-bit extended
    var p: ClientParser = .init;
    var buf: [10]u8 = undefined;
    buf[0] = 0x82;
    buf[1] = 127;
    writeInt(u64, buf[2..10], 65535);
    try testing.expectError(error.InvalidPayloadLength, p.feed(&buf));
}

test "feed: reject 64-bit length with MSB set" {
    var p: ClientParser = .init;
    var buf: [10]u8 = @splat(0);
    buf[0] = 0x82;
    buf[1] = 127;
    // Set MSB of the 64-bit length
    buf[2] = 0x80;
    try testing.expectError(error.InvalidPayloadLength, p.feed(&buf));
}

test "feed: control frame with max payload 125 accepted" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x89, 125 }; // FIN + ping, len=125
    const result = try p.feed(&buf);
    try testing.expectEqual(@as(u64, 125), result.event.frame_header.payload_len);
}

test "feed: control frame with payload 126 rejected" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x89, 126, 0x00, 126 }; // ping with 16-bit len
    try testing.expectError(error.ControlFrameTooLong, p.feed(&buf));
}

test "feed: close frame with FIN=0 rejected" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x08, 0x00 }; // close without FIN
    try testing.expectError(error.ControlFrameFragmented, p.feed(&buf));
}

test "feed: ping frame with FIN=0 rejected" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x09, 0x00 }; // ping without FIN
    try testing.expectError(error.ControlFrameFragmented, p.feed(&buf));
}

test "feed: pong frame with FIN=0 rejected" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x0A, 0x00 }; // pong without FIN
    try testing.expectError(error.ControlFrameFragmented, p.feed(&buf));
}

test "feed: continuation frame opcode parsed correctly" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x00, 0x02, 'A', 'B' }; // continuation, FIN=0, len=2
    const result = try p.feed(&buf);
    try testing.expectEqual(Opcode.continuation, result.event.frame_header.opcode);
    try testing.expect(!result.event.frame_header.fin);
}

test "feed: final continuation frame has FIN set" {
    var p: ClientParser = .init;
    var buf = [_]u8{ 0x80, 0x02, 'A', 'B' }; // continuation, FIN=1, len=2
    const result = try p.feed(&buf);
    try testing.expectEqual(Opcode.continuation, result.event.frame_header.opcode);
    try testing.expect(result.event.frame_header.fin);
}

test "feed: fragmented text message sequence" {
    var p: ClientParser = .init;

    // First fragment: text, FIN=0, "Hel"
    var f1 = [_]u8{ 0x01, 0x03, 'H', 'e', 'l' };
    var result = try p.feed(&f1);
    try testing.expectEqual(Opcode.text, result.event.frame_header.opcode);
    try testing.expect(!result.event.frame_header.fin);

    // Consume payload and frame_end
    result = try p.feed(f1[2..]);
    try testing.expectEqualSlices(u8, "Hel", result.event.payload);
    result = try p.feed(f1[5..]);
    try testing.expectEqual(Event.frame_end, result.event);

    // Final fragment: continuation, FIN=1, "lo"
    var f2 = [_]u8{ 0x80, 0x02, 'l', 'o' };
    result = try p.feed(&f2);
    try testing.expectEqual(Opcode.continuation, result.event.frame_header.opcode);
    try testing.expect(result.event.frame_header.fin);

    result = try p.feed(f2[2..]);
    try testing.expectEqualSlices(u8, "lo", result.event.payload);
    result = try p.feed(f2[4..]);
    try testing.expectEqual(Event.frame_end, result.event);
}

test "feed: control frame interleaved in fragmented message" {
    var p: ClientParser = .init;

    // Fragment 1: text, FIN=0, "A"
    var f1 = [_]u8{ 0x01, 0x01, 'A' };
    var result = try p.feed(&f1);
    try testing.expectEqual(Opcode.text, result.event.frame_header.opcode);
    result = try p.feed(f1[2..]);
    // consume payload
    var empty: [0]u8 = .{};
    result = try p.feed(&empty);
    try testing.expectEqual(Event.frame_end, result.event);

    // Interleaved ping (control frames allowed mid-fragment)
    var ping = [_]u8{ 0x89, 0x00 }; // FIN + ping, no payload
    result = try p.feed(&ping);
    try testing.expectEqual(Opcode.ping, result.event.frame_header.opcode);
    result = try p.feed(&empty);
    try testing.expectEqual(Event.frame_end, result.event);

    // Fragment 2: continuation, FIN=1, "B"
    var f2 = [_]u8{ 0x80, 0x01, 'B' };
    result = try p.feed(&f2);
    try testing.expectEqual(Opcode.continuation, result.event.frame_header.opcode);
    try testing.expect(result.event.frame_header.fin);
}

test "round-trip: FrameHeader.Buffer → feed for all standard opcodes" {
    const opcodes = [_]Opcode{ .text, .binary, .close, .ping, .pong, .continuation };
    for (opcodes) |opcode| {
        var p: ClientParser = .init;
        const header: FrameHeader.Buffer = .init(.{
            .opcode = opcode,
            .payload_len = 10,
            .fin = if (opcode.isControl()) true else false,
        });
        const bytes = header.constSlice();
        var buf: [max_header_len]u8 = undefined;
        @memcpy(buf[0..bytes.len], bytes);
        const result = try p.feed(buf[0..bytes.len]);
        try testing.expectEqual(opcode, result.event.frame_header.opcode);
        try testing.expectEqual(@as(u64, 10), result.event.frame_header.payload_len);
    }
}

test "round-trip: FrameHeader.Buffer → feed with mask" {
    const mask_key = [4]u8{ 0x37, 0xFA, 0x21, 0x3D };
    var p = ServerParser.init; // server expects masked

    const header: FrameHeader.Buffer = .init(.{
        .opcode = .text,
        .payload_len = 5,
        .mask_key = mask_key,
    });
    const bytes = header.constSlice();

    var buf: [max_header_len]u8 = undefined;
    @memcpy(buf[0..bytes.len], bytes);
    const result = try p.feed(buf[0..bytes.len]);
    const hdr = result.event.frame_header;
    try testing.expect(hdr.mask_key != null);
    try testing.expectEqual(mask_key, hdr.mask_key.?);
    try testing.expectEqual(@as(u64, 5), hdr.payload_len);
}

test "round-trip: FrameHeader.Buffer → feed at all length boundaries" {
    const lengths = [_]u64{ 0, 1, 125, 126, 127, 256, 65535, 65536, 100000 };
    for (lengths) |payload_len| {
        var p: ClientParser = .init;
        const header: FrameHeader.Buffer = .init(.{
            .opcode = .binary,
            .payload_len = payload_len,
        });
        const bytes = header.constSlice();

        var buf: [max_header_len]u8 = undefined;
        @memcpy(buf[0..bytes.len], bytes);
        const result = try p.feed(buf[0..bytes.len]);
        try testing.expectEqual(payload_len, result.event.frame_header.payload_len);
    }
}

fn makeHeader(opcode: Opcode, fin: bool) FrameHeader {
    return .{
        .fin = fin,
        .rsv = .empty,
        .opcode = opcode,
        .payload_len = 10,
        .mask_key = null,
    };
}

test "MessageValidator: unfragmented text message" {
    var v: MessageValidator = .init;
    try v.check(makeHeader(.text, true));
}

test "MessageValidator: unfragmented binary message" {
    var v: MessageValidator = .init;
    try v.check(makeHeader(.binary, true));
}

test "MessageValidator: fragmented text message" {
    var v: MessageValidator = .init;
    // First fragment: text, FIN=false.
    try v.check(makeHeader(.text, false));
    // Continuation, FIN=false.
    try v.check(makeHeader(.continuation, false));
    // Final continuation, FIN=true.
    try v.check(makeHeader(.continuation, true));
}

test "MessageValidator: continuation without initial frame" {
    var v: MessageValidator = .init;
    try testing.expectError(
        error.UnexpectedContinuation,
        v.check(makeHeader(.continuation, true)),
    );
}

test "MessageValidator: bare continuation FIN=false without initial frame" {
    var v: MessageValidator = .init;
    try testing.expectError(
        error.UnexpectedContinuation,
        v.check(makeHeader(.continuation, false)),
    );
}

test "MessageValidator: new text frame mid-fragment" {
    var v: MessageValidator = .init;
    try v.check(makeHeader(.text, false));
    try testing.expectError(
        error.ExpectedContinuation,
        v.check(makeHeader(.text, true)),
    );
}

test "MessageValidator: new binary frame mid-fragment" {
    var v: MessageValidator = .init;
    try v.check(makeHeader(.text, false));
    try testing.expectError(
        error.ExpectedContinuation,
        v.check(makeHeader(.binary, true)),
    );
}

test "MessageValidator: control frame interleaved mid-fragment" {
    var v: MessageValidator = .init;
    // Start fragment.
    try v.check(makeHeader(.text, false));
    // Interleaved ping — always allowed.
    try v.check(makeHeader(.ping, true));
    // Interleaved pong — always allowed.
    try v.check(makeHeader(.pong, true));
    // Interleaved close — always allowed.
    try v.check(makeHeader(.close, true));
    // Continue the fragment.
    try v.check(makeHeader(.continuation, false));
    // Finish.
    try v.check(makeHeader(.continuation, true));
}

test "MessageValidator: multiple complete messages in sequence" {
    var v: MessageValidator = .init;
    // First message: unfragmented.
    try v.check(makeHeader(.text, true));
    // Second message: fragmented.
    try v.check(makeHeader(.binary, false));
    try v.check(makeHeader(.continuation, true));
    // Third message: unfragmented.
    try v.check(makeHeader(.text, true));
}

test "MessageValidator: back to idle after completed fragment" {
    var v: MessageValidator = .init;
    try v.check(makeHeader(.text, false));
    try v.check(makeHeader(.continuation, true));
    // Should be idle now — continuation here is invalid.
    try testing.expectError(
        error.UnexpectedContinuation,
        v.check(makeHeader(.continuation, true)),
    );
}

/// Build a masked frame in `out`. Returns the total frame length.
fn buildMaskedFrame(out: []u8, opcode: Opcode, fin: bool, payload: []const u8) usize {
    const mask_key = [4]u8{ 0x37, 0xFA, 0x21, 0x3D };
    var byte0: u8 = @intFromEnum(opcode);
    if (fin) byte0 |= 0x80;
    out[0] = byte0;
    out[1] = 0x80 | @as(u8, @intCast(payload.len));
    out[2..6].* = mask_key;
    @memcpy(out[6..][0..payload.len], payload);
    var m: Mask = .init(mask_key);
    m.apply(out[6..][0..payload.len]);
    return 6 + payload.len;
}

test "FrameHandler: single text message" {
    var h: ServerFrameHandler = .init;
    var buf: [64]u8 = undefined;
    const len = buildMaskedFrame(&buf, .text, true, "Hello");

    var data = buf[0..len];
    const r1 = try h.feed(data);
    data = data[r1.consumed..];
    try testing.expectEqualSlices(u8, "Hello", r1.message.data);

    const r2 = try h.feed(data);
    try testing.expectEqual(
        @as(ServerFrameHandler.Message, .{ .data_end = .{ .opcode = .text } }),
        r2.message,
    );
}

test "FrameHandler: binary message" {
    var h: ServerFrameHandler = .init;
    var buf: [64]u8 = undefined;
    const payload = &[_]u8{ 0x01, 0x02, 0x03 };
    const len = buildMaskedFrame(&buf, .binary, true, payload);

    var data = buf[0..len];
    const r1 = try h.feed(data);
    data = data[r1.consumed..];
    try testing.expectEqualSlices(u8, payload, r1.message.data);

    const r2 = try h.feed(data);
    try testing.expectEqual(
        @as(ServerFrameHandler.Message, .{ .data_end = .{ .opcode = .binary } }),
        r2.message,
    );
}

test "FrameHandler: ping produces .ping" {
    var h: ServerFrameHandler = .init;
    var buf: [64]u8 = undefined;
    const len = buildMaskedFrame(&buf, .ping, true, "ping!");

    const result = try h.feed(buf[0..len]);
    try testing.expectEqualSlices(u8, "ping!", result.message.ping);
}

test "FrameHandler: pong produces .pong" {
    var h: ServerFrameHandler = .init;
    var buf: [64]u8 = undefined;
    const len = buildMaskedFrame(&buf, .pong, true, "pong!");

    const result = try h.feed(buf[0..len]);
    try testing.expectEqualSlices(u8, "pong!", result.message.pong);
}

test "FrameHandler: close produces .close with raw payload" {
    var h: ServerFrameHandler = .init;
    var buf: [64]u8 = undefined;
    const close_body = CloseCode.normal.toBytes() ++ "bye".*;
    const len = buildMaskedFrame(&buf, .close, true, &close_body);

    const result = try h.feed(buf[0..len]);
    try testing.expectEqualSlices(u8, &close_body, result.message.close);

    // Caller can parse it with parseClosePayload.
    const parsed = (try parseClosePayload(result.message.close)).?;
    try testing.expectEqual(CloseCode.normal, parsed.code);
    try testing.expectEqualStrings("bye", parsed.reason);
}

test "FrameHandler: empty close frame" {
    var h: ServerFrameHandler = .init;
    var buf: [64]u8 = undefined;
    const len = buildMaskedFrame(&buf, .close, true, "");

    const result = try h.feed(buf[0..len]);
    try testing.expectEqual(@as(usize, 0), result.message.close.len);
}

test "FrameHandler: fragmented message preserves original opcode" {
    var h: ServerFrameHandler = .init;
    var buf: [128]u8 = undefined;

    // First fragment: text, FIN=false
    const len1 = buildMaskedFrame(&buf, .text, false, "Hel");
    var data = buf[0..len1];
    const r1 = try h.feed(data);
    data = data[r1.consumed..];
    try testing.expectEqualSlices(u8, "Hel", r1.message.data);

    // Non-final continuation frame_end is skipped (returns need_more).
    const r2 = try h.feed(data);
    try testing.expectEqual(.need_more, r2.message);

    // Final fragment: continuation, FIN=true
    const len2 = buildMaskedFrame(buf[0..], .continuation, true, "lo");
    data = buf[0..len2];
    const r3 = try h.feed(data);
    data = data[r3.consumed..];
    try testing.expectEqualSlices(u8, "lo", r3.message.data);

    const r4 = try h.feed(data);
    try testing.expectEqual(
        @as(ServerFrameHandler.Message, .{ .data_end = .{ .opcode = .text } }),
        r4.message,
    );
}

test "FrameHandler: control frame interleaved mid-fragment" {
    var h: ServerFrameHandler = .init;
    var buf: [128]u8 = undefined;

    // First fragment: text, FIN=false
    var len = buildMaskedFrame(&buf, .text, false, "abc");
    var data = buf[0..len];
    var r = try h.feed(data);
    try testing.expectEqualSlices(u8, "abc", r.message.data);

    // Consume remaining (non-final frame_end → need_more)
    data = data[r.consumed..];
    r = try h.feed(data);
    try testing.expectEqual(.need_more, r.message);

    // Interleaved ping
    len = buildMaskedFrame(&buf, .ping, true, "P");
    r = try h.feed(buf[0..len]);
    try testing.expectEqualSlices(u8, "P", r.message.ping);

    // Final continuation
    len = buildMaskedFrame(&buf, .continuation, true, "def");
    data = buf[0..len];
    r = try h.feed(data);
    data = data[r.consumed..];
    try testing.expectEqualSlices(u8, "def", r.message.data);

    r = try h.feed(data);
    try testing.expectEqual(
        @as(ServerFrameHandler.Message, .{ .data_end = .{ .opcode = .text } }),
        r.message,
    );
}

test "FrameHandler: validation error on unexpected continuation" {
    var h: ServerFrameHandler = .init;
    var buf: [64]u8 = undefined;
    const len = buildMaskedFrame(&buf, .continuation, true, "bad");

    const result = h.feed(buf[0..len]);
    try testing.expectError(error.UnexpectedContinuation, result);
}

test "FrameHandler: need_more on partial input" {
    var h: ServerFrameHandler = .init;
    // Just one byte — not enough for a header.
    var buf = [_]u8{0x81};
    const result = try h.feed(&buf);
    try testing.expectEqual(.need_more, result.message);
}
