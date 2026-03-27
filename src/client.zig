//! Client-role WebSocket API.
//!
//! `Parser` and `FrameHandler` accept unmasked frames from the server.
//! `writeFrame` and `MessageWriter` mask outbound frames in place.
//! `computeAcceptKey` helps verify the server's `Sec-WebSocket-Accept` value.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const testing = std.testing;

const close = @import("close.zig");
/// Close status codes defined by RFC 6455 Section 7.4.
pub const CloseCode = close.CloseCode;
/// Parsed close frame payload containing the status code and optional reason bytes.
pub const ClosePayload = close.ClosePayload;
/// Parse and validate a close frame payload.
pub const parseClosePayload = close.parseClosePayload;
/// Supported negotiated WebSocket extensions.
pub const Extension = @import("extension.zig").Extension;
const frame = @import("frame.zig");
/// Buffer type for a base64-encoded `Sec-WebSocket-Accept` value.
pub const AcceptKey = frame.AcceptKey;
/// WebSocket frame opcode.
pub const Opcode = frame.Opcode;
/// Decoded frame header and its serialized buffer helper.
pub const FrameHeader = frame.FrameHeader;
/// Four-byte masking key used by client frames.
pub const MaskKey = frame.MaskKey;
/// Stateful XOR mask for masking and unmasking payload bytes.
pub const Mask = frame.Mask;
/// RSV bitset from the frame header.
pub const RsvBits = frame.RsvBits;
/// Streaming parser event.
pub const Event = frame.Event;
/// Protocol errors reported while parsing inbound frames.
pub const ParseError = frame.ParseError;
/// Options for frame-writing helpers.
pub const WriteFrameOptions = frame.WriteFrameOptions;
/// Generate a cryptographically random masking key.
pub const generateMaskKey = frame.generateMaskKey;
/// Maximum payload length for WebSocket control frames (ping, pong, close).
pub const max_control_payload_len = frame.max_control_payload_len;
const handshake = @import("handshake.zig");
/// Compute the expected `Sec-WebSocket-Accept` header value for a client handshake.
pub const computeAcceptKey = handshake.computeAcceptKey;
/// Fragmented message writer that masks each emitted frame.
pub const MessageWriter = @import("message_writer.zig").ClientMessageWriter;
const parse = @import("parse.zig");
/// Frame parser for unmasked frames received by a client.
pub const Parser = parse.ClientParser;
/// Message-oriented parser for client connections.
pub const FrameHandler = parse.ClientFrameHandler;
/// Parser options shared by both roles.
pub const Options = parse.Options;
/// Fragmentation validator shared by both roles.
pub const MessageValidator = parse.MessageValidator;

/// Write a complete masked frame (header + payload) to `writer`.
/// Clients MUST mask all frames per RFC 6455 Section 5.3.
///
/// `payload` is mutable because masking is applied in-place before writing.
/// The buffer contents will be XOR'd with the mask key after this call returns.
/// Callers who need to retain the original data should copy it first.
pub fn writeFrame(
    writer: *Io.Writer,
    payload: []u8,
    options: WriteFrameOptions,
) Io.Writer.Error!void {
    assert(!options.opcode.isReserved());
    assert(!options.opcode.isControl() or payload.len <= frame.max_control_payload_len);
    assert(!options.opcode.isControl() or !options.compressed);
    const mask_key = generateMaskKey();
    const rsv: RsvBits = if (options.compressed) .permessage_deflate else .empty;
    const header: FrameHeader.Buffer = .init(.{
        .opcode = options.opcode,
        .rsv = rsv,
        .payload_len = payload.len,
        .mask_key = mask_key,
    });
    try header.write(writer);
    if (payload.len > 0) {
        var mask: Mask = .init(mask_key);
        mask.apply(payload);
        try writer.writeAll(payload);
    }
}

/// Write a masked close frame with a status code (no reason text).
pub fn writeClose(writer: *Io.Writer, code: CloseCode) Io.Writer.Error!void {
    var body = code.toBytes();
    try writeFrame(writer, &body, .{ .opcode = .close, .compressed = false });
}

/// Write a masked ping frame with an optional payload.
pub fn writePing(writer: *Io.Writer, payload: []u8) Io.Writer.Error!void {
    try writeFrame(writer, payload, .{ .opcode = .ping, .compressed = false });
}

/// Write a masked pong frame with the given payload (typically echoed from a ping).
pub fn writePong(writer: *Io.Writer, payload: []u8) Io.Writer.Error!void {
    try writeFrame(writer, payload, .{ .opcode = .pong, .compressed = false });
}

test "writeFrame: masked text frame" {
    var buf: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var payload = "hello".*;
    try writeFrame(&writer, &payload, .{ .opcode = .text });

    // FIN + text
    try testing.expectEqual(@as(u8, 0x81), buf[0]);
    // MASK bit set | len=5
    try testing.expectEqual(@as(u8, 0x85), buf[1]);
    // Mask key at bytes 2..6
    const mask_key = buf[2..6].*;
    var expected = "hello".*;
    var mask: Mask = .init(mask_key);
    mask.apply(&expected);
    try testing.expectEqualSlices(u8, &expected, buf[6..11]);
    try testing.expect(!std.mem.eql(u8, &payload, "hello"));
}

test "writeFrame: empty payload" {
    var writer: Io.Writer.Allocating = .init(testing.allocator);
    defer writer.deinit();

    var payload: [0]u8 = .{};
    try writeFrame(&writer.writer, &payload, .{ .opcode = .binary });

    const written = writer.written();
    try testing.expectEqual(@as(usize, 6), written.len);
    try testing.expectEqual(@as(u8, 0x82), written[0]); // FIN + binary
    try testing.expectEqual(@as(u8, 0x80), written[1]); // MASK bit set, len=0
}

test "writeFrame: compressed frame sets RSV1" {
    var buf: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var payload = "data".*;
    try writeFrame(&writer, &payload, .{ .opcode = .text, .compressed = true });

    try testing.expectEqual(@as(u8, 0xC1), buf[0]); // FIN + RSV1 + text
    try testing.expectEqual(@as(u8, 0x84), buf[1]); // MASK bit set, len=4
}

test "writeClose: masked close frame with status code" {
    var buf: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    try writeClose(&writer, .normal);

    try testing.expectEqual(@as(u8, 0x88), buf[0]); // FIN + close
    try testing.expectEqual(@as(u8, 0x82), buf[1]); // MASK | len=2
    const mask_key = buf[2..6].*;
    var close_body = buf[6..8].*;
    var mask: Mask = .init(mask_key);
    mask.apply(&close_body);
    const code = std.mem.readInt(u16, &close_body, .big);
    try testing.expectEqual(@as(u16, 1000), code);
}

test "writePing: masked ping frame" {
    var buf: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var payload = "ping".*;
    try writePing(&writer, &payload);

    try testing.expectEqual(@as(u8, 0x89), buf[0]); // FIN + ping
    try testing.expect(buf[1] & 0x80 != 0); // MASK bit set
    try testing.expectEqual(@as(u8, 4), buf[1] & 0x7F); // len=4
}

test "writePong: masked pong frame" {
    var buf: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var payload = "pong".*;
    try writePong(&writer, &payload);

    try testing.expectEqual(@as(u8, 0x8A), buf[0]); // FIN + pong
    try testing.expect(buf[1] & 0x80 != 0); // MASK bit set
    try testing.expectEqual(@as(u8, 4), buf[1] & 0x7F); // len=4
}

test {
    testing.refAllDecls(@This());
}
