//! Server-role WebSocket API.
//!
//! `Parser` and `FrameHandler` accept masked frames from clients.
//! `writeFrame` and `MessageWriter` emit unmasked outbound frames.
//! `UpgradeRequest`, `validateUpgradeRequest`, and `UpgradeResponse` cover the
//! WebSocket-specific handshake pieces for an HTTP server.

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
/// Buffer type for a base64-encoded `Sec-WebSocket-Accept` value.
pub const AcceptKey = frame.AcceptKey;
const handshake = @import("handshake.zig");
/// Compute the `Sec-WebSocket-Accept` header value for an upgrade response.
pub const computeAcceptKey = handshake.computeAcceptKey;
/// WebSocket-specific fields extracted from an HTTP upgrade request.
pub const UpgradeRequest = handshake.UpgradeRequest;
/// Validate the WebSocket-specific headers from an upgrade request.
pub const validateUpgradeRequest = handshake.validateUpgradeRequest;
/// Prebuilt HTTP 101 response for a successful WebSocket upgrade.
pub const UpgradeResponse = handshake.UpgradeResponse;
/// Fragmented message writer that leaves each emitted frame unmasked.
pub const MessageWriter = @import("message_writer.zig").ServerMessageWriter;
const parse = @import("parse.zig");
/// Frame parser for masked frames received by a server.
pub const Parser = parse.ServerParser;
/// Message-oriented parser for server connections.
pub const FrameHandler = parse.ServerFrameHandler;
/// Parser options shared by both roles.
pub const Options = parse.Options;
/// Fragmentation validator shared by both roles.
pub const MessageValidator = parse.MessageValidator;

/// Write a complete frame (header + payload) to `writer`. The caller is
/// responsible for flushing when ready — this allows batching multiple
/// frames before a single flush.
pub fn writeFrame(
    writer: *Io.Writer,
    payload: []const u8,
    options: WriteFrameOptions,
) Io.Writer.Error!void {
    assert(!options.opcode.isReserved());
    assert(!options.opcode.isControl() or payload.len <= 125);
    assert(!options.opcode.isControl() or !options.compressed);
    const rsv: RsvBits = if (options.compressed) .permessage_deflate else .empty;
    const header: FrameHeader.Buffer = .init(.{
        .opcode = options.opcode,
        .rsv = rsv,
        .payload_len = payload.len,
    });
    try header.write(writer);
    if (payload.len > 0) try writer.writeAll(payload);
}

/// Write a close frame with a status code (no reason text).
pub fn writeClose(writer: *Io.Writer, code: CloseCode) Io.Writer.Error!void {
    const body = code.toBytes();
    try writeFrame(writer, &body, .{ .opcode = .close, .compressed = false });
}

/// Write a ping frame with an optional payload.
pub fn writePing(writer: *Io.Writer, payload: []const u8) Io.Writer.Error!void {
    try writeFrame(writer, payload, .{ .opcode = .ping, .compressed = false });
}

/// Write a pong frame with the given payload (typically echoed from a ping).
pub fn writePong(writer: *Io.Writer, payload: []const u8) Io.Writer.Error!void {
    try writeFrame(writer, payload, .{ .opcode = .pong, .compressed = false });
}

test "writeFrame: unmasked text frame" {
    var buf: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    try writeFrame(&writer, "hello", .{ .opcode = .text });

    try testing.expectEqual(@as(u8, 0x81), buf[0]);
    try testing.expectEqual(@as(u8, 5), buf[1]);
    try testing.expectEqualStrings("hello", buf[2..7]);
}

test "writeFrame: compressed frame sets RSV1" {
    var buf: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    try writeFrame(&writer, "data", .{ .opcode = .text, .compressed = true });

    try testing.expectEqual(@as(u8, 0xC1), buf[0]); // FIN + RSV1 + text
    try testing.expectEqual(@as(u8, 4), buf[1]);
    try testing.expectEqualStrings("data", buf[2..6]);
}

test "writeClose: unmasked close frame with status code" {
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    try writeClose(&writer, .normal);

    try testing.expectEqual(@as(u8, 0x88), buf[0]);
    try testing.expectEqual(@as(u8, 2), buf[1]);
    try testing.expectEqual(@as(u8, 0x03), buf[2]);
    try testing.expectEqual(@as(u8, 0xE8), buf[3]);
}

test "writePing: unmasked ping frame" {
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    try writePing(&writer, "ping");

    try testing.expectEqual(@as(u8, 0x89), buf[0]);
    try testing.expectEqual(@as(u8, 4), buf[1]);
    try testing.expectEqualStrings("ping", buf[2..6]);
}

test "writePong: unmasked pong frame" {
    var buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    try writePong(&writer, "pong");

    try testing.expectEqual(@as(u8, 0x8A), buf[0]);
    try testing.expectEqual(@as(u8, 4), buf[1]);
    try testing.expectEqualStrings("pong", buf[2..6]);
}

test {
    testing.refAllDecls(@This());
}
