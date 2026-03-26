//! Writes a fragmented WebSocket message across multiple frames, managing
//! the opcode and continuation state automatically.
//!
//! The first call to `writeChunk` sends a frame with the original opcode
//! and `fin = false`. Subsequent chunks send continuation frames. Call
//! `finish` to send the final frame with `fin = true`.
//!
//! ```
//! var msg: ws.MessageWriter = .init(writer, .{ .opcode = .text });
//! try msg.writeChunk(part1);
//! try msg.writeChunk(part2);
//! try msg.finish(part3);
//! ```
//!
//! For unfragmented messages, prefer `writeFrame` instead.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;

const frame = @import("frame.zig");
const FrameHeader = frame.FrameHeader;
const Opcode = frame.Opcode;
const RsvBits = frame.RsvBits;
const root = @import("root.zig");
const WriteFrameOptions = root.WriteFrameOptions;

writer: *Io.Writer,
opcode: Opcode,
rsv: RsvBits,

const MessageWriter = @This();

pub fn init(writer: *Io.Writer, options: WriteFrameOptions) MessageWriter {
    assert(options.opcode == .text or options.opcode == .binary);
    return .{
        .writer = writer,
        .opcode = options.opcode,
        .rsv = if (options.compressed) .{ .rsv1 = true } else .{},
    };
}

/// Write a non-final frame. The first call uses the original opcode;
/// subsequent calls use `.continuation`.
pub fn writeChunk(self: *MessageWriter, payload: []const u8) Io.Writer.Error!void {
    const header: FrameHeader.Buffer = .init(.{
        .fin = false,
        .rsv = self.rsv,
        .opcode = self.opcode,
        .payload_len = payload.len,
    });
    try header.write(self.writer);
    if (payload.len > 0) try self.writer.writeAll(payload);
    self.opcode = .continuation;
    self.rsv = .empty; // RSV1 only on first frame per RFC 7692 §6.1
}

/// Send the final frame with `fin = true`, completing the message.
/// Pass an optional last chunk of payload, or `null` for an empty
/// final frame.
pub fn finish(self: *MessageWriter, payload: ?[]const u8) Io.Writer.Error!void {
    const data = payload orelse &.{};
    const header: FrameHeader.Buffer = .init(.{
        .fin = true,
        .rsv = self.rsv,
        .opcode = self.opcode,
        .payload_len = data.len,
    });
    try header.write(self.writer);
    if (data.len > 0) try self.writer.writeAll(data);
}

test "single chunk finish" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: MessageWriter = .init(&writer, .{ .opcode = .text });
    try msg.finish("hello");

    try testing.expectEqual(@as(u8, 0x81), buf[0]); // fin + text
    try testing.expectEqual(@as(u8, 5), buf[1]);
    try testing.expectEqualStrings("hello", buf[2..7]);
}

test "two chunks and finish" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: MessageWriter = .init(&writer, .{ .opcode = .binary });
    try msg.writeChunk("ab");
    try msg.writeChunk("cd");
    try msg.finish("ef");

    // Frame 1: fin=false, opcode=binary, len=2, "ab"
    try testing.expectEqual(@as(u8, 0x02), buf[0]); // no fin + binary
    try testing.expectEqual(@as(u8, 2), buf[1]);
    try testing.expectEqualStrings("ab", buf[2..4]);

    // Frame 2: fin=false, opcode=continuation, len=2, "cd"
    try testing.expectEqual(@as(u8, 0x00), buf[4]); // no fin + continuation
    try testing.expectEqual(@as(u8, 2), buf[5]);
    try testing.expectEqualStrings("cd", buf[6..8]);

    // Frame 3: fin=true, opcode=continuation, len=2, "ef"
    try testing.expectEqual(@as(u8, 0x80), buf[8]); // fin + continuation
    try testing.expectEqual(@as(u8, 2), buf[9]);
    try testing.expectEqualStrings("ef", buf[10..12]);
}

test "finish with null payload" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: MessageWriter = .init(&writer, .{ .opcode = .text });
    try msg.writeChunk("data");
    try msg.finish(null);

    // Frame 1: fin=false, opcode=text, len=4
    try testing.expectEqual(@as(u8, 0x01), buf[0]); // no fin + text
    try testing.expectEqual(@as(u8, 4), buf[1]);

    // Frame 2: fin=true, opcode=continuation, len=0
    try testing.expectEqual(@as(u8, 0x80), buf[6]); // fin + continuation
    try testing.expectEqual(@as(u8, 0), buf[7]);
}

test "compressed: RSV1 on first frame only" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: MessageWriter = .init(&writer, .{ .opcode = .text, .compressed = true });
    try msg.writeChunk("ab");
    try msg.writeChunk("cd");
    try msg.finish("ef");

    // Frame 1: fin=false, RSV1=1, opcode=text -> 0x41
    try testing.expectEqual(@as(u8, 0x41), buf[0]);
    try testing.expectEqual(@as(u8, 2), buf[1]);

    // Frame 2: fin=false, RSV1=0, opcode=continuation -> 0x00
    try testing.expectEqual(@as(u8, 0x00), buf[4]);

    // Frame 3: fin=true, RSV1=0, opcode=continuation -> 0x80
    try testing.expectEqual(@as(u8, 0x80), buf[8]);
}

test "compressed: single frame finish sets RSV1" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: MessageWriter = .init(&writer, .{ .opcode = .binary, .compressed = true });
    try msg.finish("data");

    // fin=true, RSV1=1, opcode=binary -> 0xC2
    try testing.expectEqual(@as(u8, 0xC2), buf[0]);
    try testing.expectEqual(@as(u8, 4), buf[1]);
}
