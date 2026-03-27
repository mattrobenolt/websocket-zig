//! Writes a fragmented WebSocket message across multiple frames, managing
//! the opcode and continuation state automatically.
//!
//! The first call to `writeChunk` sends a frame with the original opcode
//! and `fin = false`. Subsequent chunks send continuation frames. Call
//! `finish` to send the final frame with `fin = true`.
//!
//! For unfragmented messages, prefer `writeFrame` instead.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;

const frame = @import("frame.zig");
const FrameHeader = frame.FrameHeader;
const generateMaskKey = frame.generateMaskKey;
const Mask = frame.Mask;
const MaskKey = frame.MaskKey;
const Opcode = frame.Opcode;
const RsvBits = frame.RsvBits;
const WriteFrameOptions = frame.WriteFrameOptions;

/// Fragmented message writer for server connections (unmasked frames).
pub const ServerMessageWriter = MessageWriter(false);
/// Fragmented message writer for client connections (masked frames).
pub const ClientMessageWriter = MessageWriter(true);

fn MessageWriter(comptime masked: bool) type {
    const Payload = if (masked) []u8 else []const u8;

    return struct {
        writer: *Io.Writer,
        opcode: Opcode,
        rsv: RsvBits,

        const Self = @This();

        /// Initialize a fragmented message writer for `.text` or `.binary` messages.
        /// When `compressed` is set, RSV1 is applied only to the first frame.
        pub fn init(writer: *Io.Writer, options: WriteFrameOptions) Self {
            assert(options.opcode == .text or options.opcode == .binary);
            return .{
                .writer = writer,
                .opcode = options.opcode,
                .rsv = if (options.compressed) .permessage_deflate else .empty,
            };
        }

        /// Write a non-final frame. The first call uses the original opcode;
        /// subsequent calls use `.continuation`.
        ///
        /// When masked, the payload is XOR'd in-place before writing.
        pub fn writeChunk(self: *Self, payload: Payload) Io.Writer.Error!void {
            try self.writePayload(false, payload);
            self.opcode = .continuation;
            self.rsv = .empty; // RSV1 only on first frame per RFC 7692 §6.1
        }

        /// Send the final frame with `fin = true`, completing the message.
        /// Pass an optional last chunk of payload, or `null` for an empty
        /// final frame.
        ///
        /// When masked, the payload is XOR'd in-place before writing.
        pub fn finish(self: *Self, payload: ?Payload) Io.Writer.Error!void {
            const data: Payload = payload orelse @constCast(&[_]u8{});
            try self.writePayload(true, data);
        }

        fn writePayload(self: *Self, fin: bool, payload: Payload) Io.Writer.Error!void {
            const mask_key = if (masked) generateMaskKey() else null;
            const header: FrameHeader.Buffer = .init(.{
                .fin = fin,
                .rsv = self.rsv,
                .opcode = self.opcode,
                .payload_len = payload.len,
                .mask_key = mask_key,
            });
            try header.write(self.writer);
            if (payload.len > 0) {
                if (masked) {
                    var mask: Mask = .init(mask_key);
                    mask.apply(payload);
                }
                try self.writer.writeAll(payload);
            }
        }
    };
}

test "single chunk finish" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: ServerMessageWriter = .init(&writer, .{ .opcode = .text });
    try msg.finish("hello");

    try testing.expectEqual(@as(u8, 0x81), buf[0]); // fin + text
    try testing.expectEqual(@as(u8, 5), buf[1]);
    try testing.expectEqualStrings("hello", buf[2..7]);
}

test "two chunks and finish" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: ServerMessageWriter = .init(&writer, .{ .opcode = .binary });
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

    var msg: ServerMessageWriter = .init(&writer, .{ .opcode = .text });
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

    var msg: ServerMessageWriter = .init(&writer, .{ .opcode = .text, .compressed = true });
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

    var msg: ServerMessageWriter = .init(&writer, .{ .opcode = .binary, .compressed = true });
    try msg.finish("data");

    // fin=true, RSV1=1, opcode=binary -> 0xC2
    try testing.expectEqual(@as(u8, 0xC2), buf[0]);
    try testing.expectEqual(@as(u8, 4), buf[1]);
}

test "masked: single frame sets mask bit and masks payload" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: ClientMessageWriter = .init(&writer, .{ .opcode = .text });
    var payload = "hello".*;
    try msg.finish(&payload);

    // fin + text
    try testing.expectEqual(@as(u8, 0x81), buf[0]);
    // mask bit set | len=5
    try testing.expectEqual(@as(u8, 0x85), buf[1]);
    // mask key at bytes 2..6, masked payload at 6..11
    const mask_key = buf[2..6].*;
    var expected = "hello".*;
    var mask: Mask = .init(mask_key);
    mask.apply(&expected);
    try testing.expectEqualSlices(u8, &expected, buf[6..11]);
}

test "masked + compressed: RSV1 on first frame only, all frames masked" {
    var buf: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: ClientMessageWriter = .init(&writer, .{ .opcode = .text, .compressed = true });
    var p1 = "ab".*;
    var p2 = "cd".*;
    var p3 = "ef".*;
    try msg.writeChunk(&p1);
    try msg.writeChunk(&p2);
    try msg.finish(&p3);

    // Frame 1: RSV1=1, masked, opcode=text -> 0x41, mask bit set
    try testing.expectEqual(@as(u8, 0x41), buf[0]); // no fin, RSV1, text
    try testing.expect(buf[1] & 0x80 != 0); // mask bit

    // Frame 2 starts at offset 8 (header=2 + mask=4 + payload=2)
    try testing.expectEqual(@as(u8, 0x00), buf[8]); // no fin, no RSV1, continuation
    try testing.expect(buf[9] & 0x80 != 0); // mask bit

    // Frame 3 starts at offset 16
    try testing.expectEqual(@as(u8, 0x80), buf[16]); // fin, no RSV1, continuation
    try testing.expect(buf[17] & 0x80 != 0); // mask bit
}

test "masked: each frame gets its own mask key" {
    var buf: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: ClientMessageWriter = .init(&writer, .{ .opcode = .binary });
    var p1 = "ab".*;
    var p2 = "cd".*;
    try msg.writeChunk(&p1);
    try msg.finish(&p2);

    try testing.expect(buf[1] & 0x80 != 0);
    // Frame 2 starts at offset 8 (header=2 + mask=4 + payload=2)
    try testing.expect(buf[9] & 0x80 != 0);
}

test "masked: finish with null payload still emits a masked final frame" {
    var writer: Io.Writer.Allocating = .init(testing.allocator);
    defer writer.deinit();

    var msg: ClientMessageWriter = .init(&writer.writer, .{ .opcode = .text });
    var payload = "ab".*;
    try msg.writeChunk(&payload);
    try msg.finish(null);

    const written = writer.written();
    try testing.expectEqual(@as(usize, 14), written.len);
    try testing.expectEqual(@as(u8, 0x01), written[0]); // first frame: text, not final
    try testing.expectEqual(@as(u8, 0x82), written[1]); // mask bit set, len=2
    try testing.expectEqual(@as(u8, 0x80), written[8]); // final continuation
    try testing.expectEqual(@as(u8, 0x80), written[9]); // mask bit set, len=0
}
