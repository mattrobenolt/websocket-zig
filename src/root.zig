//! IO-agnostic WebSocket frame parser and serializer implementing RFC 6455.
//!
//! Zero allocations, no IO — callers provide all buffers. This is a frame-level
//! library: it handles header parsing, payload length decoding, and masking.
//! Fragmentation sequencing and UTF-8 validation are the caller's responsibility.
//!
//! ## Quick start
//!
//! Use `ServerParser` (expects masked frames from clients) or `ClientParser`
//! (expects unmasked frames from servers). Feed raw bytes in via `feed()` and
//! loop until `need_more` is returned:
//!
//! ```
//! var parser: websocket.ServerParser = .init(.{});
//! while (true) {
//!     const result = try parser.feed(buf);
//!     buf = buf[result.consumed..];
//!     switch (result.event) {
//!         .frame_header => |hdr| { ... },
//!         .payload => |data| { ... },
//!         .frame_end => {},
//!         .need_more => break,
//!     }
//! }
//! ```

const std = @import("std");
const testing = std.testing;
const Io = std.Io;

const close = @import("close.zig");
pub const CloseCode = close.CloseCode;
pub const ClosePayload = close.ClosePayload;
pub const parseClosePayload = close.parseClosePayload;
pub const Extension = @import("extension.zig").Extension;
const frame = @import("frame.zig");
pub const MaskKey = frame.MaskKey;
pub const Opcode = frame.Opcode;
pub const RsvBits = frame.RsvBits;
pub const FrameHeader = frame.FrameHeader;
pub const Event = frame.Event;
pub const ParseError = frame.ParseError;
pub const Mask = frame.Mask;
const handshake = @import("handshake.zig");
pub const computeAcceptKey = handshake.computeAcceptKey;
pub const UpgradeRequest = handshake.UpgradeRequest;
pub const validateUpgradeRequest = handshake.validateUpgradeRequest;
pub const UpgradeResponse = handshake.UpgradeResponse;
pub const MessageWriter = @import("MessageWriter.zig");
const parse = @import("parse.zig");
pub const Options = parse.Options;
pub const ServerParser = parse.ServerParser;
pub const ClientParser = parse.ClientParser;
pub const MessageValidator = parse.MessageValidator;
pub const ServerFrameHandler = parse.ServerFrameHandler;
pub const ClientFrameHandler = parse.ClientFrameHandler;

pub const WriteFrameOptions = struct {
    opcode: Opcode,
    compressed: bool = false,
};

/// Write a complete frame (header + payload) to `writer`. The caller is
/// responsible for flushing when ready — this allows batching multiple
/// frames before a single flush.
pub fn writeFrame(
    writer: *Io.Writer,
    payload: []const u8,
    options: WriteFrameOptions,
) Io.Writer.Error!void {
    const rsv: RsvBits = if (options.compressed) .{ .rsv1 = true } else .{};
    const header: FrameHeader.Buffer = .init(.{
        .opcode = options.opcode,
        .rsv = rsv,
        .payload_len = payload.len,
    });
    try header.write(writer);
    if (payload.len > 0) try writer.writeAll(payload);
}

/// Write a close frame with a status code (no reason text).
pub fn writeClose(
    writer: *Io.Writer,
    code: CloseCode,
) Io.Writer.Error!void {
    const body = code.toBytes();
    try writeFrame(writer, &body, .{ .opcode = .close });
}

/// Write a ping frame with an optional payload.
pub fn writePing(
    writer: *Io.Writer,
    payload: []const u8,
) Io.Writer.Error!void {
    try writeFrame(writer, payload, .{ .opcode = .ping });
}

/// Write a pong frame with the given payload (typically echoed from a ping).
pub fn writePong(
    writer: *Io.Writer,
    payload: []const u8,
) Io.Writer.Error!void {
    try writeFrame(writer, payload, .{ .opcode = .pong });
}

test {
    testing.refAllDecls(@This());
}
