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
//! var parser: websocket.ServerParser = .init;
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
const assert = std.debug.assert;
const testing = std.testing;
const mem = std.mem;
const Io = std.Io;
const Sha1 = std.crypto.hash.Sha1;
const B64Encoder = std.base64.standard.Encoder;

/// The 4-byte masking key used to mask/unmask WebSocket frame payloads (RFC 6455 Section 5.3).
pub const MaskKey = [4]u8;
/// 28-byte buffer for the base64-encoded `Sec-WebSocket-Accept` header value.
pub const AcceptKey = [28]u8;

fn BoundedBuffer(comptime max_capacity: comptime_int) type {
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
const max_header_len = 14;
const HeaderBuffer = BoundedBuffer(max_header_len);

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

/// WebSocket close status code (RFC 6455 Section 7.4).
pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    no_status = 1005,
    abnormal = 1006,
    invalid_payload = 1007,
    policy_violation = 1008,
    too_big = 1009,
    mandatory_extension = 1010,
    internal_error = 1011,
    tls_handshake = 1015,
    _,

    /// RFC 6455 Section 7.4: validate whether a close code may appear on the wire.
    /// Codes 1005, 1006, and 1015 are reserved for local use and MUST NOT be sent.
    pub fn isValid(self: CloseCode) bool {
        const code = @intFromEnum(self);
        return switch (code) {
            1000...1003, 1007...1011, 3000...4999 => true,
            else => false,
        };
    }

    /// Encode the status code as two big-endian bytes for a close frame payload.
    pub fn toBytes(self: CloseCode) [2]u8 {
        var buf: [2]u8 = undefined;
        writeInt(u16, &buf, @intFromEnum(self));
        return buf;
    }
};

/// Parsed close frame payload (RFC 6455 Section 5.5.1).
pub const ClosePayload = struct {
    code: CloseCode,
    reason: []const u8,
};

/// Errors returned by `parseClosePayload`.
pub const ClosePayloadError = error{
    /// Close frame body is 1 byte (must be 0 or >= 2).
    InvalidClosePayloadLength,
    /// Close code is not valid per RFC 6455 Section 7.4.
    InvalidCloseCode,
};

/// Parse the body of a close frame into its status code and optional reason string.
/// Returns null if the payload is empty (no status code).
pub fn parseClosePayload(payload: []const u8) ClosePayloadError!?ClosePayload {
    if (payload.len == 0) return null;
    if (payload.len == 1) return error.InvalidClosePayloadLength;

    const code: CloseCode = @enumFromInt(readInt(u16, payload[0..2]));
    if (!code.isValid()) return error.InvalidCloseCode;

    return .{
        .code = code,
        .reason = payload[2..],
    };
}

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

/// Header values extracted from an HTTP upgrade request, for use with
/// `validateUpgradeRequest`. The caller is responsible for HTTP parsing;
/// this struct holds only the WebSocket-specific fields.
pub const UpgradeRequest = struct {
    /// `Sec-WebSocket-Key` header value.
    key: []const u8,
    /// `Sec-WebSocket-Version` header value.
    version: []const u8,
};

/// Errors returned by `validateUpgradeRequest`.
pub const UpgradeError = error{
    UnsupportedVersion,
    InvalidKeyLength,
};

/// Validate an upgrade request. Returns error if the request is not a valid
/// WebSocket handshake per RFC 6455 Section 4.2.1.
pub fn validateUpgradeRequest(request: UpgradeRequest) UpgradeError!void {
    if (!mem.eql(u8, request.version, "13")) return error.UnsupportedVersion;
    if (request.key.len != 24) return error.InvalidKeyLength;
}

/// A pre-built HTTP 101 response for completing the WebSocket handshake.
/// Contains the required `Upgrade`, `Connection`, and `Sec-WebSocket-Accept` headers.
pub const UpgradeResponse = struct {
    const prefix =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: ";
    const suffix = "\r\n\r\n";

    /// Maximum byte length of the complete HTTP response.
    pub const max_len = prefix.len + 28 + suffix.len;

    const Buffer = BoundedBuffer(max_len);

    buf: Buffer,

    /// Build the response from the client's `Sec-WebSocket-Key` header value.
    pub fn init(key: []const u8) UpgradeResponse {
        var b: Buffer = .empty;
        b.appendSliceAssumeCapacity(prefix);
        var accept_buf: AcceptKey = undefined;
        const accept = computeAcceptKey(key, &accept_buf);
        b.appendSliceAssumeCapacity(accept);
        b.appendSliceAssumeCapacity(suffix);
        return .{ .buf = b };
    }

    /// Returns the complete HTTP response bytes.
    pub fn constSlice(self: *const UpgradeResponse) []const u8 {
        return self.buf.constSlice();
    }

    /// Writes the complete HTTP response to `writer`.
    pub fn write(self: *const UpgradeResponse, writer: *Io.Writer) Io.Writer.Error!void {
        return self.buf.write(writer);
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

/// RFC 6455 Section 4.2.2 GUID used in Sec-WebSocket-Accept computation.
const handshake_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub inline fn readInt(comptime T: type, buffer: *const [@divExact(@typeInfo(T).int.bits, 8)]u8) T {
    return mem.readInt(T, buffer, .big);
}

pub inline fn writeInt(comptime T: type, buffer: *[@divExact(@typeInfo(T).int.bits, 8)]u8, value: T) void {
    return mem.writeInt(T, buffer, value, .big);
}

/// Compute the `Sec-WebSocket-Accept` header value from a client's
/// `Sec-WebSocket-Key` (RFC 6455 Section 4.2.2). The result is a
/// 28-byte base64 string written into `out` and returned as a slice.
pub fn computeAcceptKey(key: []const u8, out: *AcceptKey) []const u8 {
    var sha: Sha1 = .init(.{});
    sha.update(key);
    sha.update(handshake_guid);
    const digest = sha.finalResult();
    return B64Encoder.encode(out, &digest);
}

/// Write a complete frame (header + payload) to `writer`. The caller is
/// responsible for flushing when ready — this allows batching multiple
/// frames before a single flush.
pub fn writeFrame(
    writer: *Io.Writer,
    opcode: Opcode,
    payload: []const u8,
) Io.Writer.Error!void {
    const header: FrameHeader.Buffer = .init(.{
        .opcode = opcode,
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
    try writeFrame(writer, .close, &body);
}

/// Write a ping frame with an optional payload.
pub fn writePing(
    writer: *Io.Writer,
    payload: []const u8,
) Io.Writer.Error!void {
    try writeFrame(writer, .ping, payload);
}

/// Write a pong frame with the given payload (typically echoed from a ping).
pub fn writePong(
    writer: *Io.Writer,
    payload: []const u8,
) Io.Writer.Error!void {
    try writeFrame(writer, .pong, payload);
}

/// Writes a fragmented WebSocket message across multiple frames, managing
/// the opcode and continuation state automatically.
///
/// The first call to `writeChunk` sends a frame with the original opcode
/// and `fin = false`. Subsequent chunks send continuation frames. Call
/// `finish` to send the final frame with `fin = true`.
///
/// ```
/// var msg: ws.MessageWriter = .init(writer, .text);
/// try msg.writeChunk(part1);
/// try msg.writeChunk(part2);
/// try msg.finish(part3);
/// ```
///
/// For unfragmented messages, prefer `writeFrame` instead.
pub const MessageWriter = struct {
    writer: *Io.Writer,
    opcode: Opcode,

    pub fn init(writer: *Io.Writer, opcode: Opcode) MessageWriter {
        assert(opcode == .text or opcode == .binary);
        return .{
            .writer = writer,
            .opcode = opcode,
        };
    }

    /// Write a non-final frame. The first call uses the original opcode;
    /// subsequent calls use `.continuation`.
    pub fn writeChunk(self: *MessageWriter, payload: []const u8) Io.Writer.Error!void {
        const header: FrameHeader.Buffer = .init(.{
            .fin = false,
            .opcode = self.opcode,
            .payload_len = payload.len,
        });
        try header.write(self.writer);
        if (payload.len > 0) try self.writer.writeAll(payload);
        self.opcode = .continuation;
    }

    /// Send the final frame with `fin = true`, completing the message.
    /// Pass an optional last chunk of payload, or `null` for an empty
    /// final frame.
    pub fn finish(self: *MessageWriter, payload: ?[]const u8) Io.Writer.Error!void {
        const data = payload orelse &.{};
        const header: FrameHeader.Buffer = .init(.{
            .fin = true,
            .opcode = self.opcode,
            .payload_len = data.len,
        });
        try header.write(self.writer);
        if (data.len > 0) try self.writer.writeAll(data);
    }
};

test "MessageWriter: single chunk finish" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: MessageWriter = .init(&writer, .text);
    try msg.finish("hello");

    // Single frame: fin=true, opcode=text, len=5, "hello"
    try testing.expectEqual(@as(u8, 0x81), buf[0]); // fin + text
    try testing.expectEqual(@as(u8, 5), buf[1]); // length
    try testing.expectEqualStrings("hello", buf[2..7]);
}

test "MessageWriter: two chunks and finish" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: MessageWriter = .init(&writer, .binary);
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

test "MessageWriter: finish with null payload" {
    var buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);

    var msg: MessageWriter = .init(&writer, .text);
    try msg.writeChunk("data");
    try msg.finish(null);

    // Frame 1: fin=false, opcode=text, len=4
    try testing.expectEqual(@as(u8, 0x01), buf[0]); // no fin + text
    try testing.expectEqual(@as(u8, 4), buf[1]);

    // Frame 2: fin=true, opcode=continuation, len=0
    try testing.expectEqual(@as(u8, 0x80), buf[6]); // fin + continuation
    try testing.expectEqual(@as(u8, 0), buf[7]);
}

// --- BoundedBuffer tests ---

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

test "computeAcceptKey matches RFC 6455 Section 4.2.2 example" {
    var buf: AcceptKey = undefined;
    const accept = computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==", &buf);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "handshake_guid matches RFC 6455" {
    try testing.expectEqualStrings("258EAFA5-E914-47DA-95CA-C5AB0DC85B11", handshake_guid);
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

test "Parser.init and reset" {
    var p: ServerParser = .init;
    try testing.expect(p.state == .header);
    try testing.expectEqual(0, p.state.header.len);

    p.state = .{ .payload = .{ .remaining = 10, .mask = .none } };
    p.reset();
    try testing.expect(p.state == .header);
    try testing.expectEqual(0, p.state.header.len);
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

test "CloseCode.isValid: standard valid codes" {
    const valid = [_]u16{ 1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011 };
    for (valid) |code| {
        const cc: CloseCode = @enumFromInt(code);
        try testing.expect(cc.isValid());
    }
}

test "CloseCode.isValid: application-defined range 3000-4999" {
    const app_codes = [_]u16{ 3000, 3999, 4000, 4999 };
    for (app_codes) |code| {
        const cc: CloseCode = @enumFromInt(code);
        try testing.expect(cc.isValid());
    }
}

test "CloseCode.isValid: reserved codes must not appear on wire" {
    // 1004 is reserved, 1005/1006/1015 are for local use only
    const invalid = [_]u16{ 1004, 1005, 1006, 1015 };
    for (invalid) |code| {
        const cc: CloseCode = @enumFromInt(code);
        try testing.expect(!cc.isValid());
    }
}

test "CloseCode.isValid: codes outside defined ranges" {
    const invalid = [_]u16{ 0, 999, 1016, 1099, 1100, 2000, 2999, 5000, 65535 };
    for (invalid) |code| {
        const cc: CloseCode = @enumFromInt(code);
        try testing.expect(!cc.isValid());
    }
}

test "parseClosePayload: empty payload (no status code)" {
    const result = try parseClosePayload("");
    try testing.expect(result == null);
}

test "parseClosePayload: 1-byte payload is invalid" {
    try testing.expectError(error.InvalidClosePayloadLength, parseClosePayload("\x03"));
}

test "parseClosePayload: 2-byte payload (code only, no reason)" {
    // Code 1000 = 0x03E8
    const result = (try parseClosePayload("\x03\xE8")).?;
    try testing.expectEqual(CloseCode.normal, result.code);
    try testing.expectEqualStrings("", result.reason);
}

test "parseClosePayload: code + reason" {
    // Code 1001 = 0x03E9
    const result = (try parseClosePayload("\x03\xE9going away")).?;
    try testing.expectEqual(CloseCode.going_away, result.code);
    try testing.expectEqualStrings("going away", result.reason);
}

test "parseClosePayload: invalid close code rejected" {
    // Code 999 = 0x03E7
    try testing.expectError(error.InvalidCloseCode, parseClosePayload("\x03\xE7"));
}

test "parseClosePayload: reserved code 1005 rejected" {
    // 1005 = 0x03ED
    try testing.expectError(error.InvalidCloseCode, parseClosePayload("\x03\xED"));
}

test "parseClosePayload: reserved code 1006 rejected" {
    // 1006 = 0x03EE
    try testing.expectError(error.InvalidCloseCode, parseClosePayload("\x03\xEE"));
}

test "parseClosePayload: application code 3000 accepted" {
    // 3000 = 0x0BB8
    const result = (try parseClosePayload("\x0B\xB8")).?;
    try testing.expectEqual(@as(CloseCode, @enumFromInt(3000)), result.code);
}

test "parseClosePayload: max payload 123 bytes reason" {
    // Close frame max is 125 bytes: 2 for code + 123 for reason
    var payload: [125]u8 = @splat('A');
    writeInt(u16, payload[0..2], 1000);
    const result = (try parseClosePayload(&payload)).?;
    try testing.expectEqual(CloseCode.normal, result.code);
    try testing.expectEqual(@as(usize, 123), result.reason.len);
}

// ---- MessageValidator tests (RFC 6455 Section 5.4) ----

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

// ---- Upgrade helpers tests (RFC 6455 Section 4.2) ----

test "validateUpgradeRequest: valid request" {
    try validateUpgradeRequest(.{
        .key = "dGhlIHNhbXBsZSBub25jZQ==",
        .version = "13",
    });
}

test "validateUpgradeRequest: wrong version" {
    try testing.expectError(
        error.UnsupportedVersion,
        validateUpgradeRequest(.{
            .key = "dGhlIHNhbXBsZSBub25jZQ==",
            .version = "12",
        }),
    );
}

test "validateUpgradeRequest: empty version" {
    try testing.expectError(
        error.UnsupportedVersion,
        validateUpgradeRequest(.{
            .key = "dGhlIHNhbXBsZSBub25jZQ==",
            .version = "",
        }),
    );
}

test "validateUpgradeRequest: invalid key length" {
    // RFC 6455: key must be a base64-encoded 16-byte value = 24 chars.
    try testing.expectError(
        error.InvalidKeyLength,
        validateUpgradeRequest(.{
            .key = "tooshort",
            .version = "13",
        }),
    );
}

test "UpgradeResponse: produces valid HTTP 101" {
    const resp: UpgradeResponse = .init("dGhlIHNhbXBsZSBub25jZQ==");
    const response = resp.constSlice();

    try testing.expect(mem.startsWith(u8, response, "HTTP/1.1 101 Switching Protocols\r\n"));
    try testing.expect(mem.indexOf(u8, response, "Upgrade: websocket\r\n") != null);
    try testing.expect(mem.indexOf(u8, response, "Connection: Upgrade\r\n") != null);
    try testing.expect(mem.indexOf(u8, response, "Sec-WebSocket-Accept: ") != null);
    try testing.expect(mem.endsWith(u8, response, "\r\n\r\n"));
}

test "UpgradeResponse: correct accept value" {
    const resp: UpgradeResponse = .init("dGhlIHNhbXBsZSBub25jZQ==");
    const response = resp.constSlice();

    const accept_start = mem.indexOf(u8, response, "Sec-WebSocket-Accept: ").? + 22;
    const accept_end = mem.indexOf(u8, response[accept_start..], "\r\n").?;
    const accept = response[accept_start..][0..accept_end];
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

// --- FrameHandler tests ---

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
