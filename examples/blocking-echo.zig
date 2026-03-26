/// Blocking WebSocket Echo Server
///
/// A minimal WebSocket echo server using blocking IO with std.net.
/// This demonstrates the simplest way to use the websocket library:
///
///   1. Accept a TCP connection.
///   2. Read the HTTP upgrade request and send the 101 response.
///   3. Loop: read bytes → feed to parser → echo back frames.
///
/// This is intentionally simple — single-threaded, one connection at a time,
/// no production error handling. See the libxev example for an event-driven
/// approach suitable for handling many connections.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const mem = std.mem;
const print = std.debug.print;

const ws = @import("websocket");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const port = parsePort();
    const address: std.net.Address = try .resolveIp("0.0.0.0", port);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    print("listening on 0.0.0.0:{d}\n", .{port});

    // Accept loop — handle one connection at a time.
    while (true) {
        const conn = server.accept() catch |err| {
            print("accept error: {}\n", .{err});
            continue;
        };

        handleConnection(allocator, conn.stream) catch |err| {
            print("connection error: {}\n", .{err});
        };
    }
}

fn handleConnection(gpa: Allocator, stream: std.net.Stream) !void {
    defer stream.close();

    // Wrap the raw TCP stream with buffered reader/writer.
    // The buffers are stack-allocated — no heap needed for IO.
    var read_buf: [4096]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(&read_buf);
    var stream_writer = stream.writer(&write_buf);
    const reader = stream_reader.interface();
    const writer = &stream_writer.interface;

    // --- Step 1: HTTP Upgrade Handshake ---
    //
    // Read the HTTP request, extract the Sec-WebSocket-Key, and send
    // the 101 Switching Protocols response. After this, the connection
    // is a WebSocket connection and we switch to frame-based IO.
    // Read until we see the end of HTTP headers. We use fill/buffered/toss
    // rather than readSliceShort because we don't know the request size
    // upfront — readSliceShort would block trying to fill the entire buffer.
    while (true) {
        reader.fill(1) catch return;
        const hdr_data = reader.buffered();
        if (hdr_data.len == 0) return;
        if (mem.indexOf(u8, hdr_data, "\r\n\r\n")) |end| {
            const header_end = end + 4;
            const key = extractWebSocketKey(hdr_data[0..header_end]) orelse return;

            // Consume the HTTP headers from the reader. Any bytes after
            // the headers (WebSocket frames) stay in the reader's buffer
            // and will be picked up by the echo loop.
            reader.toss(header_end);

            // The library computes the Sec-WebSocket-Accept hash and
            // formats the complete HTTP 101 response into a buffer.
            const resp: ws.UpgradeResponse = .init(.{ .key = key });
            try resp.write(writer);
            try writer.flush();

            // --- Step 2: WebSocket Echo Loop ---
            var handler: EchoHandler = .init;
            defer handler.deinit(gpa);

            // Main read loop.
            try handler.run(gpa, reader, writer);
            return;
        }
    }
}

/// Manages WebSocket protocol state for one connection.
/// Uses `ServerFrameHandler` for parsing, fragmentation validation,
/// and control frame accumulation. Only needs to handle the
/// high-level messages: data, ping, pong, and close.
const EchoHandler = struct {
    /// The frame handler — wraps the parser, validator, and control
    /// buffer into a single state machine that emits high-level messages.
    handler: ws.ServerFrameHandler,

    /// Accumulated message payload across fragments. Grows
    /// dynamically — no fixed size limit.
    msg: std.ArrayList(u8),

    const init: EchoHandler = .{
        .handler = .init(.{}),
        .msg = .empty,
    };

    fn deinit(self: *EchoHandler, gpa: Allocator) void {
        self.msg.deinit(gpa);
        self.* = undefined;
    }

    /// Main read loop. Blocks on the reader, feeds bytes to the
    /// handler, and processes messages until the connection closes.
    fn run(
        self: *EchoHandler,
        gpa: Allocator,
        reader: *Io.Reader,
        writer: *Io.Writer,
    ) !void {
        while (true) {
            // fill(1) blocks until at least 1 byte is available.
            reader.fill(1) catch return;
            const buf = reader.buffered();
            if (buf.len == 0) return;
            const status = try self.processFrames(gpa, buf, writer);
            try writer.flush();
            if (status == .close) return;
            // Advance the reader past the bytes we consumed.
            reader.toss(buf.len);
        }
    }

    const Status = enum { continue_reading, close };

    /// Feed a buffer of bytes through the handler and act on each message.
    fn processFrames(
        self: *EchoHandler,
        gpa: Allocator,
        input: []u8,
        writer: *Io.Writer,
    ) !Status {
        var data = input;
        while (true) {
            const result = self.handler.feed(data) catch {
                try ws.writeClose(writer, .protocol_error);
                return .close;
            };
            data = data[result.consumed..];

            switch (result.message) {
                .data => |payload| {
                    try self.msg.appendSlice(gpa, payload);
                },
                .data_end => |end| {
                    try ws.writeFrame(writer, self.msg.items, .{ .opcode = end.opcode });
                    self.msg.clearRetainingCapacity();
                },
                .ping => |payload| try ws.writePong(writer, payload),
                .pong => {},
                .close => |payload| {
                    try ws.writeFrame(writer, payload, .{ .opcode = .close });
                    return .close;
                },
                .need_more => break,
            }
        }
        return .continue_reading;
    }
};

fn parsePort() u16 {
    var args = std.process.args();
    _ = args.next();
    const port_str = args.next() orelse return 8080;
    return std.fmt.parseInt(u16, port_str, 10) catch 8080;
}

fn extractWebSocketKey(request: []const u8) ?[]const u8 {
    const needle = "Sec-WebSocket-Key: ";
    var pos: usize = 0;
    while (pos < request.len) {
        const line_end = mem.indexOf(u8, request[pos..], "\r\n") orelse
            (request.len - pos);
        const line = request[pos .. pos + line_end];
        if (std.ascii.startsWithIgnoreCase(line, needle)) {
            return mem.trim(u8, line[needle.len..], " ");
        }
        pos += line_end + 2;
    }
    return null;
}
