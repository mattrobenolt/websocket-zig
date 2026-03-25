/// Minimal WebSocket echo server for the Autobahn test suite.
///
/// TEST SCAFFOLDING ONLY — not part of the library.
///
/// Does a raw HTTP upgrade handshake, then uses websocket.Parser /
/// websocket.writeFrameHeader for WebSocket frame handling.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = std.net;
const Stream = net.Stream;
const Address = net.Address;
const mem = std.mem;
const print = std.debug.print;

const ws = @import("websocket");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const port = parsePort();
    const address: Address = try .resolveIp("0.0.0.0", port);

    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    print("echo server listening on 0.0.0.0:{d}\n", .{port});

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

fn handleConnection(allocator: Allocator, stream: Stream) !void {
    defer stream.close();

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var stream_reader = stream.reader(&read_buf);
    var stream_writer = stream.writer(&write_buf);
    const reader = stream_reader.interface();
    const writer = &stream_writer.interface;

    while (true) {
        reader.fill(1) catch return;
        const hdr_data = reader.buffered();
        if (hdr_data.len == 0) return;
        if (mem.indexOf(u8, hdr_data, "\r\n\r\n")) |end| {
            const header_end = end + 4;
            const key = extractWebSocketKey(hdr_data[0..header_end]) orelse return;
            reader.toss(header_end);

            const resp: ws.UpgradeResponse = .init(key);
            try resp.write(writer);
            try writer.flush();

            var state: EchoHandler = .init;
            defer state.deinit(allocator);
            try state.run(allocator, reader, writer);
            return;
        }
    }
}

const EchoHandler = struct {
    handler: ws.ServerFrameHandler,
    msg: std.ArrayList(u8),

    const init: EchoHandler = .{
        .handler = .init,
        .msg = .empty,
    };

    fn deinit(self: *EchoHandler, gpa: Allocator) void {
        self.msg.deinit(gpa);
        self.* = undefined;
    }

    const Error = Io.Writer.Error || Io.Reader.Error;

    fn run(self: *EchoHandler, gpa: Allocator, reader: *Io.Reader, writer: *Io.Writer) Error!void {
        while (true) {
            reader.fill(1) catch return;
            const buf = reader.buffered();
            if (buf.len == 0) return;
            const consumed = try self.processBuffer(gpa, buf, writer) orelse return;
            reader.toss(consumed);
        }
    }

    /// Returns number of bytes consumed, or null if the connection should close.
    fn processBuffer(
        self: *EchoHandler,
        gpa: Allocator,
        input: []u8,
        writer: *Io.Writer,
    ) Error!?usize {
        var data = input;
        while (true) {
            const result = self.handler.feed(data) catch {
                try ws.writeClose(writer, .protocol_error);
                return null;
            };
            data = data[result.consumed..];

            switch (result.message) {
                .data => |payload| {
                    self.msg.appendSlice(gpa, payload) catch {
                        try ws.writeClose(writer, .too_big);
                        return null;
                    };
                },
                .data_end => |end| {
                    if (end.opcode == .text) {
                        if (!std.unicode.utf8ValidateSlice(self.msg.items)) {
                            try ws.writeClose(writer, .invalid_payload);
                            return null;
                        }
                    }
                    try ws.writeFrame(writer, end.opcode, self.msg.items);
                    self.msg.clearRetainingCapacity();
                },
                .ping => |payload| try ws.writeFrame(writer, .pong, payload),
                .pong => {},
                .close => |payload| {
                    if (ws.parseClosePayload(payload)) |close_payload_opt| {
                        if (close_payload_opt) |close_payload| {
                            if (!std.unicode.utf8ValidateSlice(close_payload.reason)) {
                                try ws.writeClose(writer, .invalid_payload);
                                return null;
                            }
                        }
                        try ws.writeFrame(writer, .close, payload);
                    } else |_| {
                        try ws.writeClose(writer, .protocol_error);
                    }
                    return null;
                },
                .need_more => break,
            }
        }
        return input.len - data.len;
    }
};

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

fn parsePort() u16 {
    var args = std.process.args();
    _ = args.next();
    const port_str = args.next() orelse return 9002;
    return std.fmt.parseInt(u16, port_str, 10) catch 9002;
}
