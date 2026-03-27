/// Blocking WebSocket Client
///
/// A minimal WebSocket client using blocking IO with std.net.
/// Connects to a server, sends a text message, receives the echo,
/// and closes the connection.
///
/// Pair with the blocking-echo server:
///   Terminal 1: zig-out/bin/blocking-echo
///   Terminal 2: zig-out/bin/blocking-client
const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const print = std.debug.print;

const ws = @import("websocket").client;

pub fn main() !void {
    const port = parsePort();
    const stream = try tcpConnect(port);
    defer stream.close();

    var read_buf: [4096]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(&read_buf);
    var stream_writer = stream.writer(&write_buf);
    const reader = stream_reader.interface();
    const writer = &stream_writer.interface;

    // --- Client Handshake ---
    var key_raw: [16]u8 = undefined;
    std.crypto.random.bytes(&key_raw);
    var key_b64: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&key_b64, &key_raw);

    var req_buf: [256]u8 = undefined;
    const req = std.fmt.bufPrint(
        &req_buf,
        "GET / HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:{d}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
        .{ port, &key_b64 },
    ) catch unreachable;
    try writer.writeAll(req);
    try writer.flush();

    while (true) {
        reader.fill(1) catch return error.ConnectionClosed;
        const buf = reader.buffered();
        if (mem.indexOf(u8, buf, "\r\n\r\n")) |end| {
            const header_end = end + 4;
            const headers = buf[0..header_end];

            if (!mem.startsWith(u8, headers, "HTTP/1.1 101 "))
                return error.UpgradeRejected;
            const accept = extractHeader(headers, "Sec-WebSocket-Accept: ") orelse
                return error.MissingAcceptKey;
            var expected_buf: ws.AcceptKey = undefined;
            const expected = ws.computeAcceptKey(&key_b64, &expected_buf);
            if (!mem.eql(u8, accept, expected))
                return error.InvalidAcceptKey;
            reader.toss(header_end);
            break;
        }
    }

    print("connected to ws://127.0.0.1:{d}/\n", .{port});

    // --- Send a text message ---
    var message = "Hello, WebSocket!".*;
    try ws.writeFrame(writer, &message, .{ .opcode = .text });
    try writer.flush();
    print("sent: Hello, WebSocket!\n", .{});

    // --- Receive the echo ---
    var handler: ws.FrameHandler = .init(.{});
    var msg_buf: [4096]u8 = undefined;
    var msg_len: usize = 0;

    outer: while (true) {
        reader.fill(1) catch break;
        const buf = reader.buffered();
        if (buf.len == 0) break;

        var data = buf;
        while (true) {
            const result = handler.feed(data) catch break :outer;
            data = data[result.consumed..];

            switch (result.message) {
                .data => |payload| {
                    const space = msg_buf.len - msg_len;
                    const n = @min(payload.len, space);
                    @memcpy(msg_buf[msg_len..][0..n], payload[0..n]);
                    msg_len += n;
                },
                .data_end => {
                    print("received: {s}\n", .{msg_buf[0..msg_len]});
                    try ws.writeClose(writer, .normal);
                    try writer.flush();
                    break :outer;
                },
                .ping => |payload| {
                    var pong_buf: [ws.max_control_payload_len]u8 = undefined;
                    const pong = pong_buf[0..payload.len];
                    @memcpy(pong, payload);
                    try ws.writePong(writer, pong);
                    try writer.flush();
                },
                .pong, .close => break :outer,
                .need_more => break,
            }
        }
        reader.toss(buf.len - data.len);
    }
}

fn extractHeader(request: []const u8, needle: []const u8) ?[]const u8 {
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

fn tcpConnect(port: u16) !std.net.Stream {
    const address: std.net.Address = try .resolveIp("127.0.0.1", port);
    return std.net.tcpConnectToAddress(address);
}

fn parsePort() u16 {
    var args = std.process.args();
    _ = args.next();
    const port_str = args.next() orelse return 8080;
    return std.fmt.parseInt(u16, port_str, 10) catch 8080;
}
