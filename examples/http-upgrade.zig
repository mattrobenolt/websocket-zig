/// HTTP Server with WebSocket Upgrade
///
/// Demonstrates integrating websocket-zig with Zig's standard library HTTP
/// server (`std.http.Server`). This is a more realistic example showing how
/// a single server can handle both normal HTTP requests and WebSocket
/// connections on different paths:
///
///   GET /        → serves a simple HTML page with a WebSocket client
///   GET /ws      → upgrades to a WebSocket connection (echo)
///   everything   → 404 Not Found
///
/// The key insight is that `std.http.Server` handles all the HTTP parsing,
/// header validation, and upgrade negotiation. Once the connection is
/// upgraded, we get a raw reader/writer pair and hand off to our WebSocket
/// frame handler — the same pattern as the blocking example, but with
/// proper HTTP handling instead of hand-rolled header parsing.
///
/// Connections are handled concurrently by spawning a thread per connection.
const std = @import("std");
const Allocator = std.mem.Allocator;
const http = std.http;
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
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    print("listening on http://0.0.0.0:{d}\n", .{port});

    // Accept loop — spawn a thread per connection.
    while (true) {
        const conn = listener.accept() catch |err| {
            print("accept error: {}\n", .{err});
            continue;
        };

        const thread = std.Thread.spawn(.{}, handleConnectionThread, .{ allocator, conn.stream }) catch |err| {
            print("thread spawn error: {}\n", .{err});
            conn.stream.close();
            continue;
        };
        thread.detach();
    }
}

/// Thread entry point — handles a connection and ensures the stream is
/// closed when done, even if an error occurs.
fn handleConnectionThread(gpa: Allocator, stream: std.net.Stream) void {
    defer stream.close();
    handleConnection(gpa, stream) catch |err| {
        print("connection error: {}\n", .{err});
    };
}

/// Handle a single TCP connection. Uses std.http.Server to parse HTTP
/// requests and dispatch based on the path. The server supports HTTP
/// keep-alive, so multiple requests can be served on the same connection
/// — until one of them upgrades to WebSocket.
fn handleConnection(gpa: Allocator, stream: std.net.Stream) !void {
    // Wrap the TCP stream with buffered reader/writer.
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var stream_reader = stream.reader(&read_buf);
    var stream_writer = stream.writer(&write_buf);
    const reader = stream_reader.interface();
    const writer = &stream_writer.interface;

    // Initialize the HTTP server. It handles request parsing, content
    // negotiation, keep-alive, and the upgrade handshake.
    var server: http.Server = .init(reader, writer);

    // Request loop — keep handling requests on this connection until
    // the client disconnects or we upgrade to WebSocket.
    while (true) {
        var request = server.receiveHead() catch |err| switch (err) {
            // Client disconnected cleanly.
            error.HttpConnectionClosing => return,
            else => return err,
        };

        // Route based on the request target (path).
        if (mem.eql(u8, request.head.target, "/ws")) {
            // --- WebSocket Upgrade ---
            try handleWebSocket(gpa, &request, writer);
            // After a WebSocket session, the connection is done.
            return;
        } else if (mem.eql(u8, request.head.target, "/")) {
            // --- Serve the HTML page ---
            try request.respond(index_html, .{
                .extra_headers = &.{
                    .{ .name = "content-type", .value = "text/html" },
                },
            });
        } else {
            // --- 404 Not Found ---
            try request.respond("Not Found\n", .{
                .status = .not_found,
            });
        }

        // Flush after each HTTP response to ensure it's sent.
        try writer.flush();

        // If the client doesn't want keep-alive, we're done.
        if (!request.head.keep_alive) return;
    }
}

/// Upgrade an HTTP request to a WebSocket connection and run the echo loop.
fn handleWebSocket(
    gpa: Allocator,
    request: *http.Server.Request,
    writer: *Io.Writer,
) !void {
    // Check if the client actually requested a WebSocket upgrade.
    // std.http.Server parses the Upgrade and Sec-WebSocket-Key headers
    // for us — we just need to check the result.
    const upgrade = request.upgradeRequested();
    const websocket_key = switch (upgrade) {
        .websocket => |key| key orelse {
            // Upgrade: websocket header present but missing the key.
            try request.respond("Missing Sec-WebSocket-Key\n", .{
                .status = .bad_request,
            });
            return;
        },
        else => {
            // Not a WebSocket upgrade request (or a different protocol).
            try request.respond("Expected WebSocket upgrade\n", .{
                .status = .bad_request,
            });
            return;
        },
    };

    // Complete the WebSocket handshake. std.http.Server computes the
    // Sec-WebSocket-Accept hash and sends the 101 Switching Protocols
    // response. After this, the connection is a WebSocket.
    const ws_conn = try request.respondWebSocket(.{
        .key = websocket_key,
    });

    // Flush the 101 response to the client before starting the
    // WebSocket frame loop.
    try writer.flush();

    // From here on, ws_conn.input and ws_conn.output are raw
    // reader/writer pairs — the HTTP layer is out of the picture.
    // We use our websocket-zig frame handler exactly like the
    // blocking example.
    try echoLoop(gpa, ws_conn.input, ws_conn.output);
}

/// WebSocket echo loop — identical in structure to the blocking example.
/// Reads frames from the client, echoes data messages back, and handles
/// control frames (ping/pong/close).
fn echoLoop(
    gpa: Allocator,
    reader: *Io.Reader,
    writer: *Io.Writer,
) !void {
    var handler: ws.ServerFrameHandler = .init;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);

    while (true) {
        // Block until at least one byte is available.
        reader.fill(1) catch return;
        const buf = reader.buffered();
        if (buf.len == 0) return;

        // Process all frames in this buffer. The defer ensures we always
        // flush and advance the reader, regardless of how we exit.
        const status = try processFrames(gpa, &handler, &msg, buf, writer);
        try writer.flush();
        reader.toss(buf.len);

        if (status == .close) return;
    }
}

const Status = enum { continue_reading, close };

/// Feed a buffer through the frame handler and act on each message.
fn processFrames(
    gpa: Allocator,
    handler: *ws.ServerFrameHandler,
    msg: *std.ArrayList(u8),
    input: []u8,
    writer: *Io.Writer,
) Io.Writer.Error!Status {
    var data = input;
    while (true) {
        const result = handler.feed(data) catch {
            // Parse or validation error — close with protocol error.
            try ws.writeClose(writer, .protocol_error);
            return .close;
        };
        data = data[result.consumed..];

        switch (result.message) {
            // Payload chunk — accumulate until the message is complete.
            .data => |payload| {
                msg.appendSlice(gpa, payload) catch {
                    try ws.writeClose(writer, .too_big);
                    return .close;
                };
            },

            // Complete message — echo it back to the client.
            .data_end => |end| {
                try ws.writeFrame(writer, end.opcode, msg.items);
                msg.clearRetainingCapacity();
            },

            // Ping — respond with pong (same payload).
            .ping => |payload| try ws.writePong(writer, payload),

            // Pong — nothing to do.
            .pong => {},

            // Close — echo the close frame and shut down.
            .close => |payload| {
                try ws.writeFrame(writer, .close, payload);
                return .close;
            },

            // Need more data — break out and read again.
            .need_more => break,
        }
    }
    return .continue_reading;
}

fn parsePort() u16 {
    var args = std.process.args();
    _ = args.next();
    const port_str = args.next() orelse return 8080;
    return std.fmt.parseInt(u16, port_str, 10) catch 8080;
}

/// A minimal HTML page with a WebSocket client for testing.
/// Open http://localhost:8080 in a browser to try it.
const index_html = @embedFile("index.html");
