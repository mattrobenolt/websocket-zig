/// Completion-Based WebSocket Echo Server (libxev)
///
/// A WebSocket echo server using libxev's event loop for non-blocking IO.
/// This demonstrates how to use the websocket library with a completion-based
/// IO engine — the same pattern you'd use with io_uring, kqueue, or IOCP.
///
/// Key differences from the blocking example:
///
///   - No threads, no blocking reads. A single event loop drives everything.
///   - Each connection is a finite state machine driven by a single completion
///     token — reads and writes are serialized, never in flight simultaneously.
///   - The parser state lives in a heap-allocated Connection struct that
///     persists across completion callbacks.
///   - Writes use a buffer-oriented approach (queue into an ArrayList, then
///     submit to the event loop) rather than writing directly to an Io.Writer.
///   - Connection structs are recycled through a MemoryPool to avoid
///     per-connection heap allocation overhead.
///
/// The connection lifecycle is:
///
///   handshake → upgrade → read ⇄ write → close → draining → shutdown
///
const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = std.mem;
const posix = std.posix;
const print = std.debug.print;

const ws = @import("websocket").server;
const xev = @import("xev");

/// Pool for recycling Connection structs. Avoids hitting the general-purpose
/// allocator on every accept/close cycle. Initialized in main().
const ConnectionPool = std.heap.MemoryPool(Connection);
var connection_pool: ConnectionPool = undefined;

/// Per-connection state. Everything that needs to survive between
/// "submit read" and "read completed" lives here. In a completion-based
/// model, you can't use stack variables across IO boundaries like you
/// would in blocking code.
const Connection = struct {
    /// General-purpose allocator for dynamic buffers (write_buf, msg).
    /// The Connection struct itself comes from the pool, but its
    /// variable-size buffers still need a regular allocator.
    allocator: Allocator,

    /// The TCP socket for this connection, wrapped in xev's type.
    socket: xev.TCP,

    /// Completion token for async operations. We use a single token
    /// because reads and writes are serialized — only one IO operation
    /// is ever in flight at a time.
    completion: xev.Completion = .{},

    /// Fixed read buffer. When a read completes, the event loop tells
    /// us how many bytes arrived here. We feed those bytes to the
    /// WebSocket frame handler.
    read_buf: [4096]u8 = undefined,

    /// Dynamic write buffer. We serialize frame headers and payloads
    /// here before submitting a write to the event loop. Unlike the
    /// blocking example which writes directly to an Io.Writer, we
    /// need to buffer everything because xev takes ownership of the
    /// buffer slice until the write completes.
    write_buf: std.ArrayList(u8),

    /// How many bytes of write_buf have been sent so far. If a write
    /// completes partially, we resume from this offset.
    write_offset: usize = 0,

    /// The WebSocket frame handler — wraps the parser, fragmentation
    /// validator, and control frame accumulator into a single state
    /// machine that emits high-level messages (data, ping, close, etc).
    handler: ws.FrameHandler = .init(.{}),

    /// Accumulated message payload across fragments. For an echo server,
    /// we need the complete message before we can echo it back.
    msg: std.ArrayList(u8),

    /// Connection lifecycle state. Each state determines which callback
    /// will fire next and what to do when it does.
    state: State = .{ .handshake = .empty },

    const State = union(enum) {
        /// Accumulating the HTTP upgrade request. The ArrayList buffers
        /// request bytes across multiple reads until we see \r\n\r\n.
        handshake: std.ArrayList(u8),
        /// Writing the HTTP 101 response. The u16 payload is the number
        /// of leftover bytes in read_buf that arrived after the HTTP
        /// headers — these are the start of the first WebSocket frame.
        upgrade: u16,
        /// Waiting for inbound WebSocket frames.
        read,
        /// Flushing queued output, then resume reading.
        write,
        /// Flushing a close frame, then drain remaining reads.
        close,
        /// Draining reads after the close handshake until the peer
        /// disconnects (EOF). This ensures we don't RST the connection.
        draining,
        /// socket.close() is in flight — waiting for the OS to clean up.
        shutdown,
    };

    /// Initialize a Connection struct (already allocated from the pool).
    fn init(self: *Connection, gpa: Allocator, socket: xev.TCP) void {
        self.* = .{
            .allocator = gpa,
            .socket = socket,
            .write_buf = .empty,
            .msg = .empty,
        };
    }

    /// Allocate a Connection from the pool and initialize it.
    fn create(gpa: Allocator, socket: xev.TCP) !*Connection {
        const conn = try connection_pool.create();
        conn.init(gpa, socket);
        return conn;
    }

    /// Clean up all owned resources and return the Connection to the pool.
    fn destroy(self: *Connection) void {
        const allocator = self.allocator;
        switch (self.state) {
            .handshake => |*hs| hs.deinit(allocator),
            else => {},
        }
        self.write_buf.deinit(allocator);
        self.msg.deinit(allocator);
        connection_pool.destroy(self);
    }

    // -- IO submission -------------------------------------------------------
    //
    // These methods submit async operations to the event loop. Each one
    // registers a callback that will fire when the operation completes.
    // Only one operation is in flight at a time (we use a single
    // completion token).

    /// Submit an async read into our fixed buffer.
    fn submitRead(self: *Connection, loop: *xev.Loop) void {
        self.socket.read(
            loop,
            &self.completion,
            .{ .slice = &self.read_buf },
            Connection,
            self,
            onRead,
        );
    }

    /// Submit an async write of the pending output buffer.
    fn submitWrite(self: *Connection, loop: *xev.Loop) void {
        self.socket.write(
            loop,
            &self.completion,
            .{ .slice = self.write_buf.items[self.write_offset..] },
            Connection,
            self,
            onWrite,
        );
    }

    /// Begin the shutdown sequence by closing the socket.
    fn submitClose(self: *Connection, loop: *xev.Loop) void {
        self.state = .shutdown;
        self.socket.close(loop, &self.completion, Connection, self, onClose);
    }

    // -- Callbacks -----------------------------------------------------------
    //
    // These are called by the event loop when an async operation completes.
    // They must return .disarm (we re-submit manually) and must not block.

    /// Called when a read completes. Dispatches to the appropriate handler
    /// based on the current connection state.
    fn onRead(
        self_opt: ?*Connection,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: xev.TCP,
        _: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        const self = self_opt.?;
        const n = result catch {
            self.submitClose(loop);
            return .disarm;
        };

        // n == 0 means EOF — the peer closed the connection.
        if (n == 0) {
            self.submitClose(loop);
            return .disarm;
        }

        switch (self.state) {
            // Still reading the HTTP upgrade request.
            .handshake => self.handleHandshake(loop, n) catch {
                self.submitClose(loop);
            },
            // Normal WebSocket operation — process frames.
            .read => self.processFrames(loop, self.read_buf[0..n]) catch {
                self.submitClose(loop);
            },
            // After sending close, drain reads until EOF.
            .draining => self.submitRead(loop),
            else => unreachable,
        }
        return .disarm;
    }

    /// Called when a write completes. Handles partial writes and
    /// transitions to the next state once all data is flushed.
    fn onWrite(
        self_opt: ?*Connection,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: xev.TCP,
        _: xev.WriteBuffer,
        result: xev.WriteError!usize,
    ) xev.CallbackAction {
        const self = self_opt.?;
        const n = result catch {
            self.submitClose(loop);
            return .disarm;
        };

        // Track how much we've sent. If there's more to write,
        // submit another write for the remainder.
        self.write_offset += n;
        if (self.write_offset < self.write_buf.items.len) {
            self.submitWrite(loop);
            return .disarm;
        }

        // All data flushed — reset the write buffer.
        self.write_buf.clearRetainingCapacity();
        self.write_offset = 0;

        // What we do next depends on why we were writing.
        switch (self.state) {
            .upgrade => |leftover_len| {
                // Just sent the 101 response. If there were leftover
                // bytes after the HTTP headers (the start of a WebSocket
                // frame), process them now before reading more.
                self.state = .read;
                if (leftover_len > 0) {
                    self.processFrames(
                        loop,
                        self.read_buf[0..leftover_len],
                    ) catch {
                        self.submitClose(loop);
                    };
                } else {
                    self.submitRead(loop);
                }
            },
            .write => {
                // Finished flushing echo response — read more frames.
                self.state = .read;
                self.submitRead(loop);
            },
            .close => {
                // Finished sending the close frame. Shut down the
                // write side of the socket, then drain reads until EOF.
                // This is the clean close handshake per RFC 6455 §7.1.1.
                // ziglint-ignore: Z026
                posix.shutdown(self.socket.fd, .send) catch {};
                self.state = .draining;
                self.submitRead(loop);
            },
            else => unreachable,
        }
        return .disarm;
    }

    /// Called when the socket close completes. Destroys the connection.
    fn onClose(
        self_opt: ?*Connection,
        _: *xev.Loop,
        _: *xev.Completion,
        _: xev.TCP,
        _: xev.CloseError!void,
    ) xev.CallbackAction {
        if (self_opt) |self| self.destroy();
        return .disarm;
    }

    // -- Handshake -----------------------------------------------------------

    /// Accumulate HTTP request bytes and complete the WebSocket handshake
    /// once we have the full headers.
    fn handleHandshake(self: *Connection, loop: *xev.Loop, n: usize) !void {
        const hs = &self.state.handshake;
        try hs.appendSlice(self.allocator, self.read_buf[0..n]);

        // Look for the end of HTTP headers.
        const end = mem.indexOf(u8, hs.items, "\r\n\r\n") orelse {
            // Haven't received the full headers yet — read more.
            self.submitRead(loop);
            return;
        };
        const header_end = end + 4;

        // Extract the Sec-WebSocket-Key from the request headers.
        const key = extractWebSocketKey(hs.items[0..header_end]) orelse
            return error.BadHandshake;

        // Build the HTTP 101 Switching Protocols response. The library
        // computes the Sec-WebSocket-Accept hash and formats the
        // complete response.
        const resp: ws.UpgradeResponse = .init(.{ .key = key });
        try self.write_buf.appendSlice(self.allocator, resp.constSlice());

        // Any bytes after the HTTP headers are the start of a WebSocket
        // frame. Copy them to the front of read_buf so processFrames
        // can pick them up after the 101 response is sent.
        const leftover_len: u16 = @intCast(hs.items.len - header_end);
        if (leftover_len > 0) {
            @memcpy(self.read_buf[0..leftover_len], hs.items[header_end..]);
        }

        // Done with the handshake buffer — free it and transition
        // to the upgrade state (writing the 101 response).
        hs.deinit(self.allocator);
        self.state = .{ .upgrade = leftover_len };
        self.submitWrite(loop);
    }

    // -- WebSocket frame processing ------------------------------------------

    /// Feed input bytes through the frame handler and act on each message.
    /// Queues response frames into write_buf, then submits either a write
    /// (if there's data to send) or a read (if we need more input).
    fn processFrames(self: *Connection, loop: *xev.Loop, input: []u8) !void {
        var closing = false;
        var data = input;
        while (true) {
            const result = self.handler.feed(data) catch {
                // Parse or validation error — send a protocol error close.
                try self.queueCloseFrame(.protocol_error);
                closing = true;
                break;
            };
            data = data[result.consumed..];

            switch (result.message) {
                // Payload chunk — accumulate until the message is complete.
                .data => |payload| {
                    try self.msg.appendSlice(self.allocator, payload);
                },

                // Complete message — echo it back.
                .data_end => |end| {
                    // Validate UTF-8 for text messages (the library
                    // intentionally leaves this to the caller).
                    if (end.opcode == .text) {
                        if (!std.unicode.utf8ValidateSlice(self.msg.items)) {
                            try self.queueCloseFrame(.invalid_payload);
                            closing = true;
                            break;
                        }
                    }
                    try self.queueFrame(end.opcode, self.msg.items);
                    self.msg.clearRetainingCapacity();
                },

                // Ping — respond with pong (same payload).
                .ping => |payload| {
                    try self.queueFrame(.pong, payload);
                },

                // Pong — nothing to do (we never send pings).
                .pong => {},

                // Close — validate and echo the close frame back,
                // then begin the closing handshake.
                .close => |payload| {
                    if (ws.parseClosePayload(payload)) |close_opt| {
                        // Validate UTF-8 in the close reason string.
                        if (close_opt) |close| {
                            if (!std.unicode.utf8ValidateSlice(close.reason)) {
                                try self.queueCloseFrame(.invalid_payload);
                                closing = true;
                                break;
                            }
                        }
                        // Echo the close frame back verbatim.
                        try self.queueFrame(.close, payload);
                    } else |_| {
                        // Invalid close payload — respond with protocol error.
                        try self.queueCloseFrame(.protocol_error);
                    }
                    closing = true;
                    break;
                },

                // Need more data — break out and submit a read.
                .need_more => break,
            }
        }

        // Decide what to do next based on whether we have data to send
        // and whether we're closing.
        if (self.write_buf.items.len > 0) {
            self.state = if (closing) .close else .write;
            self.submitWrite(loop);
        } else if (closing) {
            self.submitClose(loop);
        } else {
            self.submitRead(loop);
        }
    }

    /// Serialize a WebSocket frame (header + payload) into the write buffer.
    /// Unlike the blocking example which uses ws.writeFrame() with an
    /// Io.Writer, here we buffer into an ArrayList because xev needs
    /// a contiguous slice to submit to the kernel.
    fn queueFrame(self: *Connection, opcode: ws.Opcode, payload: []const u8) !void {
        const header: ws.FrameHeader.Buffer = .init(.{
            .opcode = opcode,
            .payload_len = payload.len,
        });
        try self.write_buf.appendSlice(self.allocator, header.constSlice());
        if (payload.len > 0)
            try self.write_buf.appendSlice(self.allocator, payload);
    }

    /// Queue a close frame with just a status code (no reason text).
    fn queueCloseFrame(self: *Connection, code: ws.CloseCode) !void {
        const close_bytes = code.toBytes();
        try self.queueFrame(.close, &close_bytes);
    }
};

// -- Server setup --------------------------------------------------------

/// Accept callback — fired by the event loop when a new client connects.
/// Allocates a Connection from the pool and kicks off the first read.
fn onAccept(
    gpa: ?*Allocator,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.AcceptError!xev.TCP,
) xev.CallbackAction {
    const client = result catch return .rearm;
    const conn = Connection.create(gpa.?.*, client) catch return .rearm;
    conn.submitRead(loop);
    // .rearm keeps the accept listener active for the next connection.
    return .rearm;
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    var allocator = debug_allocator.allocator();

    // Initialize the connection pool with the general-purpose allocator.
    // The pool recycles Connection structs so we don't hit the allocator
    // on every accept/close cycle.
    connection_pool = .init(allocator);
    defer connection_pool.deinit();

    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();

    const port = parsePort();
    const address: std.net.Address = try .resolveIp("127.0.0.1", port);
    var server: xev.TCP = try .init(address);
    try server.bind(address);
    try server.listen(128);

    print("listening on 127.0.0.1:{d}\n", .{port});

    // Start accepting connections. The accept callback re-arms itself
    // so we keep accepting after each connection.
    var accept_completion: xev.Completion = .{};
    server.accept(&loop, &accept_completion, Allocator, &allocator, onAccept);

    // Run the event loop until all completions are done (i.e. forever,
    // since the accept listener keeps re-arming).
    try loop.run(.until_done);
}

fn parsePort() u16 {
    var args = std.process.args();
    _ = args.next();
    const port_str = args.next() orelse return 8080;
    return std.fmt.parseInt(u16, port_str, 10) catch 8080;
}

/// Extract the Sec-WebSocket-Key header value from raw HTTP request bytes.
/// This is a minimal header parser for this example — a real application
/// would use a proper HTTP library.
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
