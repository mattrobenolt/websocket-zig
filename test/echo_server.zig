/// Minimal WebSocket echo server for the Autobahn test suite.
///
/// TEST SCAFFOLDING ONLY — not part of the library.
///
/// Does a raw HTTP upgrade handshake, then uses the websocket library's
/// parser and frame writer for WebSocket handling.
/// Supports permessage-deflate (RFC 7692) when offered by the client.
///
/// The zlib integration here is a minimal, brute-force implementation
/// sufficient for passing the Autobahn conformance tests. It is NOT a
/// reference for how to do compression well. A real application should
/// use a proper zlib wrapper with better buffer management.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = std.net;
const Stream = net.Stream;
const Address = net.Address;
const mem = std.mem;
const print = std.debug.print;

const ws = @import("websocket");
const DeflateConfig = ws.Extension.DeflateConfig;

const c = @cImport(@cInclude("zlib.h"));

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

const HandshakeResult = struct {
    deflate: ?DeflateConfig,
};

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
            const headers = hdr_data[0..header_end];
            const key = extractWebSocketKey(headers) orelse return;
            const hs = negotiateHandshake(headers);
            reader.toss(header_end);

            const ext: ?ws.Extension = if (hs.deflate) |cfg|
                .{ .permessage_deflate = cfg }
            else
                null;
            const resp: ws.UpgradeResponse = .init(.{ .key = key, .extension = ext });
            try resp.write(writer);
            try writer.flush();

            var state: EchoHandler = try .init(allocator, hs.deflate);
            defer state.deinit(allocator);
            try state.run(allocator, reader, writer);
            return;
        }
    }
}

fn negotiateHandshake(headers: []const u8) HandshakeResult {
    const ext_value = extractHeader(
        headers,
        "Sec-WebSocket-Extensions: ",
    ) orelse return .{ .deflate = null };

    if (mem.indexOf(u8, ext_value, "permessage-deflate") == null)
        return .{ .deflate = null };

    var cfg: DeflateConfig = .init;

    if (mem.indexOf(u8, ext_value, "server_no_context_takeover") != null)
        cfg.server_no_context_takeover = true;
    if (mem.indexOf(u8, ext_value, "client_no_context_takeover") != null)
        cfg.client_no_context_takeover = true;

    if (extractParamValue(ext_value, "server_max_window_bits")) |v|
        cfg.server_max_window_bits = v;
    if (extractParamValue(ext_value, "client_max_window_bits")) |v|
        cfg.client_max_window_bits = v;

    return .{ .deflate = cfg };
}

fn extractParamValue(
    ext_value: []const u8,
    param: []const u8,
) ?ws.Extension.WindowBits {
    const idx = mem.indexOf(u8, ext_value, param) orelse return null;
    const after = ext_value[idx + param.len ..];
    if (after.len == 0 or after[0] != '=') return null;
    const rest = after[1..];

    var end: usize = 0;
    while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') end += 1;
    if (end == 0) return null;

    const val = std.fmt.parseInt(u4, rest[0..end], 10) catch return null;
    return std.meta.intToEnum(ws.Extension.WindowBits, val) catch null;
}

const sync_flush_suffix = [_]u8{ 0x00, 0x00, 0xff, 0xff };

const ZlibState = struct {
    inflate_stream: c.z_stream,
    deflate_stream: c.z_stream,
    client_no_context_takeover: bool,
    server_no_context_takeover: bool,

    fn create(gpa: Allocator, cfg: DeflateConfig) !*ZlibState {
        const self = try gpa.create(ZlibState);
        errdefer gpa.destroy(self);

        // Init zlib streams in-place — zlib stores internal
        // pointers back to the z_stream struct, so it must not
        // be moved after init.
        self.* = .{
            .inflate_stream = mem.zeroes(c.z_stream),
            .deflate_stream = mem.zeroes(c.z_stream),
            .client_no_context_takeover = cfg.client_no_context_takeover,
            .server_no_context_takeover = cfg.server_no_context_takeover,
        };

        const client_wbits: c_int = @intFromEnum(cfg.client_max_window_bits);
        if (c.inflateInit2(&self.inflate_stream, -client_wbits) != c.Z_OK)
            return error.ZlibInitFailed;
        errdefer _ = c.inflateEnd(&self.inflate_stream);

        const server_wbits: c_int = @intFromEnum(cfg.server_max_window_bits);
        if (c.deflateInit2(
            &self.deflate_stream,
            c.Z_DEFAULT_COMPRESSION,
            c.Z_DEFLATED,
            -server_wbits,
            8,
            c.Z_DEFAULT_STRATEGY,
        ) != c.Z_OK)
            return error.ZlibInitFailed;

        return self;
    }

    fn destroy(self: *ZlibState, gpa: Allocator) void {
        self.deinit();
        gpa.destroy(self);
    }

    fn deinit(self: *ZlibState) void {
        _ = c.inflateEnd(&self.inflate_stream);
        _ = c.deflateEnd(&self.deflate_stream);
        self.* = undefined;
    }

    fn inflate(self: *ZlibState, gpa: Allocator, msg: *std.ArrayList(u8)) !std.ArrayList(u8) {
        // Append the sync flush suffix stripped per RFC 7692.
        try msg.appendSlice(gpa, &sync_flush_suffix);

        self.inflate_stream.next_in = msg.items.ptr;
        self.inflate_stream.avail_in = @intCast(msg.items.len);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);

        var buf: [8192]u8 = undefined;
        while (self.inflate_stream.avail_in > 0) {
            self.inflate_stream.next_out = &buf;
            self.inflate_stream.avail_out = buf.len;
            const ret = c.inflate(&self.inflate_stream, c.Z_SYNC_FLUSH);
            const have = buf.len - self.inflate_stream.avail_out;
            if (have > 0) try out.appendSlice(gpa, buf[0..have]);
            if (ret == c.Z_STREAM_END or self.inflate_stream.avail_in == 0) break;
            if (ret != c.Z_OK and ret != c.Z_BUF_ERROR)
                return error.ZlibInflateFailed;
        }

        if (self.client_no_context_takeover) {
            _ = c.inflateReset(&self.inflate_stream);
        }

        return out;
    }

    fn deflate(self: *ZlibState, gpa: Allocator, data: []const u8) ![]u8 {
        self.deflate_stream.next_in = @constCast(data.ptr);
        self.deflate_stream.avail_in = @intCast(data.len);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);

        var buf: [8192]u8 = undefined;
        while (true) {
            self.deflate_stream.next_out = &buf;
            self.deflate_stream.avail_out = buf.len;
            const ret = c.deflate(&self.deflate_stream, c.Z_SYNC_FLUSH);
            if (ret != c.Z_OK) return error.ZlibDeflateFailed;
            const have = buf.len - self.deflate_stream.avail_out;
            if (have > 0) try out.appendSlice(gpa, buf[0..have]);
            if (self.deflate_stream.avail_in == 0 and self.deflate_stream.avail_out > 0)
                break;
        }

        // Strip trailing sync flush marker per RFC 7692 §7.2.1.
        if (out.items.len >= 4 and
            mem.eql(u8, out.items[out.items.len - 4 ..], &sync_flush_suffix))
        {
            out.shrinkRetainingCapacity(out.items.len - 4);
        }

        if (self.server_no_context_takeover) {
            _ = c.deflateReset(&self.deflate_stream);
        }

        return out.toOwnedSlice(gpa);
    }
};

const EchoHandler = struct {
    handler: ws.ServerFrameHandler,
    msg: std.ArrayList(u8),
    zlib: ?*ZlibState,

    fn init(gpa: Allocator, deflate_cfg: ?DeflateConfig) !EchoHandler {
        const ext: ?ws.Extension = if (deflate_cfg) |cfg|
            .{ .permessage_deflate = cfg }
        else
            null;
        return .{
            .handler = .init(.{ .extension = ext }),
            .msg = .empty,
            .zlib = if (deflate_cfg) |cfg| try .create(gpa, cfg) else null,
        };
    }

    fn deinit(self: *EchoHandler, gpa: Allocator) void {
        self.msg.deinit(gpa);
        if (self.zlib) |z| z.destroy(gpa);
        self.* = undefined;
    }

    const Error = Io.Writer.Error || Io.Reader.Error;

    fn run(
        self: *EchoHandler,
        gpa: Allocator,
        reader: *Io.Reader,
        writer: *Io.Writer,
    ) Error!void {
        while (true) {
            reader.fill(1) catch return;
            const buf = reader.buffered();
            if (buf.len == 0) return;
            const status = try self.processFrames(gpa, buf, writer);
            try writer.flush();
            if (status == .close) return;
            reader.toss(buf.len);
        }
    }

    const Status = enum { continue_reading, close };

    fn processFrames(
        self: *EchoHandler,
        gpa: Allocator,
        input: []u8,
        writer: *Io.Writer,
    ) Error!Status {
        var data = input;
        while (true) {
            const result = self.handler.feed(data) catch {
                try ws.writeClose(writer, .protocol_error);
                return .close;
            };
            data = data[result.consumed..];

            switch (result.message) {
                .data => |payload| {
                    self.msg.appendSlice(gpa, payload) catch {
                        try ws.writeClose(writer, .too_big);
                        return .close;
                    };
                },
                .data_end => |end| {
                    var decompressed: ?std.ArrayList(u8) = null;
                    defer if (decompressed) |*d| d.deinit(gpa);

                    if (end.compressed) {
                        const z = self.zlib orelse {
                            try ws.writeClose(writer, .protocol_error);
                            return .close;
                        };
                        decompressed = z.inflate(gpa, &self.msg) catch {
                            try ws.writeClose(writer, .protocol_error);
                            return .close;
                        };
                    }

                    const payload = if (decompressed) |d| d.items else self.msg.items;

                    if (end.opcode == .text) {
                        if (!std.unicode.utf8ValidateSlice(payload)) {
                            try ws.writeClose(writer, .invalid_payload);
                            return .close;
                        }
                    }

                    if (self.zlib) |z| {
                        const comp = z.deflate(gpa, payload) catch {
                            try ws.writeClose(writer, .internal_error);
                            return .close;
                        };
                        defer gpa.free(comp);
                        try ws.writeFrame(writer, comp, .{
                            .opcode = end.opcode,
                            .compressed = true,
                        });
                    } else {
                        try ws.writeFrame(writer, payload, .{ .opcode = end.opcode });
                    }
                    self.msg.clearRetainingCapacity();
                },
                .ping => |payload| try ws.writePong(writer, payload),
                .pong => {},
                .close => |payload| {
                    if (ws.parseClosePayload(payload)) |cp_opt| {
                        if (cp_opt) |cp| {
                            if (!std.unicode.utf8ValidateSlice(cp.reason)) {
                                try ws.writeClose(writer, .invalid_payload);
                                return .close;
                            }
                        }
                        try ws.writeFrame(writer, payload, .{ .opcode = .close });
                    } else |_| {
                        try ws.writeClose(writer, .protocol_error);
                    }
                    return .close;
                },
                .need_more => break,
            }
        }
        return .continue_reading;
    }
};

fn extractWebSocketKey(request: []const u8) ?[]const u8 {
    return extractHeader(request, "Sec-WebSocket-Key: ");
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

fn parsePort() u16 {
    var args = std.process.args();
    _ = args.next();
    const port_str = args.next() orelse return 9002;
    return std.fmt.parseInt(u16, port_str, 10) catch 9002;
}
