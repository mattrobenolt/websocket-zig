/// Minimal WebSocket echo client for the Autobahn test suite.
///
/// TEST SCAFFOLDING ONLY — not part of the library.
///
/// Connects to a running Autobahn fuzzingserver, iterates all test cases,
/// echoes back everything the server sends, then triggers report generation.
/// Supports permessage-deflate (RFC 7692) when offered by the server.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = std.net;
const Stream = net.Stream;
const Address = net.Address;
const mem = std.mem;
const print = std.debug.print;

const ws = @import("websocket").client;
const DeflateConfig = ws.Extension.DeflateConfig;

const c = @cImport(@cInclude("zlib.h"));

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const args = parseArgs();

    print("getting case count from fuzzingserver on port {d}...\n", .{args.port});
    const case_count = try getCaseCount(args.port);
    print("running {d} test cases as \"{s}\"...\n", .{ case_count, args.agent });

    var i: u32 = 1;
    while (i <= case_count) : (i += 1) {
        if (i % 100 == 0 or i == 1 or i == case_count) {
            print("  case {d}/{d}\n", .{ i, case_count });
        }
        runCase(allocator, args.port, i, args.agent) catch |err| {
            print("  case {d} error: {s}\n", .{ i, @errorName(err) });
        };
    }

    print("updating reports...\n", .{});
    try updateReports(args.port, args.agent);
    print("done.\n", .{});
}

fn getCaseCount(port: u16) !u32 {
    const stream = try tcpConnect(port);
    defer stream.close();

    var read_buf: [4096]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(&read_buf);
    var stream_writer = stream.writer(&write_buf);
    const reader = stream_reader.interface();
    const writer = &stream_writer.interface;

    _ = try doHandshake(reader, writer, port, "/getCaseCount", false);

    var handler: ws.FrameHandler = .init(.{});
    var count_buf: [32]u8 = undefined;
    var count_len: usize = 0;

    while (true) {
        reader.fill(1) catch return error.ConnectionClosed;
        const buf = reader.buffered();
        if (buf.len == 0) return error.ConnectionClosed;

        var data = buf;
        while (true) {
            const result = handler.feed(data) catch return error.ProtocolError;
            data = data[result.consumed..];

            switch (result.message) {
                .data => |payload| {
                    if (count_len + payload.len > count_buf.len) return error.InvalidResponse;
                    @memcpy(count_buf[count_len..][0..payload.len], payload);
                    count_len += payload.len;
                },
                .data_end => {},
                .ping => |payload| {
                    var pong_buf: [ws.max_control_payload_len]u8 = undefined;
                    const pong = pong_buf[0..payload.len];
                    @memcpy(pong, payload);
                    try ws.writePong(writer, pong);
                    try writer.flush();
                },
                .pong => {},
                .close => |payload| {
                    var close_buf: [ws.max_control_payload_len]u8 = undefined;
                    const close_data = close_buf[0..payload.len];
                    @memcpy(close_data, payload);
                    try ws.writeFrame(writer, close_data, .{ .opcode = .close });
                    try writer.flush();
                    return std.fmt.parseInt(u32, count_buf[0..count_len], 10) catch
                        return error.InvalidResponse;
                },
                .need_more => break,
            }
        }
        reader.toss(buf.len - data.len);
    }
}

fn runCase(allocator: Allocator, port: u16, case_num: u32, agent: []const u8) !void {
    const stream = try tcpConnect(port);
    defer stream.close();

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var stream_reader = stream.reader(&read_buf);
    var stream_writer = stream.writer(&write_buf);
    const reader = stream_reader.interface();
    const writer = &stream_writer.interface;

    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/runCase?case={d}&agent={s}", .{
        case_num, agent,
    }) catch return error.PathTooLong;

    const hs = try doHandshake(reader, writer, port, path, true);

    var echo: EchoHandler = try .init(allocator, hs.deflate);
    defer echo.deinit(allocator);
    echo.run(allocator, reader, writer) catch return;
}

fn updateReports(port: u16, agent: []const u8) !void {
    const stream = try tcpConnect(port);
    defer stream.close();

    var read_buf: [4096]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(&read_buf);
    var stream_writer = stream.writer(&write_buf);
    const reader = stream_reader.interface();
    const writer = &stream_writer.interface;

    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/updateReports?agent={s}", .{agent}) catch
        return error.PathTooLong;

    _ = try doHandshake(reader, writer, port, path, false);

    var handler: ws.FrameHandler = .init(.{});
    while (true) {
        reader.fill(1) catch return;
        const buf = reader.buffered();
        if (buf.len == 0) return;

        var data = buf;
        while (true) {
            const result = handler.feed(data) catch return;
            data = data[result.consumed..];

            switch (result.message) {
                .data, .data_end, .pong => {},
                .ping => |payload| {
                    var pong_buf: [ws.max_control_payload_len]u8 = undefined;
                    const pong = pong_buf[0..payload.len];
                    @memcpy(pong, payload);
                    try ws.writePong(writer, pong);
                    try writer.flush();
                },
                .close => |payload| {
                    var close_buf: [ws.max_control_payload_len]u8 = undefined;
                    const close_data = close_buf[0..payload.len];
                    @memcpy(close_data, payload);
                    try ws.writeFrame(writer, close_data, .{ .opcode = .close });
                    try writer.flush();
                    return;
                },
                .need_more => break,
            }
        }
        reader.toss(buf.len - data.len);
    }
}

const HandshakeResult = struct {
    deflate: ?DeflateConfig,
};

fn doHandshake(
    reader: *Io.Reader,
    writer: *Io.Writer,
    port: u16,
    path: []const u8,
    offer_deflate: bool,
) !HandshakeResult {
    var key_raw: [16]u8 = undefined;
    std.crypto.random.bytes(&key_raw);
    var key_b64: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&key_b64, &key_raw);

    const ext_line: []const u8 = if (offer_deflate)
        "Sec-WebSocket-Extensions: permessage-deflate\r\n"
    else
        "";

    var req_buf: [512]u8 = undefined;
    const req = std.fmt.bufPrint(
        &req_buf,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:{d}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "{s}" ++
            "\r\n",
        .{ path, port, &key_b64, ext_line },
    ) catch return error.RequestTooLong;

    try writer.writeAll(req);
    try writer.flush();

    while (true) {
        reader.fill(1) catch return error.ConnectionClosed;
        const buf = reader.buffered();
        if (buf.len == 0) return error.ConnectionClosed;
        if (mem.indexOf(u8, buf, "\r\n\r\n")) |end| {
            const header_end = end + 4;
            const headers = buf[0..header_end];

            if (!mem.startsWith(u8, headers, "HTTP/1.1 101 "))
                return error.BadUpgradeStatus;

            const accept = extractHeader(headers, "Sec-WebSocket-Accept: ") orelse
                return error.MissingAcceptKey;
            var expected_buf: ws.AcceptKey = undefined;
            const expected = ws.computeAcceptKey(&key_b64, &expected_buf);
            if (!mem.eql(u8, accept, expected))
                return error.InvalidAcceptKey;

            const deflate: ?DeflateConfig = if (offer_deflate)
                negotiateDeflate(headers)
            else
                null;

            reader.toss(header_end);
            return .{ .deflate = deflate };
        }
    }
}

fn negotiateDeflate(headers: []const u8) ?DeflateConfig {
    const ext_value = extractHeader(headers, "Sec-WebSocket-Extensions: ") orelse return null;
    if (mem.indexOf(u8, ext_value, "permessage-deflate") == null) return null;

    var cfg: DeflateConfig = .init;
    if (mem.indexOf(u8, ext_value, "server_no_context_takeover") != null)
        cfg.server_no_context_takeover = true;
    if (mem.indexOf(u8, ext_value, "client_no_context_takeover") != null)
        cfg.client_no_context_takeover = true;
    if (extractParamValue(ext_value, "server_max_window_bits")) |v|
        cfg.server_max_window_bits = v;
    if (extractParamValue(ext_value, "client_max_window_bits")) |v|
        cfg.client_max_window_bits = v;
    return cfg;
}

fn extractParamValue(
    ext_value: []const u8,
    param: []const u8,
) ?ws.Extension.WindowBits {
    const idx = mem.indexOf(u8, ext_value, param) orelse return null;
    const after = ext_value[idx + param.len ..];
    if (after.len == 0 or after[0] != '=') return null;
    const rest = after[1..];

    var end_pos: usize = 0;
    while (end_pos < rest.len and rest[end_pos] >= '0' and rest[end_pos] <= '9') end_pos += 1;
    if (end_pos == 0) return null;

    const val = std.fmt.parseInt(u4, rest[0..end_pos], 10) catch return null;
    return std.meta.intToEnum(ws.Extension.WindowBits, val) catch null;
}

const sync_flush_suffix = [_]u8{ 0x00, 0x00, 0xff, 0xff };

const ZlibState = struct {
    inflate_stream: c.z_stream,
    deflate_stream: c.z_stream,
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,

    fn create(gpa: Allocator, cfg: DeflateConfig) !*ZlibState {
        const self = try gpa.create(ZlibState);
        errdefer gpa.destroy(self);

        self.* = .{
            .inflate_stream = mem.zeroes(c.z_stream),
            .deflate_stream = mem.zeroes(c.z_stream),
            .server_no_context_takeover = cfg.server_no_context_takeover,
            .client_no_context_takeover = cfg.client_no_context_takeover,
        };

        const inflate_wbits: c_int = @intFromEnum(cfg.server_max_window_bits);
        if (c.inflateInit2(&self.inflate_stream, -inflate_wbits) != c.Z_OK)
            return error.ZlibInitFailed;
        errdefer _ = c.inflateEnd(&self.inflate_stream);

        const deflate_wbits: c_int = @intFromEnum(cfg.client_max_window_bits);
        if (c.deflateInit2(
            &self.deflate_stream,
            c.Z_DEFAULT_COMPRESSION,
            c.Z_DEFLATED,
            -deflate_wbits,
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

    fn inflate(self: *ZlibState, gpa: Allocator, compressed: []const u8) !std.ArrayList(u8) {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);

        var buf: [8192]u8 = undefined;

        // Decompress the message payload, then the sync flush suffix
        // that was stripped per RFC 7692. Fed in two passes to avoid
        // mutating or copying the caller's buffer.
        var suffix = sync_flush_suffix;
        const passes = [2]struct { ptr: [*]u8, len: c_uint }{
            .{ .ptr = @constCast(compressed.ptr), .len = @intCast(compressed.len) },
            .{ .ptr = &suffix, .len = suffix.len },
        };
        for (&passes) |pass| {
            self.inflate_stream.next_in = pass.ptr;
            self.inflate_stream.avail_in = pass.len;
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
        }

        if (self.server_no_context_takeover) {
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

        if (out.items.len >= 4 and
            mem.eql(u8, out.items[out.items.len - 4 ..], &sync_flush_suffix))
        {
            out.shrinkRetainingCapacity(out.items.len - 4);
        }

        if (self.client_no_context_takeover) {
            _ = c.deflateReset(&self.deflate_stream);
        }

        return out.toOwnedSlice(gpa);
    }
};

const EchoHandler = struct {
    handler: ws.FrameHandler,
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
            const result = try self.processFrames(gpa, buf, writer);
            try writer.flush();
            if (result.closed) return;
            reader.toss(result.consumed);
        }
    }

    const ProcessResult = struct { consumed: usize, closed: bool };

    fn processFrames(
        self: *EchoHandler,
        gpa: Allocator,
        input: []u8,
        writer: *Io.Writer,
    ) Error!ProcessResult {
        var data = input;
        while (true) {
            const result = self.handler.feed(data) catch {
                try ws.writeClose(writer, .protocol_error);
                return .{ .consumed = input.len - data.len, .closed = true };
            };
            data = data[result.consumed..];

            switch (result.message) {
                .data => |payload| {
                    self.msg.appendSlice(gpa, payload) catch {
                        try ws.writeClose(writer, .too_big);
                        return .{ .consumed = input.len - data.len, .closed = true };
                    };
                },
                .data_end => |end| {
                    var decompressed: ?std.ArrayList(u8) = null;
                    defer if (decompressed) |*d| d.deinit(gpa);

                    if (end.compressed) {
                        const z = self.zlib orelse {
                            try ws.writeClose(writer, .protocol_error);
                            return .{ .consumed = input.len - data.len, .closed = true };
                        };
                        decompressed = z.inflate(gpa, self.msg.items) catch {
                            try ws.writeClose(writer, .protocol_error);
                            return .{ .consumed = input.len - data.len, .closed = true };
                        };
                    }

                    const payload = if (decompressed) |d| d.items else self.msg.items;

                    if (end.opcode == .text) {
                        if (!std.unicode.utf8ValidateSlice(payload)) {
                            try ws.writeClose(writer, .invalid_payload);
                            return .{ .consumed = input.len - data.len, .closed = true };
                        }
                    }

                    if (self.zlib) |z| {
                        const comp = z.deflate(gpa, payload) catch {
                            try ws.writeClose(writer, .internal_error);
                            return .{ .consumed = input.len - data.len, .closed = true };
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
                .ping => |payload| {
                    var pong_buf: [ws.max_control_payload_len]u8 = undefined;
                    const pong = pong_buf[0..payload.len];
                    @memcpy(pong, payload);
                    try ws.writePong(writer, pong);
                },
                .pong => {},
                .close => |payload| {
                    if (ws.parseClosePayload(payload)) |cp_opt| {
                        if (cp_opt) |cp| {
                            if (!std.unicode.utf8ValidateSlice(cp.reason)) {
                                try ws.writeClose(writer, .invalid_payload);
                                return .{ .consumed = input.len - data.len, .closed = true };
                            }
                        }
                        var close_buf: [ws.max_control_payload_len]u8 = undefined;
                        const close_data = close_buf[0..payload.len];
                        @memcpy(close_data, payload);
                        try ws.writeFrame(writer, close_data, .{ .opcode = .close });
                    } else |_| {
                        try ws.writeClose(writer, .protocol_error);
                    }
                    return .{ .consumed = input.len - data.len, .closed = true };
                },
                .need_more => break,
            }
        }
        return .{ .consumed = input.len - data.len, .closed = false };
    }
};

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

fn tcpConnect(port: u16) !Stream {
    const address: Address = try .resolveIp("127.0.0.1", port);
    return net.tcpConnectToAddress(address);
}

const Args = struct {
    port: u16,
    agent: []const u8,
};

fn parseArgs() Args {
    var args = std.process.args();
    _ = args.next();
    const port_str = args.next() orelse "9001";
    const agent = args.next() orelse "echo-client";
    return .{
        .port = std.fmt.parseInt(u16, port_str, 10) catch 9001,
        .agent = agent,
    };
}
