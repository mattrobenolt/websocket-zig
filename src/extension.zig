const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const frame = @import("frame.zig");
const RsvBits = frame.RsvBits;

pub const Extension = union(enum) {
    permessage_deflate: DeflateConfig,

    pub const DeflateConfig = struct {
        server_no_context_takeover: bool,
        client_no_context_takeover: bool,
        server_max_window_bits: WindowBits,
        client_max_window_bits: WindowBits,

        pub const init: DeflateConfig = .{
            .server_no_context_takeover = false,
            .client_no_context_takeover = false,
            .server_max_window_bits = .@"15",
            .client_max_window_bits = .@"15",
        };
    };

    pub const WindowBits = enum(u4) {
        @"8" = 8,
        @"9" = 9,
        @"10" = 10,
        @"11" = 11,
        @"12" = 12,
        @"13" = 13,
        @"14" = 14,
        @"15" = 15,
    };

    pub fn claimedRsv(self: Extension) RsvBits {
        return switch (self) {
            .permessage_deflate => .permessage_deflate,
        };
    }

    pub fn allowedRsv(ext: ?Extension) RsvBits {
        return if (ext) |e| e.claimedRsv() else .empty;
    }

    pub const max_header_len = 256;
    pub const HeaderBuffer = frame.BoundedBuffer(max_header_len);

    pub fn writeHeader(self: Extension, buf: *HeaderBuffer) void {
        assert(buf.len == 0);
        switch (self) {
            .permessage_deflate => |cfg| {
                buf.appendSliceAssumeCapacity("permessage-deflate");
                if (cfg.server_no_context_takeover) {
                    buf.appendSliceAssumeCapacity("; server_no_context_takeover");
                }
                if (cfg.client_no_context_takeover) {
                    buf.appendSliceAssumeCapacity("; client_no_context_takeover");
                }
                if (cfg.server_max_window_bits != .@"15") {
                    buf.appendSliceAssumeCapacity("; server_max_window_bits=");
                    buf.appendSliceAssumeCapacity(@tagName(cfg.server_max_window_bits));
                }
                if (cfg.client_max_window_bits != .@"15") {
                    buf.appendSliceAssumeCapacity("; client_max_window_bits=");
                    buf.appendSliceAssumeCapacity(@tagName(cfg.client_max_window_bits));
                }
            },
        }
    }
};

test "Extension.claimedRsv: permessage_deflate claims RSV1" {
    const ext: Extension = .{ .permessage_deflate = .init };
    const rsv = ext.claimedRsv();
    try testing.expect(rsv.rsv1);
    try testing.expect(!rsv.rsv2);
    try testing.expect(!rsv.rsv3);
}

test "Extension.allowedRsv: null" {
    const rsv = Extension.allowedRsv(null);
    try testing.expect(!rsv.areSet());
}

test "Extension.allowedRsv: permessage_deflate" {
    const rsv = Extension.allowedRsv(.{ .permessage_deflate = .init });
    try testing.expect(rsv.rsv1);
    try testing.expect(!rsv.rsv2);
    try testing.expect(!rsv.rsv3);
}

test "Extension.writeHeader: default config" {
    const ext: Extension = .{ .permessage_deflate = .init };
    var buf: Extension.HeaderBuffer = .empty;
    ext.writeHeader(&buf);
    try testing.expectEqualStrings("permessage-deflate", buf.constSlice());
}

test "Extension.writeHeader: all params set" {
    const ext: Extension = .{ .permessage_deflate = .{
        .server_no_context_takeover = true,
        .client_no_context_takeover = true,
        .server_max_window_bits = .@"10",
        .client_max_window_bits = .@"12",
    } };
    var buf: Extension.HeaderBuffer = .empty;
    ext.writeHeader(&buf);
    try testing.expectEqualStrings(
        "permessage-deflate" ++
            "; server_no_context_takeover" ++
            "; client_no_context_takeover" ++
            "; server_max_window_bits=10" ++
            "; client_max_window_bits=12",
        buf.constSlice(),
    );
}

test "Extension.writeHeader: only server_no_context_takeover" {
    var cfg: Extension.DeflateConfig = .init;
    cfg.server_no_context_takeover = true;
    const ext: Extension = .{ .permessage_deflate = cfg };
    var buf: Extension.HeaderBuffer = .empty;
    ext.writeHeader(&buf);
    try testing.expectEqualStrings(
        "permessage-deflate; server_no_context_takeover",
        buf.constSlice(),
    );
}
