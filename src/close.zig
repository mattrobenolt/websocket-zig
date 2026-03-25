const std = @import("std");
const testing = std.testing;

const frame = @import("frame.zig");
const readInt = frame.readInt;
const writeInt = frame.writeInt;

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
