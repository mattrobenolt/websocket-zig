const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const Io = std.Io;
const Sha1 = std.crypto.hash.Sha1;
const B64Encoder = std.base64.standard.Encoder;

const frame = @import("frame.zig");
const AcceptKey = frame.AcceptKey;
const BoundedBuffer = frame.BoundedBuffer;

/// RFC 6455 Section 4.2.2 GUID used in Sec-WebSocket-Accept computation.
const handshake_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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

test "computeAcceptKey matches RFC 6455 Section 4.2.2 example" {
    var buf: AcceptKey = undefined;
    const accept = computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==", &buf);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "handshake_guid matches RFC 6455" {
    try testing.expectEqualStrings("258EAFA5-E914-47DA-95CA-C5AB0DC85B11", handshake_guid);
}

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
