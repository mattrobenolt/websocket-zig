# websocket-zig

A streaming WebSocket parser and serializer for Zig. In the same spirit as [picohttpparser](https://github.com/h2o/picohttpparser) or [nghttp2](https://nghttp2.org/), this is a bring-your-own-IO library: you feed it bytes, it gives you parsed frames. It never touches a socket, never allocates, and has no opinion about your event loop.

Implements [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455). Passes the [Autobahn test suite](https://github.com/crossbario/autobahn-testsuite). Requires Zig 0.15.

## Install

```
zig fetch --save git+https://github.com/mattrobenolt/websocket-zig
```

```zig
// build.zig
const websocket = b.dependency("websocket", .{ .target = target });
exe.root_module.addImport("websocket", websocket.module("websocket"));
```

## Parsing

### Frame Handler (recommended)

`ServerFrameHandler` / `ClientFrameHandler` handles fragmentation, control frame accumulation, and message boundaries. Feed it bytes, switch on events:

```zig
const ws = @import("websocket");

var handler: ws.ServerFrameHandler = .init;

while (true) {
    const result = try handler.feed(buf);
    buf = buf[result.consumed..];

    switch (result.message) {
        .data => |payload| {
            // Accumulate message payload.
        },
        .data_end => |end| {
            // Complete message received. end.opcode is .text or .binary.
        },
        .ping => |payload| try ws.writePong(writer, payload),
        .pong => {},
        .close => |payload| {
            try ws.writeFrame(writer, .close, payload);
            return;
        },
        .need_more => break,
    }
}
```

### Low-Level Parser

`ServerParser` / `ClientParser` gives raw frame-level events for full control. The frame handler above is built on top of this:

```zig
var parser: ws.ServerParser = .init;

while (true) {
    const result = try parser.feed(buf);
    buf = buf[result.consumed..];

    switch (result.event) {
        .frame_header => |hdr| {
            // hdr.fin, hdr.opcode, hdr.payload_len, hdr.mask_key
        },
        .payload => |data| {
            // Slice into your input buffer, already unmasked.
        },
        .frame_end => {},
        .need_more => break,
    }
}
```

## Serialization

```zig
// Complete frame in one call.
try ws.writeFrame(writer, .text, payload);

// Close with a status code.
try ws.writeClose(writer, .normal);

// Stream a large message across multiple frames.
var msg: ws.MessageWriter = .init(writer, .text);
try msg.writeChunk(part1);
try msg.writeChunk(part2);
try msg.finish(part3);

// Serialize just the header for scatter-gather IO.
const header: ws.FrameHeader.Buffer = .init(.{
    .opcode = .text,
    .payload_len = payload.len,
});
```

## Masking

```zig
var mask: ws.Mask = .init(mask_key);
mask.apply(chunk1);
mask.apply(chunk2);
// XOR is its own inverse: apply the same mask to unmask.
```

## Handshake

Computes the `Sec-WebSocket-Accept` value and can generate the full HTTP 101 response. HTTP parsing is your responsibility.

```zig
// Build the full HTTP 101 response.
const resp: ws.UpgradeResponse = .init(client_key);
try resp.write(writer);

// Or compute just the accept key.
var accept_buf: ws.AcceptKey = undefined;
const accept = ws.computeAcceptKey(client_key, &accept_buf);
```

## Examples

The `examples/` directory has complete, runnable echo servers:

| Example | What it demonstrates |
|---|---|
| **`blocking-echo`** | Single-threaded blocking server with `std.net`. Simplest possible integration. |
| **`http-upgrade`** | Thread-per-connection HTTP server. Serves a test page on `/`, upgrades to WebSocket on `/ws`. |
| **`xev-echo`** | Completion-based server on [libxev](https://github.com/mitchellh/libxev) with connection pooling. Closest to production use. |

```
just examples
```

## Design

- **No allocations.** The parser operates on caller-provided buffers and returns slices back into them. Internal state is a 14-byte header buffer in the parser, plus 125 bytes in the frame handler for control frame payloads.
- **No UTF-8 validation.** Text frame payloads are opaque bytes. Validation is the caller's choice.
- **No compression.** `permessage-deflate` (RFC 7692) is not implemented.
- **No HTTP parsing.** The handshake computes `Sec-WebSocket-Accept`. Everything else about your HTTP stack is up to you.

## Conformance

Passes the full [Autobahn test suite](https://github.com/crossbario/autobahn-testsuite). Run it yourself (requires Docker):

```
just conformance
just report        # serve the HTML report on localhost:8080
```

## License

MIT
