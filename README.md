# websocket-zig

IO-agnostic WebSocket frame parser and serializer for Zig. Zero allocations, no IO ownership, bring-your-own-buffers. Designed for completion-based IO engines like io_uring.

Implements [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455). Passes the [Autobahn test suite](https://github.com/crossbario/autobahn-testsuite).

## Usage

Add the dependency:

```
zig fetch --save git+https://github.com/mattrobenolt/websocket-zig
```

Then in your `build.zig`:

```zig
const websocket = b.dependency("websocket", .{ .target = target });
exe.root_module.addImport("websocket", websocket.module("websocket"));
```

### Frame Handler (recommended)

`ServerFrameHandler` / `ClientFrameHandler` wraps the parser with fragmentation validation, control frame accumulation, and message-level events. This is the easiest way to use the library:

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
        .ping => |payload| try ws.writeFrame(writer, .pong, payload),
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

`ServerParser` / `ClientParser` gives raw frame-level events for full control. The frame handler is built on top of this.

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

### Serialization

```zig
// Write a complete frame (header + payload) and flush.
try ws.writeFrame(writer, .text, payload);

// Write a close frame with a status code.
try ws.writeClose(writer, .normal);

// Or serialize the header separately for scatter-gather IO.
const header: ws.FrameHeader.Buffer = .init(.{
    .opcode = .text,
    .payload_len = payload.len,
});
// header.constSlice() returns the wire bytes.
```

### Masking

```zig
// Stateful masker for incremental processing.
var mask: ws.Mask = .init(mask_key);
mask.apply(chunk1);
mask.apply(chunk2);

// XOR is its own inverse — apply the same mask to unmask.
```

### Handshake

```zig
// Build the full HTTP 101 response.
const resp: ws.UpgradeResponse = .init(client_key);
try resp.write(writer);

// Or compute just the Sec-WebSocket-Accept value.
var accept_buf: ws.AcceptKey = undefined;
const accept = ws.computeAcceptKey(client_key, &accept_buf);
```

## Examples

The `examples/` directory contains complete, runnable echo servers at different levels of complexity:

- **`blocking-echo`** — single-threaded blocking server using `std.net` and `std.Io`. Simplest possible integration.
- **`http-upgrade`** — thread-per-connection HTTP server using `std.http.Server`. Serves a test page on `/` and upgrades to WebSocket on `/ws`.
- **`xev-echo`** — completion-based server using [libxev](https://github.com/mitchellh/libxev) with connection pooling. Most production-like example.

Build all examples:

```
just examples
```

## Conformance

The library passes the [Autobahn test suite](https://github.com/crossbario/autobahn-testsuite). Running the suite requires Docker:

```
just conformance
```

View the HTML report:

```
just report
```

## Design

- **Two abstraction levels.** `ServerFrameHandler` handles fragmentation validation, control frame accumulation, and message boundaries. `ServerParser` gives raw frame events for when you need full control.
- **No IO.** The library never reads or writes bytes. You feed it data, it gives you events.
- **No allocations.** The parser uses a 14-byte internal buffer for frame headers. The frame handler adds a 125-byte buffer for control frame payloads. Everything else operates on caller-provided slices.
- **No UTF-8 validation.** Text frame payloads are opaque bytes. Validation is the caller's choice.
- **No compression.** `permessage-deflate` (RFC 7692) is not implemented.

## License

MIT
