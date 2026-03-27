# AGENTS.md

IO-agnostic WebSocket frame parser and serializer in Zig. Zero allocations, no IO, bring-your-own-buffers. Implements [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455).

## Architecture

- `src/root.zig` — library entry point. Exports the `client` and `server` namespaces.
- `src/client.zig` — client namespace. Re-exports client-side types (`Parser`, `FrameHandler`, `MessageWriter`) and provides masked `writeFrame`/`writeClose`/`writePing`/`writePong`.
- `src/server.zig` — server namespace. Re-exports server-side types (`Parser`, `FrameHandler`, `MessageWriter`, `UpgradeResponse`) and provides unmasked `writeFrame`/`writeClose`/`writePing`/`writePong`.
- `src/frame.zig` — core types (`Opcode`, `RsvBits`, `FrameHeader`, `Mask`, `Event`, `ParseError`, `WriteFrameOptions`), `BoundedBuffer`, `generateMaskKey`, and `readInt`/`writeInt` helpers.
- `src/parse.zig` — streaming `Parser` (server/client), `MessageValidator`, and `FrameHandler` (higher-level message-oriented API).
- `src/close.zig` — `CloseCode`, `ClosePayload`, `parseClosePayload`.
- `src/handshake.zig` — `computeAcceptKey`, `UpgradeRequest`, `validateUpgradeRequest`, `UpgradeResponse`.
- `src/message_writer.zig` — `MessageWriter(comptime masked: bool)` generic, instantiated as `ServerMessageWriter` (unmasked) and `ClientMessageWriter` (masked).
- `test/echo_server.zig` — test scaffolding only. A minimal echo server for running the Autobahn conformance suite. Not part of the library.
- `examples/blocking-echo.zig` — single-threaded blocking echo server using `std.net` and `std.Io`. Simplest possible integration.
- `examples/http-upgrade.zig` — thread-per-connection HTTP server using `std.http.Server` with WebSocket upgrade on `/ws` and a static HTML page on `/`. Uses `@embedFile` for the HTML.
- `examples/xev-echo.zig` — completion-based echo server using libxev's event loop with connection pooling. Most production-like example.

## Design Decisions

- **No UTF-8 validation.** Text frame payloads are treated as opaque bytes. UTF-8 validation is the caller's responsibility. The echo server does its own validation to satisfy Autobahn.
- **Permessage-deflate.** The library supports the `permessage-deflate` extension (RFC 7692) via the `Extension` type and the `compressed` flag on `WriteFrameOptions`. The echo server negotiates compression for the Autobahn conformance suite.
- **No handshake HTTP parsing.** The library provides `computeAcceptKey` for the `Sec-WebSocket-Accept` header, but HTTP upgrade parsing is the caller's responsibility.

## Development

Requires [Nix](https://nixos.org/) with flakes. All tools come from the devshell — do not install anything globally.

```
nix develop
```

## Tasks

All tasks are in the `justfile`:

```
just test             # Run unit tests
just fmt              # Format all Zig source files
just fmt-check        # Check formatting without modifying files
just lint             # Run ziglint
just check            # Format check and lint
just examples         # Build all examples
just autobahn-setup   # Install the native Autobahn TestSuite runtime
just conformance      # Run the fast native Autobahn suite for local iteration
just conformance-full # Run the full native Autobahn suite
just conformance-xev  # Run the fast Autobahn suite against xev echo server
just ci               # All checks: format, lint, test, full conformance
just report           # Serve the Autobahn HTML report on localhost:8080
```
## RFC Reference

The full RFC 6455 text is at `rfc6455.txt` in the project root. A quick-reference skill is at `.agents/skills/rfc6455.md`.
