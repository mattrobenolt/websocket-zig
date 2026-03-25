# AGENTS.md

IO-agnostic WebSocket frame parser and serializer in Zig. Zero allocations, no IO, bring-your-own-buffers. Implements [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455).

## Architecture

- `src/root.zig` — library entry point. Re-exports the public API and contains the `writeFrame`/`writeClose`/`writePing`/`writePong` helpers.
- `src/frame.zig` — core types (`Opcode`, `RsvBits`, `FrameHeader`, `Mask`, `Event`, `ParseError`), `BoundedBuffer`, and `readInt`/`writeInt` helpers.
- `src/parse.zig` — streaming `Parser` (server/client), `MessageValidator`, and `FrameHandler` (higher-level message-oriented API).
- `src/close.zig` — `CloseCode`, `ClosePayload`, `parseClosePayload`.
- `src/handshake.zig` — `computeAcceptKey`, `UpgradeRequest`, `validateUpgradeRequest`, `UpgradeResponse`.
- `src/MessageWriter.zig` — fragmented message writer (file-as-struct).
- `test/echo_server.zig` — test scaffolding only. A minimal echo server for running the Autobahn conformance suite. Not part of the library.
- `examples/blocking-echo.zig` — single-threaded blocking echo server using `std.net` and `std.Io`. Simplest possible integration.
- `examples/http-upgrade.zig` — thread-per-connection HTTP server using `std.http.Server` with WebSocket upgrade on `/ws` and a static HTML page on `/`. Uses `@embedFile` for the HTML.
- `examples/xev-echo.zig` — completion-based echo server using libxev's event loop with connection pooling. Most production-like example.

## Design Decisions

- **No UTF-8 validation.** Text frame payloads are treated as opaque bytes. UTF-8 validation is the caller's responsibility. The echo server does its own validation to satisfy Autobahn.
- **No compression.** We do not implement `permessage-deflate` (RFC 7692). The Autobahn compression tests (categories 12–13) report `UNIMPLEMENTED`, which is the correct status.
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
just conformance      # Run the Autobahn conformance suite (requires Docker)
just conformance-xev  # Run Autobahn against xev echo server
just ci               # All checks: format, lint, test, conformance
just report           # Serve the Autobahn HTML report on localhost:8080
```
## RFC Reference

The full RFC 6455 text is at `rfc6455.txt` in the project root. A quick-reference skill is at `.agents/skills/rfc6455.md`.
