[default]
_default:
    @just --list

[doc("Run unit tests")]
test *args:
    zig build test --summary all {{ args }}

[doc("Format all Zig source files")]
fmt:
    zig fmt src/ test/ examples/ build.zig

[doc("Check formatting without modifying files")]
fmt-check:
    zig fmt --check src/ test/ examples/ build.zig

[doc("Run ziglint")]
lint:
    ziglint

[doc("Format and lint")]
check: fmt-check lint

[doc("Build all examples")]
examples:
    zig build examples

[doc("Install the native Autobahn TestSuite into the local PyPy environment")]
autobahn-setup:
    ./scripts/setup-autobahn-native.nu

[doc("Regenerate the Autobahn hashed dependency lock")]
autobahn-lock:
    ./scripts/generate-autobahn-lock.nu

[doc("Run native wstest from the local PyPy environment")]
autobahn-wstest *args: autobahn-setup
    ./scripts/wstest-native.nu {{ args }}

[doc("Run the fast Autobahn conformance suite for local iteration")]
conformance: autobahn-setup
    zig build conformance

[doc("Run the full Autobahn conformance suite")]
conformance-full: autobahn-setup
    zig build conformance-full

[doc("Run the fast Autobahn client conformance suite")]
conformance-client: autobahn-setup
    zig build conformance-client

[doc("Run the full Autobahn client conformance suite")]
conformance-client-full: autobahn-setup
    zig build conformance-client-full

[doc("Run the fast Autobahn suite against the xev echo server")]
conformance-xev: autobahn-setup
    zig build conformance-xev

[doc("Run all checks: format, lint, test, full conformance")]
ci: check test conformance-full

[doc("Serve the Autobahn report in a browser")]
report port="8080":
    @echo "http://localhost:{{ port }}/index.html"
    python3 -m http.server -d test/autobahn/reports -b 127.0.0.1 {{ port }}
