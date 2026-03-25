[default]
_default:
    @just --list

[doc("Run unit tests")]
test *args:
    zig build test --summary all {{args}}

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

[doc("Run the Autobahn conformance suite")]
conformance:
    rm -rf test/autobahn/reports
    zig build conformance

[doc("Run Autobahn against the xev echo server")]
conformance-xev:
    rm -rf test/autobahn/reports
    zig build conformance-xev

[doc("Run all checks: format, lint, test, conformance")]
ci: check test conformance

[doc("Serve the Autobahn report in a browser")]
report port="8080":
    @echo "http://localhost:{{port}}/index.html"
    python3 -m http.server -d test/autobahn/reports -b 127.0.0.1 {{port}}
