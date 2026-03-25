#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SERVER_BIN="${1:?Usage: $0 <server-binary> [port] [agent-name]}"
SERVER_PORT="${2:-9002}"
AGENT_NAME="${3:-websocket-zig}"

REPORTS_DIR="$PROJECT_DIR/test/autobahn/reports"

if [ ! -x "$SERVER_BIN" ]; then
    echo "ERROR: server not found at $SERVER_BIN"
    exit 1
fi

if [[ "$(uname)" == "Darwin" ]]; then
    HOST_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "127.0.0.1")
else
    HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    HOST_IP="${HOST_IP:-127.0.0.1}"
fi

AUTOBAHN_CONFIG=$(mktemp)
cat > "$AUTOBAHN_CONFIG" <<EOF
{
    "outdir": "/reports",
    "servers": [{"agent": "$AGENT_NAME", "url": "ws://$HOST_IP:$SERVER_PORT"}],
    "cases": ["*"],
    "exclude-cases": [],
    "options": {"failByDrop": false}
}
EOF

echo "Starting $AGENT_NAME on 0.0.0.0:$SERVER_PORT..."
"$SERVER_BIN" "$SERVER_PORT" &
SERVER_PID=$!

cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    rm -f "$AUTOBAHN_CONFIG"
}
trap cleanup EXIT

sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: server failed to start"
    exit 1
fi

mkdir -p "$REPORTS_DIR"

echo "Running Autobahn against ws://$HOST_IP:$SERVER_PORT..."
timeout 600 docker run --rm \
    -v "$AUTOBAHN_CONFIG:/config/fuzzingclient.json:ro" \
    -v "$REPORTS_DIR:/reports" \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingclient -s /config/fuzzingclient.json

echo ""
echo "Results: $REPORTS_DIR/index.html"
echo ""

if [ -f "$REPORTS_DIR/index.json" ]; then
    python3 -c "
import json, sys
with open('$REPORTS_DIR/index.json') as f:
    results = json.load(f)
for agent, cases in results.items():
    failed = {k: v['behavior'] for k, v in cases.items()
              if v['behavior'] not in ('OK', 'NON-STRICT', 'INFORMATIONAL', 'UNIMPLEMENTED')}
    total = len(cases)
    passed = total - len(failed)
    print(f'{agent}: {passed}/{total} passed')
    if failed:
        for case_id, behavior in sorted(failed.items())[:20]:
            print(f'  FAIL {case_id}: {behavior}')
        if len(failed) > 20:
            print(f'  ... and {len(failed) - 20} more')
        sys.exit(1)
"
fi
