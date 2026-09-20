#!/usr/bin/env bash
#
# Stress test for the curl-hang bug.
#
# Usage:
#   tests/test_curl_hang.sh [iterations] [disk_size_mb]
#
# Defaults: 10 iterations, 128 MB disk.
# Requires: curl.layer in project root.
# A temporary HTTP server is started on port 18199 for the duration.

set -euo pipefail
cd "$(dirname "$0")/.."

# The guest is an arm64 VM: skip (do not fail) on hosts that cannot run it.
case "$(uname -m)" in
    aarch64 | arm64 | x86_64) ;;
    *)
        echo "test_curl_hang: SKIP: host cannot run the guest (machine=$(uname -m))"
        exit 0
        ;;
esac

ITERATIONS=${1:-10}
DISK_SIZE=${2:-128}
PORT=18199
PASS=0
FAIL=0

# --- Start a tiny HTTP server ---------------------------------------------------
cleanup() {
    if [[ -n "${HTTP_PID:-}" ]]; then
        kill "$HTTP_PID" 2>/dev/null || true
        wait "$HTTP_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Python one-liner HTTP server that returns "SANDAL_TEST_OK"
python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'SANDAL_TEST_OK\n')
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(('', $PORT), H) as s:
    s.serve_forever()
" &
HTTP_PID=$!
# Give it a moment to bind
sleep 0.3

# --- Run iterations -------------------------------------------------------------
echo "=== curl-hang stress test: ${ITERATIONS} iterations, disk_size=${DISK_SIZE}MB ==="

for i in $(seq 1 "$ITERATIONS"); do
    if expect tests/test_fetch_hang.exp "$DISK_SIZE" 2>/tmp/sandal_test_stderr; then
        PASS=$((PASS + 1))
        printf "  [%2d/%d] PASS\n" "$i" "$ITERATIONS"
    else
        FAIL=$((FAIL + 1))
        printf "  [%2d/%d] FAIL\n" "$i" "$ITERATIONS"
        # Print diagnostic output from stderr (deadlock dump etc.)
        if [ -s /tmp/sandal_test_stderr ]; then
            echo "--- stderr ---"
            cat /tmp/sandal_test_stderr
            echo "--- end stderr ---"
        fi
    fi
done

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed out of ${ITERATIONS}"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
