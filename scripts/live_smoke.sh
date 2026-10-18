#!/usr/bin/env bash
# Live end-to-end smoke test for Alya VPN (Linux/macOS).
#
# Starts a local HTTP target on the runner's own non-loopback IPv4 address
# (loopback targets always bypass the tunnel by design), then proves through
# a real server+client pair:
#   1. SOCKS5 tunneled fetch and HTTP CONNECT fetch (mode all)
#   2. split-tunnel include: curl tunnels, an unknown process goes direct
#   3. split-tunnel exclude: the reverse
# It also asserts /healthz reports the version from alya.toml (drift guard)
# and exercises the documented config/*.toml parsing (auto-loaded from cwd).
set -u

BIN=${1:-./alya-vpn}
SRV_PORT=51999
HEALTH_PORT=18099
HTTP_PORT=18777
PROXY_ALL=11180
PROXY_INC=11190
PROXY_EXC=11200
PSK="ci_smoke_psk_2026"
EXPECTED="alya-vpn-live-ok"

TMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/vpn-live-smoke"
rm -rf "$TMP"
mkdir -p "$TMP/www"
printf '%s' "$EXPECTED" > "$TMP/www/ok.txt"

SRV_LOG="$TMP/server.log"
HTTP_LOG="$TMP/http.log"
PIDS=""

cleanup() {
    for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

fail() {
    echo "SMOKE FAIL: $1"
    echo "--- server log (tail) ---"
    tail -40 "$SRV_LOG" 2>/dev/null || true
    echo "--- http log (tail) ---"
    tail -10 "$HTTP_LOG" 2>/dev/null || true
    for f in "$TMP"/client_*.log; do
        [ -f "$f" ] && { echo "--- $f (tail) ---"; tail -60 "$f"; }
    done
    exit 1
}

count_matches() { # file, regex -> count (0 when none)
    grep -c -E "$2" "$1" 2>/dev/null || true
}

socks_fetch() { # proxy port -> body on stdout
    curl -sS --max-time 15 --socks5 "127.0.0.1:$1" "http://$TIP:$HTTP_PORT/ok.txt" 2>/dev/null
}

socks_fetch_ready() { # wait until a tunneled fetch through the given proxy succeeds
    local i body
    i=0
    while [ "$i" -lt 60 ]; do
        i=$((i + 1))
        body=$(socks_fetch "$1") || true
        [ "$body" = "$EXPECTED" ] && return 0
        sleep 1
    done
    return 1
}

probe_fetch_ready() { # probe binary, proxy port: wait until the probe goes through the tunnel
    local i body
    i=0
    while [ "$i" -lt 60 ]; do
        i=$((i + 1))
        body=$("$1" -sS --max-time 15 --socks5 "127.0.0.1:$2" "http://$TIP:$HTTP_PORT/ok.txt" 2>/dev/null) || true
        [ "$body" = "$EXPECTED" ] && return 0
        sleep 1
    done
    return 1
}

# --- runner's own non-loopback IPv4 (the tunnel-proof target) ---
TIP=""
if command -v hostname >/dev/null 2>&1; then
    TIP=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | head -1) || true
fi
if [ -z "$TIP" ]; then TIP=$(ipconfig getifaddr en0 2>/dev/null || true); fi
if [ -z "$TIP" ]; then TIP=$(ipconfig getifaddr en1 2>/dev/null || true); fi
if [ -z "$TIP" ]; then
    TIP=$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | head -1) || true
fi
[ -n "$TIP" ] || fail "could not determine the runner's non-loopback IPv4"
echo "== target: http://$TIP:$HTTP_PORT (non-loopback = tunnel proof)"

# --- expected app version from the manifest (healthz drift guard) ---
APP_VERSION=$(grep -m1 -E '^version[[:space:]]*=' alya.toml | cut -d'"' -f2)
[ -n "$APP_VERSION" ] || fail "could not read version from alya.toml"

# --- local HTTP target ---
python3 -m http.server "$HTTP_PORT" --bind 0.0.0.0 --directory "$TMP/www" >"$HTTP_LOG" 2>&1 &
PIDS="$PIDS $!"
i=0
while [ "$i" -lt 20 ]; do
    i=$((i + 1))
    curl -sS --max-time 5 "http://127.0.0.1:$HTTP_PORT/ok.txt" 2>/dev/null | grep -q "$EXPECTED" && break
    sleep 1
done
curl -sS --max-time 5 "http://127.0.0.1:$HTTP_PORT/ok.txt" 2>/dev/null | grep -q "$EXPECTED" \
    || fail "local HTTP target did not come up"
echo "ok: local HTTP target serving on 0.0.0.0:$HTTP_PORT"

# --- VPN server (also exercises the documented config/server.toml) ---
"$BIN" server --bind 127.0.0.1 --port "$SRV_PORT" --pass "$PSK" \
    --block-lan false --health-port "$HEALTH_PORT" --log-level debug >"$SRV_LOG" 2>&1 &
PIDS="$PIDS $!"

HC=""
i=0
while [ "$i" -lt 30 ]; do
    i=$((i + 1))
    HC=$(curl -sS --max-time 5 "http://127.0.0.1:$HEALTH_PORT/healthz" 2>/dev/null) || true
    [ -n "$HC" ] && break
    sleep 1
done
echo "$HC" | grep -q '"status":"ok"' || fail "healthz did not come up"
echo "$HC" | grep -q "\"version\":\"$APP_VERSION\"" \
    || fail "healthz version != alya.toml ($APP_VERSION): $HC"
echo "ok: healthz reports version $APP_VERSION"

start_client() { # proxy port, mode, apps (may be empty), log file
    local extra=""
    if [ -n "${3:-}" ]; then extra="--apps $3"; fi
    # shellcheck disable=SC2086
    "$BIN" client --bind 127.0.0.1 --server 127.0.0.1 --port "$SRV_PORT" \
        --proxy "$1" --pass "$PSK" --mode "$2" $extra --bypass-lan false \
        --no-system-proxy --log-direct --log-level debug >"$4" 2>&1 &
    PIDS="$PIDS $!"
}

# --- phase ALL: every target tunnels ---
CLIENT_ALL="$TMP/client_all.log"
start_client "$PROXY_ALL" all "" "$CLIENT_ALL"
socks_fetch_ready "$PROXY_ALL" || fail "mode=all: tunneled fetch never succeeded"
grep -qE "\[TUNNEL\] \[curl.*-> $TIP:$HTTP_PORT" "$CLIENT_ALL" || fail "mode=all: no [TUNNEL] log line"
grep -qE "\[FORWARD\] Connected: Channel .* -> $TIP:$HTTP_PORT" "$SRV_LOG" || fail "mode=all: no server [FORWARD] line"
echo "ok: mode=all SOCKS5 fetch tunneled (client [TUNNEL] + server [FORWARD])"

# HTTP CONNECT on the same port
BEFORE=$(count_matches "$CLIENT_ALL" "\[TUNNEL\] \[curl.*-> $TIP:$HTTP_PORT")
BODY=$(curl -sS --max-time 15 --proxytunnel -x "http://127.0.0.1:$PROXY_ALL" "http://$TIP:$HTTP_PORT/ok.txt" 2>/dev/null) \
    || fail "HTTP CONNECT fetch failed"
[ "$BODY" = "$EXPECTED" ] || fail "HTTP CONNECT body mismatch: $BODY"
AFTER=$(count_matches "$CLIENT_ALL" "\[TUNNEL\] \[curl.*-> $TIP:$HTTP_PORT")
[ "${AFTER:-0}" -gt "${BEFORE:-0}" ] || fail "HTTP CONNECT did not tunnel (TUNNEL count $BEFORE -> $AFTER)"
echo "ok: HTTP CONNECT fetch tunneled"

# notcurl = curl copied under an unrecognized name (split-tunnel probe)
NOTCURL="$TMP/notcurl"
cp "$(command -v curl)" "$NOTCURL" || fail "could not copy curl for the split-tunnel probe"

# --- phase INCLUDE: only curl tunnels ---
CLIENT_INC="$TMP/client_inc.log"
start_client "$PROXY_INC" include "curl,curl.exe" "$CLIENT_INC"
socks_fetch_ready "$PROXY_INC" || fail "mode=include: proxy never came up"
"$NOTCURL" -sS --max-time 15 --socks5 "127.0.0.1:$PROXY_INC" "http://$TIP:$HTTP_PORT/ok.txt" >"$TMP/notcurl_inc.out" 2>/dev/null \
    || fail "mode=include: notcurl fetch failed"
[ "$(cat "$TMP/notcurl_inc.out")" = "$EXPECTED" ] || fail "mode=include: notcurl body mismatch"
grep -qE "\[DIRECT\] \[notcurl" "$CLIENT_INC" || fail "mode=include: notcurl was not DIRECT"
grep -qE "\[TUNNEL\] \[notcurl" "$CLIENT_INC" && fail "mode=include: notcurl was tunneled"
echo "ok: mode=include (curl tunnels, notcurl bypasses)"

# --- phase EXCLUDE: everything but curl tunnels ---
# Readiness must be probed with notcurl: real curl bypasses here, so it can
# come back 200 long before the tunnel to the server is up.
CLIENT_EXC="$TMP/client_exc.log"
start_client "$PROXY_EXC" exclude "curl,curl.exe" "$CLIENT_EXC"
probe_fetch_ready "$NOTCURL" "$PROXY_EXC" || fail "mode=exclude: tunnel never came up"
curl -sS --max-time 15 --socks5 "127.0.0.1:$PROXY_EXC" "http://$TIP:$HTTP_PORT/ok.txt" >"$TMP/curl_exc.out" 2>/dev/null \
    || fail "mode=exclude: curl fetch failed"
[ "$(cat "$TMP/curl_exc.out")" = "$EXPECTED" ] || fail "mode=exclude: curl body mismatch"
grep -qE "\[DIRECT\] \[curl" "$CLIENT_EXC" || fail "mode=exclude: curl was not DIRECT"
"$NOTCURL" -sS --max-time 15 --socks5 "127.0.0.1:$PROXY_EXC" "http://$TIP:$HTTP_PORT/ok.txt" >"$TMP/notcurl_exc.out" 2>/dev/null \
    || fail "mode=exclude: notcurl fetch failed"
[ "$(cat "$TMP/notcurl_exc.out")" = "$EXPECTED" ] || fail "mode=exclude: notcurl body mismatch"
grep -qE "\[TUNNEL\] \[notcurl.*-> $TIP:$HTTP_PORT" "$CLIENT_EXC" || fail "mode=exclude: notcurl was not tunneled"
echo "ok: mode=exclude (curl bypasses, notcurl tunnels)"

echo "SMOKE PASS: live tunnel, HTTP CONNECT, split-tunnel include/exclude verified"
exit 0
