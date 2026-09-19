#!/usr/bin/env bash
# Drives this library's state machine against the real ZTCS ground station
# over a real socket, with credentials minted for the run. Host only: it
# exercises secure_link.c itself, so what ships is what was tested.
#
# Needs libsodium, and a ZTCS checkout for the gateway and the CLI.
set -euo pipefail

SL=$(cd "$(dirname "$0")/.." && pwd)
ZTCS=${ZTCS_DIR:-$HOME/Code/ztcs}
WORK=$(mktemp -d)
GCS_PID=""
GW_PID=""

cleanup() {
  if [ -n "$GW_PID" ]; then kill "$GW_PID" 2>/dev/null || true; fi
  if [ -n "$GCS_PID" ]; then kill "$GCS_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

await() {
  local file=$1 pattern=$2
  for _ in $(seq 100); do
    if grep -qE "$pattern" "$file" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "timed out waiting for /$pattern/ in $file" >&2
  cat "$file" >&2
  return 1
}

[ -d "$ZTCS" ] || { echo "set ZTCS_DIR to a ZTCS checkout" >&2; exit 1; }

read -r -a SODIUM <<< "$(pkg-config --cflags --libs libsodium)"
gcc -O2 -Wall -Wextra -std=gnu99 -I"$SL" -o "$WORK/aircraft" \
  "$SL/secure_link.c" "$SL/noise/noise_ik.c" "$SL/noise/chacha20_ietf.c" \
  "$ZTCS/crates/ztcs-noise-udp/c/backend_sodium.c" \
  "$SL/test/secure_link_e2e.c" "${SODIUM[@]}"

cd "$ZTCS"
cargo build -q -p ztcs-cli -p ztcs-mavlink-gateway
CLI="$ZTCS/target/debug/ztcs"
GW="$ZTCS/target/debug/ztcs-mavlink-gateway"

"$CLI" keygen --out-seed "$WORK/operator.seed" --out-pubkey "$WORK/operator.pub" >/dev/null 2>&1

KEYS=$(cargo run -q -p ztcs-mavlink-gateway --example aircraft_keys)
PEER=$(awk '/^peer_id/{print $2}' <<<"$KEYS")
AIR_PRIV=$(awk '/^static_private/{print $2}' <<<"$KEYS")
IDENTITY=$(awk '/^identity_payload/{print $2}' <<<"$KEYS")
mkdir -p "$WORK/attest"
"$CLI" mint-attestation --seed "$WORK/operator.seed" --peer-id "$PEER" \
  --device-serial px4-e2e --protocol-family control \
  --out "$WORK/attest/$PEER.attest" >/dev/null 2>&1

python3 - > "$WORK/gcs.log" 2>&1 <<'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print("port", s.getsockname()[1], flush=True)
s.settimeout(30)
data, addr = s.recvfrom(2048)
print("uplink", data.decode(), flush=True)
s.sendto(b"COMMAND_ACK", addr)
PY
GCS_PID=$!
await "$WORK/gcs.log" '^port [0-9]+'
GCS_PORT=$(awk '/^port/{print $2}' "$WORK/gcs.log")

STATION=$("$GW" --static-key "$WORK/station.key" --operator-key "$WORK/operator.pub" \
  --attest-dir "$WORK/attest" --print-public-key 2>/dev/null)
"$GW" --listen 127.0.0.1:0 --gcs "127.0.0.1:$GCS_PORT" \
  --static-key "$WORK/station.key" --operator-key "$WORK/operator.pub" \
  --attest-dir "$WORK/attest" > "$WORK/gw.log" 2>&1 &
GW_PID=$!
await "$WORK/gw.log" 'secure MAVLink gateway up'
GW_PORT=$(grep -oE 'listen=127\.0\.0\.1:[0-9]+' "$WORK/gw.log" | head -1 | cut -d: -f2)

"$WORK/aircraft" 127.0.0.1 "$GW_PORT" "$AIR_PRIV" "$STATION" "$IDENTITY" \
  "HEARTBEAT" | tee "$WORK/air.log"

grep -q '^uplink HEARTBEAT$' "$WORK/gcs.log" \
  || { echo "the GCS never received the payload" >&2; exit 1; }
grep -q '^downlink COMMAND_ACK$' "$WORK/air.log" \
  || { echo "the aircraft never received the reply" >&2; exit 1; }

echo "e2e ok: PX4 state machine -> gateway -> GCS, both ways"
