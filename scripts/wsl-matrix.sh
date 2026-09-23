#!/usr/bin/env bash
# Run the static Linux extractor across local WSL2 distros — no Docker, no
# engine switching. Install distros once, e.g.:
#   wsl --list --online
#   wsl --install -d Ubuntu-24.04
#   wsl --install -d Debian
#
# Usage: bash scripts/wsl-matrix.sh [path-to-linux-musl-binary]
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/extractor/target/x86_64-unknown-linux-musl/debug/hbs-extractor}"
OUT="$ROOT/scripts/docker-test/out"
mkdir -p "$OUT"

if [ ! -f "$BIN" ]; then
  echo "missing $BIN — build it first:"
  echo "  (cd extractor && cargo zigbuild --target x86_64-unknown-linux-musl)"
  exit 2
fi

mapfile -t DISTROS < <(wsl.exe --list --quiet 2>/dev/null | tr -d '\r' | grep -v '^$' | grep -vi 'docker-desktop')
if [ "${#DISTROS[@]}" -eq 0 ]; then
  echo "no WSL distros found; install some with: wsl --install -d Ubuntu-24.04"
  exit 2
fi

DEVKEY="$(printf 'ab%.0s' {1..32})"
PASS=0; FAIL=0
for d in "${DISTROS[@]}"; do
  tag="$(echo "$d" | tr ' /:' '___')"
  report="$OUT/report-$tag.hbs"
  echo "=== WSL: $d ==="
  # Stream the binary into the distro, run a read-only scan (no push), then pull
  # the sealed report back out over stdout.
  wsl.exe -d "$d" -- bash -lc \
    "cat > /tmp/hbs && chmod +x /tmp/hbs && /tmp/hbs --no-elevate --no-pause --quiet --dev-insecure-key $DEVKEY --out /tmp/report.hbs" \
    < "$BIN" >/dev/null 2>&1
  run_code=$?
  wsl.exe -d "$d" -- bash -lc "cat /tmp/report.hbs" > "$report" 2>/dev/null

  if [ "$run_code" -eq 0 ] && [ -s "$report" ] && [ "$(head -c 4 "$report")" = "HBS2" ]; then
    echo "PASS: $d ($(wc -c < "$report")B)"
    PASS=$((PASS+1))
  else
    echo "FAIL: $d (exit=$run_code)"
    FAIL=$((FAIL+1))
  fi
done

echo "=== WSL matrix: $PASS pass / $FAIL fail (reports in $OUT) ==="
[ "$FAIL" -eq 0 ]
