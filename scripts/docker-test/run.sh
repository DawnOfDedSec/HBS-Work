#!/usr/bin/env bash
# REAL-WORLD validation: run the actual linux-x64 extractor binary
# inside real distro containers, root and non-root, and verify:
#   - exit code 0
#   - sealed report (.hbs) written with HBS1 magic
#   - no crash across the full catalog
# Usage: bash scripts/docker-test/run.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# zig discovery for cargo-zigbuild (PATH or python ziglang package)
if ! command -v zig >/dev/null 2>&1; then
  ZIGPKG="$(python -c 'import ziglang,os;print(os.path.dirname(ziglang.__file__))' 2>/dev/null || true)"
  ZIGPKG="$(cygpath -u "$ZIGPKG" 2>/dev/null || echo "$ZIGPKG")"
  [ -n "$ZIGPKG" ] && export PATH="$ZIGPKG:$PATH"
fi
BIN="$ROOT/extractor/target/x86_64-unknown-linux-musl/debug/hbs-extractor"
OUT="$ROOT/scripts/docker-test/out"
mkdir -p "$OUT"
RESULTS="$OUT/results.json"

# Always invoke cargo (incremental): guarantees the binary matches the
# current source instead of trusting a possibly-stale artifact.
(cd "$ROOT/extractor" && PATH="/c/Users/jonmori/.cargo/bin:$PATH" cargo zigbuild --target x86_64-unknown-linux-musl) || exit 1

DEVKEY="abababababababab""abababababababab""abababababababab""abababababababab"

# Windows-style host paths for Docker Desktop; MSYS_NO_PATHCONV stops
# Git-Bash from mangling the -v volume specs.
WIN_BIN=$(cygpath -w "$BIN" 2>/dev/null || echo "$BIN")
WIN_OUT=$(cygpath -w "$OUT" 2>/dev/null || echo "$OUT")

IMAGES=(ubuntu:24.04 debian:12 alpine:3.20 rockylinux:9)
PASS=0; FAIL=0

for img in "${IMAGES[@]}"; do
  for usermode in root nonroot; do
    tag=$(echo "${img}_${usermode}" | tr ':/' '__')
    echo "=== $img ($usermode) ==="
    if [ "$usermode" = "root" ]; then
      run_as=""
    else
      # non-root via su/su-exec/setpriv depending on distro toolbox
      run_as=""
    fi
    MSYS_NO_PATHCONV=1 docker run --rm \
      -v "$WIN_BIN":/hbs-extractor:ro \
      -v "$WIN_OUT":/out \
      --user "$([ "$usermode" = root ] && echo 0:0 || echo 1000:1000)" \
      "$img" \
      sh -c "cp /hbs-extractor /tmp/h 2>/dev/null; chmod +x /tmp/h; /tmp/h --no-pause --quiet --no-elevate --dev-insecure-key $DEVKEY --out /out/report-$tag.hbs; echo EXIT=\$? > /out/exit-$tag.txt; ls -la /out" 2>&1 | tail -5
    code=$(grep -o '[0-9]*' "$OUT/exit-$tag.txt" 2>/dev/null | head -1)
    if [ "$code" = "0" ] && [ -f "$OUT/report-$tag.hbs" ] && head -c 4 "$OUT/report-$tag.hbs" | grep -q "HBS1"; then
      size=$(stat -c %s "$OUT/report-$tag.hbs" 2>/dev/null)
      echo "PASS: $tag (report ${size}B)"
      PASS=$((PASS+1))
    else
      echo "FAIL: $tag (exit=$code)"
      FAIL=$((FAIL+1))
    fi
  done
done

echo "{\"pass\": $PASS, \"fail\": $FAIL}" > "$RESULTS"
echo "=== results: $PASS pass / $FAIL fail (saved to $RESULTS) ==="
[ "$FAIL" -eq 0 ]
