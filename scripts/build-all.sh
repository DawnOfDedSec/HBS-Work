#!/usr/bin/env bash
# Build the extractor for all required targets and publish to
# dashboard/binaries/ with a SHA-256 manifest. Fails if any binary
# reaches the 10 MB budget (spec §4.8).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dashboard/binaries"
BUDGET=$((10 * 1024 * 1024))

# cargo-zigbuild needs a zig: prefer one on PATH, else fall back to the
# `ziglang` Python package's bundled binary if importable.
if ! command -v zig >/dev/null 2>&1; then
  ZIGPKG="$(python -c 'import ziglang,os;print(os.path.dirname(ziglang.__file__))' 2>/dev/null || true)"
  # python prints a Windows-style path; convert for the bash PATH.
  ZIGPKG="$(cygpath -u "$ZIGPKG" 2>/dev/null || echo "$ZIGPKG")"
  if [ -n "$ZIGPKG" ] && [ -x "$ZIGPKG/zig.exe" -o -x "$ZIGPKG/zig" ]; then
    export PATH="$ZIGPKG:$PATH"
  fi
fi

mkdir -p "$OUT"
rm -f "$OUT"/manifest.json

MANIFEST='[]'

build() {
  local target="$1" name="$2"
  echo "==> building $target"
  if [[ "$target" == *windows* ]]; then
    (cd "$ROOT/extractor" && cargo build --release --target "$target")
  else
    (cd "$ROOT/extractor" && cargo zigbuild --release --target "$target")
  fi
  local src="$ROOT/extractor/target/$target/release/$name"
  local dest="$OUT/$target"
  mkdir -p "$dest"
  cp "$src" "$dest/$name"
  local size sha
  size=$(stat -c %s "$dest/$name" 2>/dev/null || stat -f %z "$dest/$name")
  sha=$(sha256sum "$dest/$name" | cut -d' ' -f1)
  if [ "$size" -ge "$BUDGET" ]; then
    echo "FATAL: $target binary is $size bytes (budget $BUDGET)" >&2
    exit 1
  fi
  echo "    $name  size=$size  sha256=$sha"
  MANIFEST=$(echo "$MANIFEST" | jq \
    --arg t "$target" --arg f "$name" --arg s "$sha" --argjson z "$size" \
    '. + [{target: $t, file: $f, sha256: $s, size: $z, built_at: (now | floor)}]')
}

build x86_64-unknown-linux-musl hbs-extractor
build aarch64-unknown-linux-musl hbs-extractor
build x86_64-pc-windows-msvc hbs-extractor.exe

echo "$MANIFEST" > "$OUT/manifest.json"
echo "==> manifest written to dashboard/binaries/manifest.json"
