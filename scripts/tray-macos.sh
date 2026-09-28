#!/usr/bin/env bash
# HBS Console menu-bar helper for macOS.
#
# macOS has no plain-shell tray API: the real menu-bar icon is provided by the
# optional HBS Console desktop app (Tauri 2). This script therefore:
#   1. opens the desktop app (with its menu-bar icon) when it is installed, or
#   2. falls back to the launcher/browser and tells you how to get the app.
#
#   hbs tray          keep the menu-bar icon available
#   hbs tray stop     no-op, kept for symmetry with the Linux helper
set -uo pipefail

HBS_HOME="${HBS_HOME:-$HOME/.hbs}"
BIN_DIR="$HOME/.local/bin"

hbs_bin() {
  if [[ -x "$BIN_DIR/hbs" ]]; then printf '%s' "$BIN_DIR/hbs"; else printf 'hbs'; fi
}

desktop_app() {
  for app in "$HOME/Applications/HBS Console.app" "/Applications/HBS Console.app"; do
    [[ -d "$app" ]] && { printf '%s' "$app"; return 0; }
  done
  return 1
}

if [[ "${1:-}" == "stop" ]]; then
  osascript -e 'tell application "HBS Console" to quit' >/dev/null 2>&1 || true
  exit 0
fi

if app="$(desktop_app)"; then
  "$(hbs_bin)" start >/dev/null 2>&1 || true
  open -a "$app"
  echo "HBS Console menu bar icon started (desktop app)."
  exit 0
fi

echo "The macOS menu-bar icon comes with the HBS Console desktop app."
echo "Install it (optional) with:"
echo "  hbs install-app"
"$(hbs_bin)" app >/dev/null 2>&1 || true
echo "Opened the dashboard instead."
