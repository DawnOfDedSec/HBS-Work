#!/usr/bin/env bash
# HBS Console tray for Linux (optional). Shows a notification-area icon with
# server controls via `yad` (sudo apt install yad / sudo dnf install yad).
#
# Start it from the desktop session (the installer adds an autostart entry) or
# run `hbs tray`. Without yad this prints the equivalent commands and exits.
set -uo pipefail

HBS_HOME="${HBS_HOME:-$HOME/.hbs}"
DATA_DIR="${HBS_DATA_DIR:-$HBS_HOME/data}"
ICON="${ICON:-}"
STATE="stopped"

port() {
  if [[ -f "$DATA_DIR/hbs.env" ]]; then
    local p; p="$(grep -E '^PORT=' "$DATA_DIR/hbs.env" | cut -d= -f2 | tr -d '[:space:]')"
    [[ -n "$p" ]] && { printf '%s' "$p"; return; }
  fi
  printf '%s' "${PORT:-3000}"
}

hbs() {
  if command -v hbs >/dev/null 2>&1; then hbs "$@"
  elif [[ -x "$HBS_HOME/installer/hbs" ]]; then "$HBS_HOME/installer/hbs" "$@"
  else "$HBS_HOME/app/scripts/hbs" "$@"; fi
}

# prefer the brand icon when the installer dropped one
for cand in "$HOME/.local/share/icons/hicolor/256x256/apps/hbs-console.png" \
            "$HBS_HOME/share/icon.png" \
            "$HBS_HOME/app/desktop/icons/icon.png"; do
  [[ -f "$cand" ]] && { ICON="--image=$cand"; break; }
done
[[ -z "$ICON" ]] && ICON="--image=network-server"

if ! command -v yad >/dev/null 2>&1; then
  echo "tray-linux: 'yad' is not installed - use the control commands instead:"
  echo "  hbs app | hbs open | hbs start | hbs stop | hbs restart | hbs status | hbs logs"
  echo "install yad (e.g. 'sudo apt install yad') and re-run 'hbs tray' for a real tray icon."
  exit 0
fi

# If the Tauri desktop app is installed it has its own tray: use it.
if command -v hbs-console >/dev/null 2>&1 || [[ -x "$HOME/.local/bin/HBS-Console.AppImage" ]]; then
  tray_bin="$(command -v hbs-console || printf '%s' "$HOME/.local/bin/HBS-Console.AppImage")"
  if [[ "${1:-}" == "stop" ]]; then pkill -f "$tray_bin" >/dev/null 2>&1 || true; exit 0; fi
  nohup "$tray_bin" >/dev/null 2>&1 &
  echo "HBS Console desktop app tray started."
  exit 0
fi

while true; do
  if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$(port)" 2>/dev/null; then STATE="running"; else STATE="stopped"; fi
  yad --notification "$ICON" --text="HBS Console ($STATE)" \
    --command="hbs app" \
    --menu="Open HBS Console!hbs app|\
Open in browser!hbs open|\
Start server!hbs start|\
Stop server!hbs stop|\
Restart server!hbs restart|\
View logs!hbs logs|\
Open data folder!xdg-open \"$DATA_DIR\"|\
Update HBS!hbs update|\
Quit!quit" 2>/dev/null
  rc=$?
  [[ $rc -ne 0 ]] && break
done
