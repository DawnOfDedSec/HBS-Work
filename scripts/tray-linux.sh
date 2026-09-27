#!/usr/bin/env bash
# HBS Console tray for Linux (optional). Shows a notification-area icon with
# server controls via `yad` when installed (sudo apt install yad).
# Without yad this prints the equivalent `hbs` commands and exits.
#
# Start it from the desktop session: ~/.config/autostart or manually.
set -uo pipefail

HBS_HOME="${HBS_HOME:-$HOME/.hbs}"
DATA_DIR="$HBS_HOME/data"
ICON_STATE="stopped"

port() {
  [[ -f "$DATA_DIR/hbs.env" ]] && grep -E '^PORT=' "$DATA_DIR/hbs.env" | cut -d= -f2 || echo 3000
}
menu() {
  yad --notification --image="network-server" --text="HBS Console ($ICON_STATE)" \
    --menu="Open Console!xdg-open http://127.0.0.1:$(port)!Start!hbs start!Stop!hbs stop!Restart!hbs restart!Logs!hbs logs!Update!hbs update!Quit!quit" \
    --command="xdg-open http://127.0.0.1:$(port)" 2>/dev/null
}

if ! command -v yad >/dev/null 2>&1; then
  echo "tray-linux: 'yad' is not installed - using plain control commands instead."
  echo "  hbs start | hbs stop | hbs restart | hbs status | hbs logs"
  echo "install yad (e.g. 'sudo apt install yad') and re-run for a real tray icon."
  exit 0
fi

while true; do
  if hbs status >/dev/null 2>&1 || systemctl --user is-active hbs >/dev/null 2>&1; then ICON_STATE="running"; else ICON_STATE="stopped"; fi
  menu
  action=$?
  [[ "$action" -ne 0 ]] && break
done
