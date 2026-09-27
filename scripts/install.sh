#!/usr/bin/env bash
# HBS Console installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/DawnOfDedSec/HBS-Work/main/scripts/install.sh | bash
#
# Installs or updates: Bun (runtime), the HBS repo (app), the `hbs` control
# CLI, and a background service (systemd user unit on Linux, LaunchAgent on
# macOS). Data lives separately from the app so updates never touch reports.
#
# Flags: --dir PATH | --port N | --no-start | --uninstall | --purge
set -euo pipefail

HBS_HOME="${HBS_HOME:-$HOME/.hbs}"
APP_DIR="$HBS_HOME/app"
DATA_DIR="$HBS_HOME/data"
BIN_DIR="$HOME/.local/bin"
REPO_URL="${HBS_REPO_URL:-https://github.com/DawnOfDedSec/HBS-Work.git}"
BRANCH="${HBS_BRANCH:-main}"
PORT="${HBS_PORT:-3000}"
SERVICE="hbs"
PLIST_LABEL="net.hbs.dashboard"
DO_START=1
UNINSTALL=0
PURGE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) APP_DIR="$2"; HBS_HOME="$(dirname "$APP_DIR")"; DATA_DIR="$(dirname "$APP_DIR")/data"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --no-start) DO_START=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; UNINSTALL=1; shift ;;
    -h|--help)
      echo "usage: install.sh [--dir PATH] [--port N] [--no-start] [--uninstall] [--purge]"
      exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m[hbs]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[hbs]\033[0m %s\n' "$*" >&2; exit 1; }

OS="$(uname -s)"
IS_LINUX=0; IS_MAC=0
[[ "$OS" == "Linux" ]] && IS_LINUX=1
[[ "$OS" == "Darwin" ]] && IS_MAC=1
{ [[ $IS_LINUX -eq 0 && $IS_MAC -eq 0 ]]; } && fail "unsupported OS: $OS (use scripts/install.ps1 on Windows)"

# --- uninstall ---------------------------------------------------------------
if [[ $UNINSTALL -eq 1 ]]; then
  log "stopping service…"
  if [[ $IS_LINUX -eq 1 ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl --user stop "$SERVICE" 2>/dev/null || true
    systemctl --user disable "$SERVICE" 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/$SERVICE.service"
    systemctl --user daemon-reload 2>/dev/null || true
  fi
  if [[ $IS_MAC -eq 1 ]]; then
    launchctl bootout "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/$PLIST_LABEL.plist"
  fi
  rm -f "$BIN_DIR/hbs"
  if [[ $PURGE -eq 1 ]]; then
    rm -rf "$HBS_HOME"
    log "removed $HBS_HOME (including data)"
  else
    rm -rf "$APP_DIR"
    log "removed the app; data kept at $DATA_DIR"
  fi
  log "uninstalled."
  exit 0
fi

# --- prerequisites -----------------------------------------------------------
command -v git >/dev/null 2>&1 || fail "git is required (install it, then re-run)"
if ! command -v bun >/dev/null 2>&1; then
  log "installing Bun runtime…"
  curl -fsSL https://bun.sh/install | bash
  export PATH="$HOME/.bun/bin:$PATH"
fi
command -v bun >/dev/null 2>&1 || fail "Bun installation failed — open a new shell and re-run"
mkdir -p "$APP_DIR" "$DATA_DIR" "$BIN_DIR"

# --- app: clone or update ----------------------------------------------------
if [[ -d "$APP_DIR/.git" ]]; then
  log "updating app…"
  git -C "$APP_DIR" fetch origin "$BRANCH" --quiet
  git -C "$APP_DIR" reset --hard "origin/$BRANCH" --quiet
else
  log "cloning HBS…"
  git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$APP_DIR" --quiet
fi

log "installing dependencies…"
(cd "$APP_DIR/dashboard" && bun install --quiet)

# --- env + CLI ---------------------------------------------------------------
if [[ ! -f "$DATA_DIR/hbs.env" ]]; then
  cat > "$DATA_DIR/hbs.env" <<EOF
PORT=$PORT
HBS_DATA_ROOT=$DATA_DIR
HBS_BOOTSTRAP_ADMIN=false
EOF
  log "wrote $DATA_DIR/hbs.env (edit PORT etc. there)"
fi

cat > "$BIN_DIR/hbs" <<EOF
#!/usr/bin/env bash
# HBS Console control CLI (installed by scripts/install.sh)
source "$DATA_DIR/hbs.env" 2>/dev/null || true
export HBS_DATA_ROOT="$DATA_DIR"
export PORT="\${PORT:-$PORT}"
exec "$APP_DIR/scripts/hbs" "\$@"
EOF
chmod +x "$BIN_DIR/hbs"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) log "note: add $BIN_DIR to your PATH to use 'hbs' from anywhere" ;; esac

# --- service -----------------------------------------------------------------
write_systemd() {
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/$SERVICE.service" <<EOF
[Unit]
Description=HBS Console
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR/dashboard
EnvironmentFile=$DATA_DIR/hbs.env
ExecStart=$(command -v bun) run server/index.ts
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
}

if [[ $IS_LINUX -eq 1 ]] && command -v systemctl >/dev/null 2>&1; then
  write_systemd
  if [[ $DO_START -eq 1 ]]; then
    systemctl --user enable --now "$SERVICE" 2>/dev/null || systemctl --user restart "$SERVICE"
  fi
  log "service: systemctl --user {status|restart|stop} $SERVICE"
elif [[ $IS_MAC -eq 1 ]]; then
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$HOME/Library/LaunchAgents/$PLIST_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$PLIST_LABEL</string>
  <key>WorkingDirectory</key><string>$APP_DIR/dashboard</string>
  <key>ProgramArguments</key><array>
    <string>$(command -v bun)</string><string>run</string><string>server/index.ts</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>HBS_DATA_ROOT</key><string>$DATA_DIR</string>
    <key>PORT</key><string>$PORT</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF
  launchctl bootout "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
  [[ $DO_START -eq 1 ]] && launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$PLIST_LABEL.plist"
  log "service: launchctl print gui/$(id -u)/$PLIST_LABEL"
fi

log "done. console: http://127.0.0.1:$PORT  (first run: create the admin account in the browser)"
