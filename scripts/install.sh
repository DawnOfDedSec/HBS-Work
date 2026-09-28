#!/usr/bin/env bash
# HBS Console installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.sh | bash
#
# Zero dependencies by design: everything ships as a prebuilt native binary in
# the project's latest GitHub release, so nothing but the shell built-ins you
# already have is needed - no Bun, no Node, no Rust, no compiler. The
# installer downloads the right asset for your OS and architecture, verifies
# its checksum, and wires the console into your system: Start-menu entry,
# desktop shortcut, tray icon, launch-at-login.
#
# Interactive runs open a short wizard (arrow keys / number keys). Piped runs
# (curl | bash) never prompt and install the recommended full setup; every
# choice also has a flag, so the same script runs unattended in CI.
#
# Options:
#   --mode full|dashboard|desktop   what to install
#                                   full:      console engine + tray + shortcuts
#                                              + desktop app  (recommended)
#                                   dashboard: engine + tray + shortcuts, no
#                                              desktop app
#                                   desktop:   engine + desktop app only; the
#                                              app owns the tray and shortcuts
#   --dir PATH            install root               (default: ~/.hbs)
#   --port N              dashboard port             (default: 3000)
#   --desktop-icon / --no-desktop-icon    desktop shortcut
#   --autostart / --no-autostart          start HBS at login
#   --tray / --no-tray                    tray icon (dashboard mode)
#   --desktop-app / --no-desktop-app      HBS Console desktop app
#   --expose              bind ALL interfaces (0.0.0.0) so the LAN can reach it
#   --host ADDR           bind one address (use --host alone for 0.0.0.0)
#   --local               loopback only, remove any previous exposure (default)
#   --tls-cert PATH       TLS certificate (with --tls-key)
#   --tls-key PATH        TLS private key
#   --tls                 enable HTTPS, self-signing a cert when none exists
#   -y, --yes             accept defaults, never prompt
#   --no-start            install but do not start anything
#   --tag vX.Y.Z          install a specific release   (default: latest)
#   --from-source         build from a git checkout instead (needs Bun)
#   --uninstall           remove the app (keep data)
#   --purge               remove the app AND all data
#   -h, --help            this help
#
# Env overrides: HBS_HOME, HBS_PORT, HBS_RELEASE_TAG, HBS_ASSET_BASE (local
# mirror or directory for testing), HBS_REPO_RAW, NO_COLOR.
set -uo pipefail

REPO="PotenFYR-Studios/HBS-Tool"
RELEASE_BASE="${HBS_RELEASE_URL:-https://github.com/$REPO/releases}"
RAW_BASE="${HBS_REPO_RAW:-https://raw.githubusercontent.com/$REPO/main}"

# ------------------------------------------------------------------ defaults
HBS_HOME="${HBS_HOME:-$HOME/.hbs}"
DATA_DIR="$HBS_HOME/data"
BIN_DIR="$HBS_HOME/bin"
INSTALLER_DIR="$HBS_HOME/installer"
LOCAL_BIN="$HOME/.local/bin"
DESKTOP_DIR="$HOME/Desktop"
PORT="${HBS_PORT:-3000}"
TAG="${HBS_RELEASE_TAG:-}"
ASSET_BASE="${HBS_ASSET_BASE:-}"
SERVICE="hbs"
PLIST_LABEL="net.hbs.dashboard"
BRANCH="${HBS_BRANCH:-main}"
REPO_URL="${HBS_REPO_URL:-https://github.com/$REPO.git}"

MODE=""            # "" = wizard, or full|dashboard|desktop
WANT_ICON=""       # desktop shortcut
WANT_AUTOSTART=""
WANT_TRAY=""
WANT_APP=""
ASSUME_YES=0
DO_START=1
UNINSTALL=0
PURGE=0
FROM_SOURCE=0
# Network exposure is opt-in and only rewritten when the user answers for it,
# so `hbs update` (install.sh --yes with no flags) never clobbers a configured
# LAN/TLS setup. NETWORK_SET becomes 1 once a flag or the wizard decides it.
HOST_ADDR="${HBS_HOST:-}"     # empty = loopback only
TLS_CERT="${HBS_TLS_CERT:-}"
TLS_KEY="${HBS_TLS_KEY:-}"
TLS_AUTO=0          # 1 = self-sign a certificate if none is provided
NETWORK_SET=0

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --dir) HBS_HOME="$2"; DATA_DIR="$HBS_HOME/data"; BIN_DIR="$HBS_HOME/bin"; INSTALLER_DIR="$HBS_HOME/installer"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --desktop-icon) WANT_ICON=1; shift ;;
    --no-desktop-icon) WANT_ICON=0; shift ;;
    --autostart) WANT_AUTOSTART=1; shift ;;
    --no-autostart) WANT_AUTOSTART=0; shift ;;
    --tray) WANT_TRAY=1; shift ;;
    --no-tray) WANT_TRAY=0; shift ;;
    --desktop-app) WANT_APP=1; shift ;;
    --no-desktop-app) WANT_APP=0; shift ;;
    --expose) HOST_ADDR=0.0.0.0; NETWORK_SET=1; shift ;;
    --host) HOST_ADDR="${2:-0.0.0.0}"; [[ "$HOST_ADDR" == --* ]] && HOST_ADDR=0.0.0.0; NETWORK_SET=1; shift; [[ "${1:-}" != --* ]] && shift ;;
    --local|--no-expose) HOST_ADDR=""; TLS_CERT=""; TLS_KEY=""; NETWORK_SET=1; shift ;;
    --tls-cert) TLS_CERT="$2"; NETWORK_SET=1; shift 2 ;;
    --tls-key) TLS_KEY="$2"; NETWORK_SET=1; shift 2 ;;
    --tls) TLS_CERT="${TLS_CERT:-}"; TLS_AUTO=1; NETWORK_SET=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --no-start) DO_START=0; shift ;;
    --tag) TAG="$2"; shift 2 ;;
    --from-source) FROM_SOURCE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown flag: %s (try --help)\n' "$1" >&2; exit 2 ;;
  esac
done
case "$MODE" in ""|full|dashboard|desktop) ;; *) printf 'invalid --mode: %s (full|dashboard|desktop)\n' "$MODE" >&2; exit 2 ;; esac

# ------------------------------------------------------------------- styling
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
  B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'
  V=$'\033[38;5;141m'; P=$'\033[38;5;205m'; O=$'\033[38;5;209m'
  G=$'\033[38;5;114m'; Y=$'\033[38;5;221m'; E=$'\033[38;5;203m'; C=$'\033[38;5;117m'
  UP=$'\033[1A'; CLR=$'\033[K'
else
  B=""; D=""; R=""; V=""; P=""; O=""; G=""; Y=""; E=""; C=""; UP=""; CLR=""
fi

INTERACTIVE=0
{ [[ -t 0 ]] || [[ -r /dev/tty ]]; } && [[ -t 1 ]] && INTERACTIVE=1
[[ $ASSUME_YES -eq 1 ]] && INTERACTIVE=0

banner() {
  printf '\n'
  printf '  %s%s██████╗ ███████╗ ██████╗%s\n' "$B" "$V" "$R"
  printf '  %s%s╚════██╗██╔════╝██╔════╝%s  %sHBS%s %s· host baseline security reviews%s\n' "$B" "$P" "$R" "$B" "$R" "$D" "$R"
  printf '  %s%s █████╔╝███████╗╚█████╗ %s  %sread-only scans · sealed reports%s\n' "$B" "$P" "$R" "$D" "$R"
  printf '  %s%s ╚═══██╗╚════██║ ╚═══██╗%s\n' "$B" "$O" "$R"
  printf '  %s%s██████╔╝███████║██████╔╝%s  %sinstaller%s\n' "$B" "$O" "$R" "$D" "$R"
  printf '  %s%s╚═════╝ ╚══════╝╚═════╝ %s\n\n' "$B" "$O" "$R"
}

step()  { printf '  %s▸%s %s\n' "$C" "$R" "$*"; }
ok()    { printf '  %s✔%s %s\n' "$G" "$R" "$*"; }
warn()  { printf '  %s!%s %s\n' "$Y" "$R" "$*"; }
die()   { printf '\n  %s✖ %s%s\n\n' "$E" "$*" "$R" >&2; exit 1; }
note()  { printf '    %s%s%s\n' "$D" "$*" "$R"; }
blank() { printf '\n'; }

# Spinner for steps whose duration is unknown. Usage: spin "label" cmd...
spin() {
  local label="$1"; shift
  if [[ $INTERACTIVE -eq 0 ]]; then step "$label"; "$@"; return $?; fi
  local chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" i=0
  "$@" & local pid=$!
  printf '  %s%s%s %s%s%s' "$C" "${chars:0:1}" "$R" "$B" "$label" "$R"
  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i + 1) % 10 ))
    printf '\r  %s%s%s %s%s%s' "$C" "${chars:$i:1}" "$R" "$B" "$label" "$R"
    sleep 0.08
  done
  wait "$pid"; local rc=$?
  if [[ $rc -eq 0 ]]; then printf '\r  %s✔%s %s%s%s\n' "$G" "$R" "$B" "$label" "$R"
  else printf '\r  %s✖%s %s%s%s\n' "$E" "$R" "$B" "$label" "$R"; fi
  return $rc
}

# Prompt on the real terminal even when the script arrives through a pipe.
ask() {
  local q="$1" def="${2:-}" ans=""
  if [[ $INTERACTIVE -eq 0 ]]; then printf '%s' "$def"; return 0; fi
  printf '  %s?%s %s%s%s ' "$P" "$R" "$B" "$q" "$R"
  [[ -n "$def" ]] && printf '%s[%s]%s ' "$D" "$def" "$R"
  if [[ -t 0 ]]; then read -r ans || true; else read -r ans < /dev/tty || true; fi
  printf '%s' "${ans:-$def}"
}

ask_yn() {
  local q="$1" def="${2:-y}" ans
  ans="$(ask "$q (y/n)" "$def")"
  case "${ans:0:1}" in [Yy]) return 0 ;; [Nn]) return 1 ;; *) [[ "$def" == "y" ]] ;; esac
}

# Arrow-key menu (number keys work too). Usage: choose <prompt> [options...]
# Echoes the 1-based choice. Falls back to the first option when piped.
choose() {
  local prompt="$1"; shift
  local opts=("$@") n=$# sel=1 i key redraw=0
  if [[ $INTERACTIVE -eq 0 ]]; then printf '1'; return 0; fi
  draw() {
    ((redraw)) && printf '%s' "$(printf '\033[%dA' "$((n + 1))")"
    printf '  %s?%s %s%s%s%s\n' "$P" "$R" "$B" "$prompt" "$R" "$CLR"
    for ((i = 0; i < n; i++)); do
      if ((i + 1 == sel)); then printf '  %s❯ %s%s%s%s\n' "$P" "$B" "${opts[$i]}" "$R" "$CLR"
      else printf '    %s%s%s%s\n' "$D" "${opts[$i]}" "$R" "$CLR"; fi
    done
    redraw=1
  }
  [[ -t 0 ]] && exec 3<&0 || exec 3</dev/tty
  draw
  while true; do
    IFS= read -rsn1 key <&3 || break
    case "$key" in
      $'\x1b') read -rsn2 -t 0.1 rest <&3 || true
        case "$rest" in
          '[A') ((sel > 1)) && ((sel--));; '[B') ((sel < n)) && ((sel++));;
        esac ;;
      $'\n'|$'\r') break ;;
      [1-9]) ((key <= n)) && { sel=$key; break; } ;;
    esac
    draw
  done
  exec 3<&-
  printf '%s' "$sel"
}

# --------------------------------------------------------------- environment
command_exists() { command -v "$1" >/dev/null 2>&1; }

fetch() {
  # fetch <url> <outfile> - curl first, wget as the fallback.
  local url="$1" out="$2"
  if command_exists curl; then curl -fsSL --retry 2 -o "$out" "$url"
  elif command_exists wget; then wget -q -O "$out" "$url"
  else return 127; fi
}

hash_file() {
  # sha256 of a file, whatever coreutils the host has.
  if command_exists sha256sum; then sha256sum "$1" | cut -d' ' -f1
  elif command_exists shasum; then shasum -a 256 "$1" | cut -d' ' -f1
  else return 127; fi
}

# Set/replace or remove a single KEY= line in the data/hbs.env file. Used so
# re-running the installer can turn LAN exposure or TLS on or off, instead of
# only writing the file on the very first install.
env_set() {
  local key="$1" val="$2" f="$DATA_DIR/hbs.env" tmp
  [[ -f "$f" ]] || : > "$f"
  tmp="$(mktemp 2>/dev/null || mktemp -t hbs-env)"
  grep -vE "^${key}=" "$f" > "$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$f"
}
env_unset() {
  local key="$1" f="$DATA_DIR/hbs.env" tmp
  [[ -f "$f" ]] || return 0
  tmp="$(mktemp 2>/dev/null || mktemp -t hbs-env)"
  grep -vE "^${key}=" "$f" > "$tmp" 2>/dev/null || true
  mv "$tmp" "$f"
}

# Apply this run's network decision to hbs.env. Only called when the user (or
# a flag) actually chose, so unattended updates leave the file untouched.
apply_network_env() {
  if [[ -n "$HOST_ADDR" ]]; then env_set HOST "$HOST_ADDR"; else env_unset HOST; fi
  if [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]]; then
    env_set HBS_TLS_CERT "$TLS_CERT"
    env_set HBS_TLS_KEY "$TLS_KEY"
  else
    env_unset HBS_TLS_CERT
    env_unset HBS_TLS_KEY
  fi
}

# http/https scheme and the address the console is reachable on for status and
# health checks (0.0.0.0 is not dialable, so probe loopback for it).
console_scheme() { [[ -n "$TLS_CERT" ]] && printf 'https' || printf 'http'; }
console_host() {
  case "${HOST_ADDR:-}" in ""|0.0.0.0|"::"|"*") printf '127.0.0.1' ;; *) printf '%s' "$HOST_ADDR" ;; esac
}
probe_url()  { printf '%s://%s:%s' "$(console_scheme)" "$(console_host)" "$PORT"; }
probe() {
  local url; url="$(probe_url)"
  if command_exists curl; then
    [[ "$(console_scheme)" == https ]] && curl -fsSk -o /dev/null --max-time 2 "$url" 2>/dev/null \
      || curl -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null
  else
    wget -q -O /dev/null -T 2 "$url" 2>/dev/null
  fi
}

OS="$(uname -s)"
ARCH="$(uname -m)"
IS_LINUX=0; IS_MAC=0
[[ "$OS" == "Linux" ]] && IS_LINUX=1
[[ "$OS" == "Darwin" ]] && IS_MAC=1
{ [[ $IS_LINUX -eq 0 && $IS_MAC -eq 0 ]]; } && die "unsupported OS: $OS (on Windows use scripts/install.ps1)"

has_gui() {
  [[ "$(uname -s)" == "Darwin" ]] && return 0
  [[ -n "${WAYLAND_DISPLAY:-}" || -n "${DISPLAY:-}" ]] && return 0
  return 1
}

# musl or glibc - selects which Linux server binary to fetch.
is_musl() {
  command_exists ldd || { command_exists apk && return 0; return 1; }
  ldd --version 2>&1 | grep -q musl
}

server_target() {
  # Release asset target triple for this machine; empty = unsupported.
  local t=""
  case "$OS/$ARCH" in
    Linux/x86_64)  t="bun-linux-x64";  is_musl && t="bun-linux-x64-musl" ;;
    Linux/arm64|Linux/aarch64) t="bun-linux-arm64"; is_musl && t="bun-linux-arm64-musl" ;;
    Darwin/x86_64) t="bun-darwin-x64" ;;
    Darwin/arm64)  t="bun-darwin-arm64" ;;
  esac
  printf '%s' "$t"
}

# --------------------------------------------------------------- uninstall
remove_integration() {
  if [[ $IS_LINUX -eq 1 ]] && command_exists systemctl; then
    systemctl --user stop "$SERVICE" 2>/dev/null || true
    systemctl --user disable "$SERVICE" 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/$SERVICE.service"
    systemctl --user daemon-reload 2>/dev/null || true
  fi
  if [[ $IS_MAC -eq 1 ]]; then
    launchctl bootout "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/$PLIST_LABEL.plist"
  fi
  if [[ -f "$DATA_DIR/server.pid" ]]; then
    kill "$(cat "$DATA_DIR/server.pid")" 2>/dev/null || true
    rm -f "$DATA_DIR/server.pid"
  fi
  pkill -f "bin/hbs-server" 2>/dev/null || true
  # Desktop app (if installed) + its entries.
  if [[ -f "$INSTALLER_DIR/install-desktop.sh" ]]; then
    bash "$INSTALLER_DIR/install-desktop.sh" --uninstall >/dev/null 2>&1 || true
  elif [[ -f "$HBS_HOME/app/scripts/install-desktop.sh" ]]; then
    bash "$HBS_HOME/app/scripts/install-desktop.sh" --uninstall >/dev/null 2>&1 || true
  fi
  rm -f "$HOME/.local/share/applications/hbs-console.desktop"
  rm -f "$HOME/.config/autostart/hbs-console.desktop"
  rm -f "$DESKTOP_DIR/hbs-console.desktop"
  rm -rf "$HOME/Applications/HBS Console.app" "/Applications/HBS Console.app"
  rm -f "$DESKTOP_DIR/HBS Console.app"
  rm -f "$HOME/.local/share/icons/hicolor/256x256/apps/hbs-console.png"
  rm -f "$LOCAL_BIN/hbs"
}

if [[ $UNINSTALL -eq 1 ]]; then
  banner
  step "Removing HBS Console…"
  remove_integration
  if [[ $PURGE -eq 1 ]]; then
    rm -rf "$HBS_HOME"
    ok "removed $HBS_HOME (app and data)"
  else
    rm -rf "$BIN_DIR" "$INSTALLER_DIR" "$HBS_HOME/app"
    ok "removed the app; your reports and database stay in $DATA_DIR"
    note "re-run with --purge to delete the data too"
  fi
  blank; ok "HBS Console uninstalled. Thanks for using HBS."; blank
  exit 0
fi

# ------------------------------------------------------------ release assets
MANIFEST=""
VERSION=""

resolve_tag() {
  [[ -n "$TAG" ]] && return 0
  # The releases/latest redirect carries the tag - no API, no rate limit.
  local loc
  if command_exists curl; then
    loc="$(curl -fsSI -o /dev/null -w '%{redirect_url}' "$RELEASE_BASE/latest" 2>/dev/null || true)"
  else
    loc="$(wget --max-redirect=0 -S "$RELEASE_BASE/latest" 2>&1 | grep -i '^  *Location:' | tr -d '\r' | awk '{print $2}' || true)"
  fi
  TAG="${loc##*/}"
  [[ "$TAG" == latest || -z "$TAG" ]] && die "could not resolve the latest release tag (offline? set --tag)"
}

load_manifest() {
  # manifest.json ships with every release: exact names, sizes and sha256s.
  local tmp
  tmp="$(mktemp 2>/dev/null || mktemp -t hbs-manifest)"
  if [[ -n "$ASSET_BASE" && -d "$ASSET_BASE" ]]; then
    cp "$ASSET_BASE/manifest.json" "$tmp" || die "could not read $ASSET_BASE/manifest.json"
  elif [[ -n "$ASSET_BASE" ]]; then
    fetch "$ASSET_BASE/manifest.json" "$tmp" || die "could not read $ASSET_BASE/manifest.json"
  else
    fetch "$RELEASE_BASE/download/$TAG/manifest.json" "$tmp" || die "could not read the release manifest (offline? set --tag)"
  fi
  MANIFEST="$tmp"
  VERSION="$(grep -m1 '"version"' "$MANIFEST" | cut -d'"' -f4)"
  [[ -n "$VERSION" ]] || die "release manifest is malformed"
}

manifest_sha() {
  grep -F "\"name\": \"$1\"," -A2 "$MANIFEST" 2>/dev/null \
    | grep -o '"sha256": "[a-f0-9]*"' | head -1 | cut -d'"' -f4
}

asset_url() {
  if [[ -n "$ASSET_BASE" ]]; then printf '%s/%s' "$ASSET_BASE" "$1"
  else printf '%s/download/%s/%s' "$RELEASE_BASE" "$TAG" "$1"; fi
}

fetch_asset() {
  # fetch_asset <asset-name> <outfile> - direct copy from a local mirror.
  if [[ -n "$ASSET_BASE" && -d "$ASSET_BASE" ]]; then
    cp "$ASSET_BASE/$1" "$2"
  else
    fetch "$(asset_url "$1")" "$2"
  fi
}

# ------------------------------------------------------------- wizard + plan
banner
if [[ $INTERACTIVE -eq 1 && -z "$MODE" ]]; then
  printf '  %s%sWelcome! Let%s get HBS on your machine.%s\n' "$B" "$V" "'" "$R"
  note "Everything ships prebuilt - nothing to compile, nothing to install first."
  blank
  sel="$(choose "What do you want to install?" \
    "Full install - everything (recommended)" \
    "Dashboard only - web console + tray" \
    "Desktop app only - the native app (includes the engine)")"
  case "$sel" in
    1) MODE=full ;;
    2) MODE=dashboard ;;
    3) MODE=desktop ;;
  esac
fi
[[ -z "$MODE" ]] && MODE=full

# Per-mode defaults; explicit flags always win.
case "$MODE" in
  full)      : "${WANT_AUTOSTART:=1}"; : "${WANT_TRAY:=1}";     : "${WANT_APP:=1}"; : "${WANT_ICON:=1}" ;;
  dashboard) : "${WANT_AUTOSTART:=1}"; : "${WANT_TRAY:=1}";     : "${WANT_APP:=0}"; : "${WANT_ICON:=1}" ;;
  desktop)   : "${WANT_AUTOSTART:=1}"; : "${WANT_TRAY:=0}";     : "${WANT_APP:=1}"; : "${WANT_ICON:=0}" ;;
esac

if [[ $INTERACTIVE -eq 1 ]]; then
  blank
  printf '  %s%sCustomize%s  %s(Enter accepts the suggested value)%s\n\n' "$B" "$V" "$R" "$D" "$R"
  HBS_HOME="$(ask 'Install location' "$HBS_HOME")"
  DATA_DIR="$HBS_HOME/data"; BIN_DIR="$HBS_HOME/bin"; INSTALLER_DIR="$HBS_HOME/installer"
  PORT="$(ask 'Dashboard port' "$PORT")"
  # Network hosting is optional and off by default: the console is local-only
  # unless the operator opts in. --expose/--host/--tls skip these prompts.
  if [[ -n "$HOST_ADDR" ]]; then
    NETWORK_SET=1
  elif ask_yn 'Publish the dashboard on your local network?' n; then
    NETWORK_SET=1
    HOST_ADDR="$(ask 'Bind address (0.0.0.0 = every interface)' '0.0.0.0')"
  fi
  if [[ -n "$HOST_ADDR" || "$TLS_AUTO" -eq 1 ]]; then
    if [[ -n "$TLS_CERT" ]]; then
      :
    elif [[ "$TLS_AUTO" -eq 1 ]] || ask_yn 'Serve HTTPS with TLS? (recommended on an untrusted network)' n; then
      TLS_AUTO=1
      TLS_CERT="$(ask 'TLS certificate path' "$DATA_DIR/tls/hbs.crt")"
      TLS_KEY="$(ask 'TLS private key path' "$DATA_DIR/tls/hbs.key")"
    fi
  fi
  if has_gui; then
    ask_yn 'Create a desktop shortcut?' "$([[ $WANT_ICON -eq 1 ]] && echo y || echo n)" && WANT_ICON=1 || WANT_ICON=0
    [[ $MODE != desktop ]] && { ask_yn 'Install the tray icon?' "$([[ $WANT_TRAY -eq 1 ]] && echo y || echo n)" && WANT_TRAY=1 || WANT_TRAY=0; }
    [[ $MODE != dashboard ]] || { ask_yn 'Install the HBS Console desktop app too?' "$([[ $WANT_APP -eq 1 ]] && echo y || echo n)" && WANT_APP=1 || WANT_APP=0; }
    ask_yn 'Start HBS automatically when you sign in?' "$([[ $WANT_AUTOSTART -eq 1 ]] && echo y || echo n)" && WANT_AUTOSTART=1 || WANT_AUTOSTART=0
  else
    WANT_ICON=0; WANT_TRAY=0; WANT_APP=$([[ $MODE == full || $MODE == desktop ]] && echo 1 || echo 0)
    note "no desktop session - tray and shortcuts stay off; the web console still works"
  fi
fi
: "${WANT_ICON:=0}"; : "${WANT_AUTOSTART:=0}"; : "${WANT_TRAY:=0}"; : "${WANT_APP:=0}"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "port must be a number, got: $PORT"

# --------------------------------------------------------------- network/TLS
# `--tls` with no path self-signs under the data dir; anything else is used
# as-is. Both a certificate and a key are required together.
if [[ "$TLS_AUTO" -eq 1 && -z "$TLS_CERT" ]]; then
  TLS_CERT="$DATA_DIR/tls/hbs.crt"
  TLS_KEY="$DATA_DIR/tls/hbs.key"
fi
if [[ -n "$TLS_CERT" || -n "$TLS_KEY" ]]; then
  [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]] || die "TLS needs both a certificate and a key (--tls-cert and --tls-key)"
  if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
    command_exists openssl || die "certificate $TLS_CERT not found and openssl is unavailable - pass existing --tls-cert/--tls-key paths"
    step "Generating a self-signed TLS certificate…"
    mkdir -p "$(dirname "$TLS_CERT")" "$(dirname "$TLS_KEY")"
    SAN="DNS:localhost,IP:127.0.0.1"
    _ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [[ -n "$_ip" ]] && SAN="$SAN,IP:$_ip"
    _hn="$(hostname 2>/dev/null || true)"
    [[ -n "$_hn" ]] && SAN="$SAN,DNS:$_hn"
    if openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 \
        -keyout "$TLS_KEY" -out "$TLS_CERT" -subj "/CN=hbs-console" \
        -addext "subjectAltName=$SAN" >/dev/null 2>&1; then
      chmod 600 "$TLS_KEY" 2>/dev/null || true
      ok "Self-signed certificate: $TLS_CERT"
      note "Browsers warn until it is trusted; LAN traffic is still encrypted."
    else
      die "could not generate a certificate at $TLS_CERT"
    fi
  fi
fi

blank
step "Checking your system…"
command_exists curl || command_exists wget || die "curl or wget is required to download the release (install one, then re-run)"
hash_file /dev/null >/dev/null 2>&1 || die "sha256sum or shasum is required (install one, then re-run)"
command_exists gunzip || die "gunzip is required to unpack the release (install gzip, then re-run)"
if [[ $IS_LINUX -eq 1 ]]; then
  # shellcheck disable=SC1091
  DISTRO="$( . /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-Linux}" )"
else
  DISTRO="macOS $(sw_vers -productVersion 2>/dev/null || echo)"
fi
ok "$DISTRO · $ARCH"
[[ $MODE != desktop ]] && { if has_gui; then ok "Desktop session detected"; else warn "No desktop session detected - tray and shortcuts stay off, the web console still works"; fi; }
TARGET="$(server_target)"
[[ -z "$TARGET" ]] && die "no prebuilt server for $OS/$ARCH yet - 'hbs' from source is the fallback (see the README)"
ok "Release channel: $([[ -n "$TAG" ]] && printf '%s' "$TAG" || printf 'latest') · $TARGET"

blank
step "Installing into $HBS_HOME (port $PORT)"
blank

# -------------------------------------------------------------- the engine
TARGET="$TARGET"
if [[ $FROM_SOURCE -eq 1 ]]; then
  step "Preparing a source build (this needs Bun)…"
  command_exists git || die "git is required for --from-source"
  command_exists bun || die "Bun is required for --from-source (https://bun.sh)"
  APP_DIR="$HBS_HOME/app"
  mkdir -p "$APP_DIR"
  if [[ -d "$APP_DIR/.git" ]]; then
    git -C "$APP_DIR" fetch origin "$BRANCH" --quiet && git -C "$APP_DIR" reset --hard "origin/$BRANCH" --quiet
  else
    git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$APP_DIR" --quiet || die "clone failed"
  fi
  (cd "$APP_DIR/dashboard" && bun install --quiet && bun run build) || die "source build failed"
  mkdir -p "$BIN_DIR"
  (cd "$APP_DIR/dashboard" && bun build --compile --minify --sourcemap=none server/index.ts --outfile "$BIN_DIR/hbs-server") || die "server compile failed"
else
  if [[ -n "$ASSET_BASE" ]]; then
    TAG="local"   # asset mirror: the tag is cosmetic
    spin "Reading the manifest…" load_manifest
  else
    spin "Resolving the release…" resolve_tag
    spin "Reading the manifest…" load_manifest
  fi
  ASSET="hbs-server-$VERSION-$TARGET.gz"
  SHA="$(manifest_sha "$ASSET")"
  [[ -z "$SHA" ]] && die "release $TAG has no $ASSET - try --from-source"
  TMP="$(mktemp -d 2>/dev/null || mktemp -d -t hbs-install)"
  trap 'rm -rf "$TMP"' EXIT
  SIZE_BYTES="$(grep -F "\"name\": \"$ASSET\"," -A3 "$MANIFEST" | grep -o '"bytes": [0-9]*' | cut -d' ' -f2)"
  SIZE_MB="$(( ${SIZE_BYTES:-0} / 1048576 ))"
  step "Downloading the console engine (${SIZE_MB} MB)…"
  fetch_asset "$ASSET" "$TMP/server.gz" || die "download failed"
  echo ""
  [[ "$(hash_file "$TMP/server.gz")" == "$SHA" ]] || die "checksum mismatch - download corrupted; re-run the installer"
  ok "Checksum verified"
  mkdir -p "$BIN_DIR"
  gunzip -c "$TMP/server.gz" > "$BIN_DIR/hbs-server" && chmod +x "$BIN_DIR/hbs-server" || die "could not unpack the engine"
fi
ok "Console engine: $BIN_DIR/hbs-server"

# --------------------------------------------------------------- data + CLI
mkdir -p "$DATA_DIR" "$INSTALLER_DIR"

if [[ ! -f "$DATA_DIR/hbs.env" ]]; then
  {
    printf '# HBS Console environment (edit to change the port etc.)\n'
    printf 'PORT=%s\n' "$PORT"
    printf 'HBS_DATA_ROOT=%s\n' "$DATA_DIR"
    printf '# First launch opens the console setup wizard, where you choose the\n'
    printf '# administrator account. Set HBS_BOOTSTRAP_ADMIN=true here (with\n'
    printf '# HBS_ADMIN_USERNAME / HBS_ADMIN_PASSWORD) for unattended installs.\n'
  } > "$DATA_DIR/hbs.env"
  ok "Wrote $DATA_DIR/hbs.env (edit it to change the port)"
  FIRST_RUN=1
else
  ok "Keeping existing $DATA_DIR/hbs.env"
  FIRST_RUN=0
fi

# Persist this run's hosting choice (only when the operator actually chose).
if [[ $NETWORK_SET -eq 1 ]]; then
  apply_network_env
  if [[ -n "$HOST_ADDR" ]]; then
    ok "Dashboard listens on ${HOST_ADDR}:$PORT${TLS_CERT:+ over HTTPS}"
  else
    ok "Dashboard is loopback-only (127.0.0.1)"
  fi
fi

# Keep copies of the installer + companion scripts so `hbs update` and
# `hbs uninstall` work with no repo clone: sibling files when run from a
# checkout, the project's raw URLs when piped.
stage_script() {
  local name="$1" src_dir=""
  if [[ -f "$0" && "$0" != /dev/fd/* ]]; then
    src_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || src_dir=""
  fi
  if [[ -n "$src_dir" && -f "$src_dir/$name" ]]; then
    cp "$src_dir/$name" "$INSTALLER_DIR/$name" && chmod +x "$INSTALLER_DIR/$name" && return 0
  fi
  if [[ -n "$ASSET_BASE" && -f "$ASSET_BASE/$name" ]]; then
    cp "$ASSET_BASE/$name" "$INSTALLER_DIR/$name" && chmod +x "$INSTALLER_DIR/$name" && return 0
  fi
  if fetch "$RAW_BASE/scripts/$name" "$INSTALLER_DIR/$name" 2>/dev/null; then
    chmod +x "$INSTALLER_DIR/$name" && return 0
  fi
  if [[ -f "$HBS_HOME/app/scripts/$name" ]]; then
    cp "$HBS_HOME/app/scripts/$name" "$INSTALLER_DIR/$name" && chmod +x "$INSTALLER_DIR/$name" && return 0
  fi
  return 1
}

stage_script install.sh || warn "could not stage install.sh - 'hbs update' will need the repo"
stage_script install-desktop.sh || true
stage_script hbs || true
stage_script tray-linux.sh || true
stage_script tray-macos.sh || true

# The control CLI: thin, dependency-free, points at this install.
{
  printf '#!/usr/bin/env bash\n'
  printf '# HBS Console control CLI (installed by scripts/install.sh)\n'
  printf 'HBS_HOME="%s"\n' "$HBS_HOME"
  printf 'export HBS_DATA_ROOT="%s"\n' "$DATA_DIR"
  printf 'export PORT="${PORT:-%s}"\n' "$PORT"
  printf 'exec "%s/hbs" "$@"\n' "$INSTALLER_DIR"
} > "$LOCAL_BIN/hbs"
chmod +x "$LOCAL_BIN/hbs"

# PATH: ~/.local/bin must be usable from a fresh terminal. Cover bash, zsh
# and fish; skip every file we already configured.
case ":$PATH:" in *":$LOCAL_BIN:"*) PATH_OK=1 ;; *) PATH_OK=0 ;; esac
if [[ $PATH_OK -eq 0 ]]; then
  add_path_line() {
    local rc="$1" line="$2"
    [[ -f "$rc" ]] || touch "$rc"
    grep -qsF "$line" "$rc" && return 0
    { echo ""; echo "# Added by the HBS Console installer"; echo "$line"; } >> "$rc"
  }
  case "$(basename "${SHELL:-/bin/sh}")" in
    fish) add_path_line "$HOME/.config/fish/config.fish" "fish_add_path $LOCAL_BIN" ;;
    zsh)  add_path_line "$HOME/.zshrc" "export PATH=\"$LOCAL_BIN:\$PATH\"" ;;
    *)    add_path_line "$HOME/.bashrc" "export PATH=\"$LOCAL_BIN:\$PATH\"" ;;
  esac
  ok "Added $LOCAL_BIN to your PATH (new terminals)"
else
  ok "hbs CLI installed: $LOCAL_BIN/hbs"
fi
[[ $PATH_OK -eq 1 ]] && ok "hbs CLI installed: $LOCAL_BIN/hbs"

# ------------------------------------------------------------------ service
SERVICE_INSTALLED=0
if [[ $IS_LINUX -eq 1 ]] && command_exists systemctl && systemctl --user status >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/$SERVICE.service" <<EOF
[Unit]
Description=HBS Console
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$DATA_DIR
EnvironmentFile=$DATA_DIR/hbs.env
ExecStart=$BIN_DIR/hbs-server
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  SERVICE_INSTALLED=1
  ok "systemd user service: systemctl --user {start|stop|restart|status} $SERVICE"
elif [[ $IS_MAC -eq 1 ]]; then
  mkdir -p "$HOME/Library/LaunchAgents"
  # launchd has no EnvironmentFile. Rather than baking HOST/TLS into the plist
  # (which goes stale when the console settings page rewrites hbs.env), run the
  # engine through a shell that sources hbs.env first, exactly like systemd.
  cat > "$HOME/Library/LaunchAgents/$PLIST_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$PLIST_LABEL</string>
  <key>WorkingDirectory</key><string>$DATA_DIR</string>
  <key>ProgramArguments</key><array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>set -a; [ -f "$DATA_DIR/hbs.env" ] &amp;&amp; . "$DATA_DIR/hbs.env"; set +a; exec "$BIN_DIR/hbs-server"</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>HBS_DATA_ROOT</key><string>$DATA_DIR</string>
    <key>PORT</key><string>$PORT</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DATA_DIR/server.log</string>
  <key>StandardErrorPath</key><string>$DATA_DIR/server.err.log</string>
</dict></plist>
EOF
  launchctl bootout "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
  SERVICE_INSTALLED=1
  ok "launchd agent: launchctl print gui/$(id -u)/$PLIST_LABEL"
fi
[[ $SERVICE_INSTALLED -eq 0 && $MODE != desktop ]] && warn "no service manager found - start with 'hbs start'"

# -------------------------------------------------------------------- tray
TRAY_INSTALLED=0
if [[ $WANT_TRAY -eq 1 ]]; then
  if [[ $IS_MAC -eq 1 ]]; then
    if [[ -f "$INSTALLER_DIR/tray-macos.sh" ]]; then
      chmod +x "$INSTALLER_DIR/tray-macos.sh"; TRAY_INSTALLED=1
      ok "Menu-bar helper installed ('hbs tray')"
    fi
  else
    if [[ -f "$INSTALLER_DIR/tray-linux.sh" ]]; then
      chmod +x "$INSTALLER_DIR/tray-linux.sh"
      if command_exists yad; then
        TRAY_INSTALLED=1
        ok "Tray helper installed ('hbs tray')"
      else
        warn "the tray helper needs 'yad' - install it (e.g. sudo apt install yad) and run 'hbs tray'"
        mkdir -p "$BIN_DIR" && cp "$INSTALLER_DIR/tray-linux.sh" "$BIN_DIR/hbs-tray" && chmod +x "$BIN_DIR/hbs-tray" || true
      fi
    fi
  fi
fi

# ------------------------------------------------- desktop entry / icon
ICON_SRC="$HBS_HOME/share/icon.png"
if [[ ! -f "$ICON_SRC" ]]; then
  mkdir -p "$HBS_HOME/share"
  if [[ -f "$HBS_HOME/app/desktop/icons/icon.png" ]]; then
    cp "$HBS_HOME/app/desktop/icons/icon.png" "$ICON_SRC"
  else
    # Brand icon from the repo (12 KB); fall back to a themed icon if absent.
    fetch "$RAW_BASE/desktop/icons/icon.png" "$ICON_SRC" 2>/dev/null || rm -f "$ICON_SRC"
  fi
fi

if [[ $IS_LINUX -eq 1 ]]; then
  mkdir -p "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/256x256/apps"
  ICON_NAME="network-server"
  [[ -f "$ICON_SRC" ]] || ICON_SRC=""
  if [[ -n "$ICON_SRC" ]]; then
    cp "$ICON_SRC" "$HOME/.local/share/icons/hicolor/256x256/apps/hbs-console.png" || true
    ICON_NAME="hbs-console"
  fi
  cat > "$HOME/.local/share/applications/hbs-console.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=HBS Console
GenericName=Host Baseline Security Console
Comment=Read-only host baseline security reviews with sealed reports
Exec=$LOCAL_BIN/hbs app
TryExec=$LOCAL_BIN/hbs
Icon=$ICON_NAME
Terminal=false
Categories=Security;System;Utility;
Keywords=HBS;baseline;hardening;security;audit;compliance;
StartupNotify=true
StartupWMClass=hbs-console
EOF
  ok "Application menu entry installed (HBS Console)"
  if [[ $WANT_ICON -eq 1 && -d "$DESKTOP_DIR" ]]; then
    cp "$HOME/.local/share/applications/hbs-console.desktop" "$DESKTOP_DIR/hbs-console.desktop"
    chmod +x "$DESKTOP_DIR/hbs-console.desktop"
    command_exists gio && gio set "$DESKTOP_DIR/hbs-console.desktop" metadata::trusted true 2>/dev/null || true
    ok "Desktop shortcut created"
  fi
elif [[ $IS_MAC -eq 1 ]]; then
  APP_BUNDLE="$HOME/Applications/HBS Console.app"
  mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
  cat > "$APP_BUNDLE/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>HBS Console</string>
  <key>CFBundleDisplayName</key><string>HBS Console</string>
  <key>CFBundleIdentifier</key><string>in.potenfyr.hbs-console.launcher</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>hbs-console</string>
  <key>CFBundleIconFile</key><string>hbs</string>
  <key>LSMinimumSystemVersion</key><string>10.15</string>
</dict></plist>
EOF
  {
    printf '#!/usr/bin/env bash\n'
    printf 'exec "%s" app\n' "$LOCAL_BIN/hbs"
  } > "$APP_BUNDLE/Contents/MacOS/hbs-console"
  chmod +x "$APP_BUNDLE/Contents/MacOS/hbs-console"
  ICON_ICNS="$HBS_HOME/share/icon.icns"
  if [[ ! -f "$ICON_ICNS" ]]; then
    [[ -f "$HBS_HOME/app/desktop/icons/icon.icns" ]] && cp "$HBS_HOME/app/desktop/icons/icon.icns" "$ICON_ICNS" \
      || fetch "$RAW_BASE/desktop/icons/icon.icns" "$ICON_ICNS" 2>/dev/null || rm -f "$ICON_ICNS"
  fi
  [[ -f "$ICON_ICNS" ]] && cp "$ICON_ICNS" "$APP_BUNDLE/Contents/Resources/hbs.icns" || true
  ok "HBS Console.app installed in ~/Applications"
  if [[ $WANT_ICON -eq 1 && -d "$DESKTOP_DIR" ]]; then
    ln -sfn "$APP_BUNDLE" "$DESKTOP_DIR/HBS Console.app" 2>/dev/null && ok "Desktop shortcut created" || true
  fi
fi

# --------------------------------------------------------------- autostart
if [[ $WANT_AUTOSTART -eq 1 ]]; then
  if [[ $IS_LINUX -eq 1 && $SERVICE_INSTALLED -eq 1 ]]; then
    systemctl --user enable "$SERVICE" >/dev/null 2>&1 && ok "Dashboard starts at login (systemd user unit enabled)" \
      || warn "could not enable the service"
  fi
  if [[ $IS_MAC -eq 1 && $SERVICE_INSTALLED -eq 1 ]]; then
    ok "Dashboard starts at login (launchd RunAtLoad)"
  fi
  if [[ $TRAY_INSTALLED -eq 1 && -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    mkdir -p "$HOME/.config/autostart"
    cat > "$HOME/.config/autostart/hbs-console.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=HBS Console tray
Comment=Background dashboard server and tray icon for HBS Console
Exec=$LOCAL_BIN/hbs tray
Icon=hbs-console
Terminal=false
X-GNOME-Autostart-enabled=true
EOF
    ok "Tray starts with your session"
  fi
else
  [[ $MODE != desktop ]] && note "autostart: off - turn it on later with 'hbs autostart on'"
fi

# ------------------------------------------------------------------ start
if [[ $DO_START -eq 1 && $MODE != desktop ]]; then
  step "Starting HBS Console…"
  if [[ $SERVICE_INSTALLED -eq 1 ]]; then
    if [[ $IS_LINUX -eq 1 ]]; then
      systemctl --user restart "$SERVICE" 2>/dev/null || systemctl --user start "$SERVICE" 2>/dev/null || true
    else
      launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$PLIST_LABEL.plist" 2>/dev/null \
        || launchctl kickstart -k "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
    fi
  else
    # Source hbs.env so HOST / TLS reach the engine in the no-service path too.
    ( cd "$DATA_DIR" \
        && set -a && [[ -f "$DATA_DIR/hbs.env" ]] && . "$DATA_DIR/hbs.env" && set +a \
        && HBS_DATA_ROOT="$DATA_DIR" nohup "$BIN_DIR/hbs-server" >> "$DATA_DIR/server.log" 2>&1 & echo $! > "$DATA_DIR/server.pid" )
  fi
  started=0
  for _ in $(seq 1 40); do
    if probe; then started=1; break; fi
    sleep 0.25
  done
  if [[ $started -eq 1 ]]; then ok "Dashboard answering on $(probe_url)"; else warn "not answering yet - check 'hbs logs'"; fi

  # Surface the tray right away - launch-at-login only takes effect next login.
  if [[ $TRAY_INSTALLED -eq 1 && $WANT_APP -ne 1 && -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] || [[ $TRAY_INSTALLED -eq 1 && $IS_MAC -eq 1 && $WANT_APP -ne 1 ]]; then
    ( setsid "$LOCAL_BIN/hbs" tray >/dev/null 2>&1 & ) 2>/dev/null || nohup "$LOCAL_BIN/hbs" tray >/dev/null 2>&1 &
    ok "Tray icon started"
  fi
fi

# ------------------------------------------------------------ desktop app
APP_INSTALLED=0
if [[ $WANT_APP -eq 1 ]]; then
  blank
  DESKTOP_INSTALLER=""
  [[ -f "$INSTALLER_DIR/install-desktop.sh" ]] && DESKTOP_INSTALLER="$INSTALLER_DIR/install-desktop.sh"
  [[ -z "$DESKTOP_INSTALLER" && -f "$HBS_HOME/app/scripts/install-desktop.sh" ]] && DESKTOP_INSTALLER="$HBS_HOME/app/scripts/install-desktop.sh"
  if [[ -n "$DESKTOP_INSTALLER" ]] && bash "$DESKTOP_INSTALLER" --dir "$HBS_HOME" --port "$PORT" --yes ${TAG:+--tag "$TAG"} ${ASSET_BASE:+--asset-base "$ASSET_BASE"}; then
    APP_INSTALLED=1
  else
    warn "desktop app not installed - the web console is fully functional without it"
  fi
fi

# ---------------------------------------------------------------- summary
blank
printf '  %s%s┌──────────────────────────────────────────────────────────────┐%s\n' "$B" "$V" "$R"
printf '  %s%s│%s  %s✔ HBS Console installed%s                                  %s%s│%s\n' "$B" "$V" "$R" "$G" "$R" "$B" "$V" "$R"
printf '  %s%s└──────────────────────────────────────────────────────────────┘%s\n' "$B" "$V" "$R"
# Reflect the on-disk hosting config in the summary even when this run did not
# change it (`hbs update` re-runs with --yes and no network flags).
if [[ $NETWORK_SET -eq 0 && -f "$DATA_DIR/hbs.env" ]]; then
  HOST_ADDR="$(grep -E '^HOST=' "$DATA_DIR/hbs.env" | head -1 | cut -d= -f2- | tr -d '[:space:]')"
  TLS_CERT="$(grep -E '^HBS_TLS_CERT=' "$DATA_DIR/hbs.env" | head -1 | cut -d= -f2- | tr -d '[:space:]')"
fi
CONSOLE_URL="$(probe_url)"

blank
printf '    %sConsole%s     %s\n' "$B" "$R" "$CONSOLE_URL"
if [[ $APP_INSTALLED -eq 1 ]]; then
  printf '    %sOpen it%s     HBS Console app (desktop + tray) or any browser\n' "$B" "$R"
else
  printf '    %sOpen it%s     hbs app   %s(or just open %s)%s\n' "$B" "$R" "$D" "$CONSOLE_URL" "$R"
fi
printf '    %sControls%s    hbs {start|stop|restart|status|logs|open|app|tray|autostart|update|uninstall}\n' "$B" "$R"
printf '    %sInstall%s     %s   %s(data kept separately)%s\n' "$B" "$R" "$HBS_HOME" "$D" "$R"
printf '    %sSecurity%s    no default admin - the setup wizard creates it; Argon2id + peppered hashes\n' "$B" "$R"
printf '    %sAV/EDR%s      read-only scans, no admin required - docs/security/edr-compatibility.md\n' "$B" "$R"
blank
if [[ -n "$HOST_ADDR" ]]; then
  case "$HOST_ADDR" in 0.0.0.0|"::"|"*")
    note "Listening on every interface on port $PORT${TLS_CERT:+ (HTTPS; self-signed cert)}." ;;
  *)
    note "Listening on $HOST_ADDR:$PORT${TLS_CERT:+ (HTTPS; self-signed cert)}." ;;
  esac
  note "Open the port in your firewall, and prefer HTTPS plus a trusted certificate beyond a LAN."
fi
if [[ "${FIRST_RUN:-0}" -eq 1 ]]; then
  note "First launch opens the setup wizard in the console - you choose the admin account."
else
  note "Existing install detected - your users and reports are untouched."
fi
note "Change the admin password after signing in under Admin → Users."
note "Installed from release $([[ -n "${TAG:-}" ]] && printf '%s' "$TAG" || printf 'latest') · mode: $MODE"
blank
