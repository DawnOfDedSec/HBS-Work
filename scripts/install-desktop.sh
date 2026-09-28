#!/usr/bin/env bash
# Install the HBS Console desktop app (Tauri 2) on Linux or macOS.
#
#   bash scripts/install-desktop.sh [--dir ~/.hbs] [--port 3000] [--yes]
#                                   [--tag vX.Y.Z] [--asset-base DIR|URL]
#                                   [--from-source] [--uninstall]
#
# Prefers the prebuilt bundle published with the project's GitHub release
# (.deb/.rpm/.AppImage on Linux, universal .dmg on macOS) and falls back to a
# local source build (--from-source) when the release has no bundle for this
# platform yet. The dashboard itself keeps working in a browser either way.
set -uo pipefail

HBS_HOME="${HBS_HOME:-$HOME/.hbs}"
PORT="${HBS_PORT:-3000}"
REPO="PotenFYR-Studios/HBS-Tool"
API="https://api.github.com/repos/$REPO/releases/latest"
RELEASE_BASE="${HBS_RELEASE_URL:-https://github.com/$REPO/releases}"
FROM_SOURCE=0
UNINSTALL=0
ASSUME_YES=0
URL_OVERRIDE="${HBS_DESKTOP_URL:-}"
TAG="${HBS_RELEASE_TAG:-}"
ASSET_BASE="${HBS_ASSET_BASE:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) HBS_HOME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --from-source) FROM_SOURCE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --url) URL_OVERRIDE="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --asset-base) ASSET_BASE="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) printf 'unknown flag: %s\n' "$1" >&2; exit 2 ;;
  esac
done

OS="$(uname -s)"
ARCH="$(uname -m)"
IS_MAC=0; [[ "$OS" == "Darwin" ]] && IS_MAC=1
IS_LINUX=0; [[ "$OS" == "Linux" ]] && IS_LINUX=1
{ [[ $IS_MAC -eq 0 && $IS_LINUX -eq 0 ]]; } && { printf 'install-desktop: unsupported OS %s (use install-desktop.ps1 on Windows)\n' "$OS" >&2; exit 1; }

log()  { printf '  [desktop] %s\n' "$*"; }
warn() { printf '  [desktop] %s\n' "$*" >&2; }
die()  { printf '  [desktop] %s\n' "$*" >&2; exit 1; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

APPS_DIR="$HOME/Applications"
BIN_LOCAL="$HOME/.local/bin"

uninstall_app() {
  log "removing the HBS Console desktop app…"
  rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/hbs/root"
  if [[ $IS_MAC -eq 1 ]]; then
    osascript -e 'tell application "HBS Console" to quit' >/dev/null 2>&1 || true
    rm -rf "$APPS_DIR/HBS Console.app" "/Applications/HBS Console.app"
  else
    pkill -f "hbs-console" >/dev/null 2>&1 || true
    rm -f "$BIN_LOCAL/HBS-Console.AppImage"
    rm -f "$HOME/.local/share/applications/hbs-console-app.desktop"
    if command_exists dpkg && dpkg -l hbs-console >/dev/null 2>&1; then
      SUDO=""; [[ "$(id -u)" -ne 0 ]] && command_exists sudo && SUDO="sudo"
      $SUDO dpkg -r hbs-console >/dev/null 2>&1 || true
    fi
    if command_exists rpm && rpm -q hbs-console >/dev/null 2>&1; then
      SUDO=""; [[ "$(id -u)" -ne 0 ]] && command_exists sudo && SUDO="sudo"
      $SUDO rpm -e hbs-console >/dev/null 2>&1 || true
    fi
  fi
  log "desktop app removed."
}

if [[ $UNINSTALL -eq 1 ]]; then
  uninstall_app
  exit 0
fi

# --------------------------------------------------------------- pick a bundle
asset_url_for_platform() {
  local urls pattern arch_re arch_ex
  if [[ -n "$ASSET_BASE" && -d "$ASSET_BASE" ]]; then
    urls="$(cd "$ASSET_BASE" && ls -1 | sed "s|^|$ASSET_BASE/|")"
  elif [[ -n "$ASSET_BASE" ]]; then
    urls="$(fetch "$ASSET_BASE/manifest.json" - 2>/dev/null | grep -o '"name": "[^"]*"' | cut -d'"' -f4 | sed "s|^|$ASSET_BASE/|")"
  elif [[ -n "$TAG" ]]; then
    urls="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/tags/$TAG" 2>/dev/null | grep -o '"browser_download_url":[[:space:]]*"[^"]*"' | sed 's/.*"\(http[^"]*\)"/\1/')"
  else
    local json
    json="$(curl -fsSL "$API" 2>/dev/null || true)"
    [[ -z "$json" ]] && return 1
    urls="$(printf '%s' "$json" | grep -o '"browser_download_url":[[:space:]]*"[^"]*"' | sed 's/.*"\(http[^"]*\)"/\1/')"
  fi
  [[ -z "$urls" ]] && return 1
  # Host architecture first, package format second; never install an arm64
  # bundle on an x64 host just because it sorted first.
  if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    arch_re='arm64|aarch64|universal'; arch_ex='x86|x64_i|amd64|i686'
  else
    arch_re='amd64|x86_64|universal'; arch_ex='arm64|aarch64|armv7'
  fi
  if [[ $IS_MAC -eq 1 ]]; then
    pattern='\.dmg$'
    printf '%s\n' "$urls" | grep -Ei "$pattern" | grep -Ei "$arch_re" | grep -Eiv "$arch_ex" | head -1 \
      || printf '%s\n' "$urls" | grep -Ei "$pattern" | head -1
  else
    if command_exists apt-get || command_exists dpkg; then pattern='\.deb$'
    elif command_exists dnf || command_exists rpm; then pattern='\.rpm$'
    else pattern='\.AppImage$'; fi
    printf '%s\n' "$urls" | grep -Ei "$pattern" | grep -Ei "$arch_re" | grep -Eiv "$arch_ex" | head -1 \
      || printf '%s\n' "$urls" | grep -Ei "$pattern" | grep -Ei 'amd64|x86_64|aarch64|arm64|universal' | head -1
  fi
}

install_deb() {
  local file="$1"
  local SUDO=""; [[ "$(id -u)" -ne 0 ]] && command_exists sudo && SUDO="sudo"
  if command_exists apt-get; then
    $SUDO apt-get install -y "$file" >/dev/null 2>&1 || $SUDO dpkg -i "$file" >/dev/null 2>&1
  else
    $SUDO dpkg -i "$file" >/dev/null 2>&1
  fi
}

install_rpm() {
  local file="$1"
  local SUDO=""; [[ "$(id -u)" -ne 0 ]] && command_exists sudo && SUDO="sudo"
  if command_exists dnf; then $SUDO dnf install -y "$file" >/dev/null 2>&1
  else $SUDO rpm -Uvh "$file" >/dev/null 2>&1; fi
}

install_appimage() {
  local file="$1"
  mkdir -p "$BIN_LOCAL" "$HOME/.local/share/applications"
  install -m 0755 "$file" "$BIN_LOCAL/HBS-Console.AppImage"
  local icon="$HBS_HOME/share/icon.png"
  [[ -f "$icon" ]] || icon="$HBS_HOME/app/desktop/icons/icon.png"
  local icon_line="utilities-system-monitor"
  if [[ -f "$icon" ]]; then
    mkdir -p "$HOME/.local/share/icons/hicolor/256x256/apps"
    cp "$icon" "$HOME/.local/share/icons/hicolor/256x256/apps/hbs-console.png"
    icon_line="hbs-console"
  fi
  cat > "$HOME/.local/share/applications/hbs-console-app.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=HBS Console
Comment=Host baseline security reviews (desktop app)
Exec=$BIN_LOCAL/HBS-Console.AppImage
Icon=$icon_line
Terminal=false
Categories=Security;System;Utility;
StartupWMClass=hbs-console
EOF
}

install_dmg() {
  local file="$1"
  mkdir -p "$APPS_DIR"
  local mnt
  mnt="$(hdiutil attach -nobrowse -noverify -quiet "$file" 2>/dev/null | tail -1 | awk '{print $NF}')"
  [[ -z "$mnt" ]] && mnt="/Volumes/HBS Console"
  if [[ -d "$mnt/HBS Console.app" ]]; then
    rm -rf "$APPS_DIR/HBS Console.app"
    cp -R "$mnt/HBS Console.app" "$APPS_DIR/"
  fi
  hdiutil detach "$mnt" -quiet >/dev/null 2>&1 || true
  # Unsigned/ad-hoc builds: clear the quarantine flag so it opens normally.
  xattr -dr com.apple.quarantine "$APPS_DIR/HBS Console.app" 2>/dev/null || true
}

from_source() {
  local src="$HBS_HOME/app/desktop"
  [[ -d "$src" ]] || die "no source checkout at $src - install the app first"
  command_exists cargo || die "Rust toolchain (cargo) is required for --from-source"
  local bun="bun"; command_exists bun || bun="$HOME/.bun/bin/bun"
  [[ -x "$bun" || -n "$(command -v bun)" ]] || die "Bun is required for --from-source"
  log "building the desktop app from source (this takes a few minutes)…"
  (cd "$src" && "$bun" install --silent >/dev/null 2>&1; "$bun" x --bun @tauri-apps/cli@^2 build) || die "source build failed"
  if [[ $IS_MAC -eq 1 ]]; then
    local built
    built="$(find "$src/target/release/bundle" -maxdepth 3 -name "HBS Console.app" -print -quit 2>/dev/null)"
    [[ -n "$built" ]] || die "build finished but no .app bundle was found"
    mkdir -p "$APPS_DIR"; rm -rf "$APPS_DIR/HBS Console.app"; cp -R "$built" "$APPS_DIR/"
  else
    local deb rpm img
    deb="$(find "$src/target/release/bundle/deb" -name '*.deb' -print -quit 2>/dev/null)"
    rpm="$(find "$src/target/release/bundle/rpm" -name '*.rpm' -print -quit 2>/dev/null)"
    img="$(find "$src/target/release/bundle/appimage" -name '*.AppImage' -print -quit 2>/dev/null)"
    if [[ -n "$deb" ]]; then install_deb "$deb"
    elif [[ -n "$rpm" ]]; then install_rpm "$rpm"
    elif [[ -n "$img" ]]; then install_appimage "$img"
    else die "build finished but no bundle was found"; fi
  fi
}

log "looking for the HBS Console desktop app for $OS/$ARCH…"
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t hbs-desktop)"
trap 'rm -rf "$TMP"' EXIT

fetch() {
  # fetch <url> <outfile> ("-" streams to stdout)
  local url="$1" out="$2"
  if command_exists curl; then
    if [[ "$out" == "-" ]]; then curl -fsSL "$url"; else curl -fsSL --retry 2 -o "$out" "$url"; fi
  elif command_exists wget; then
    if [[ "$out" == "-" ]]; then wget -qO- "$url"; else wget -q -O "$out" "$url"; fi
  else return 127; fi
}

URL="$URL_OVERRIDE"
if [[ -z "$URL" ]]; then
  URL="$(asset_url_for_platform || true)"
fi

if [[ -z "$URL" && $FROM_SOURCE -eq 1 ]]; then
  from_source
  log "done - open HBS Console from your application menu."
  exit 0
fi

if [[ -z "$URL" ]]; then
  if [[ $ASSUME_YES -eq 0 ]] && { [[ -t 0 ]] || [[ -r /dev/tty ]]; }; then
    printf '  No prebuilt desktop app in the latest release. Build it from source now (needs Rust)? [y/N] '
    ans=""; { read -r ans < /dev/tty; } 2>/dev/null || true
    case "${ans:0:1}" in [Yy]) from_source; log "done."; exit 0 ;; esac
  fi
  die "no prebuilt desktop app published for this platform yet - use '--from-source' or keep using the web console"
fi

FILE="$TMP/$(basename "$URL")"
log "downloading $(basename "$URL")…"
if [[ "$URL" == "$ASSET_BASE"/* && -d "$ASSET_BASE" ]]; then
  cp "$URL" "$FILE" || die "copy failed: $URL"
else
  fetch "$URL" "$FILE" || curl -fL --progress-bar "$URL" -o "$FILE" || die "download failed: $URL"
fi
[[ -s "$FILE" ]] || die "downloaded file is empty"

case "$FILE" in
  *.deb)      log "installing (deb)…";      install_deb "$FILE"      || die "deb install failed";;
  *.rpm)      log "installing (rpm)…";      install_rpm "$FILE"      || die "rpm install failed";;
  *.AppImage) log "installing (AppImage)…"; install_appimage "$FILE" || die "AppImage install failed";;
  *.dmg)      log "installing (dmg)…";      install_dmg "$FILE"      || die "dmg install failed";;
  *)          die "unsupported bundle: $FILE";;
esac

# Tell the app where the HBS install root lives (bundles know nothing about
# a custom --dir): one-line path file the shell reads at startup.
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/hbs" 2>/dev/null && printf '%s\n' "$HBS_HOME" \
  > "${XDG_CONFIG_HOME:-$HOME/.config}/hbs/root" 2>/dev/null || true

log "done - HBS Console is in your application menu (and your desktop, if you made a shortcut)."
exit 0
