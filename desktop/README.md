# HBS Console - desktop app (Tauri 2)

An **optional** shell around the same dashboard the web install gives you. The
dashboard stays a normal web console; this app adds a native window, a tray /
menu-bar icon, desktop shortcuts, launch-at-login and one-click control of the
local server. No Electron: it uses the OS webview (~10 MB installed).

## What it does

- Starts the dashboard (Bun + `server/index.ts`) if nothing is listening yet,
  and stops only what it started.
- Tray menu: **Open HBS Console** (embedded window), **Open in browser**,
  start / stop / restart, **View logs**, **Open data folder**, **Update HBS**,
  **Launch at login**, **Quit (keep server running)** and
  **Quit and stop server**.
- Closing the window keeps HBS in the tray; the tray icon is the control point.
- Shell screen (shown when the dashboard is not answering) reports status,
  surfaces errors, and can open the logs or the data folder.
- If the dashboard is managed by systemd/launchd (from `install.sh`), the tray
  controls that unit instead of spawning a second server.

## Layout

```
desktop/
├── src/main.rs          shell: server lifecycle, tray, commands
├── ui/                  shell screen (plain HTML/CSS/JS, no build step)
├── icons/               generated brand icons (png/ico/icns)
├── capabilities/        Tauri permissions (core only)
└── tauri.conf.json      window, bundle targets, CSP
```

Install root resolution (same as the scripts): `HBS_INSTALL_DIR` or
`HBS_HOME`, else `%LOCALAPPDATA%\HBS` on Windows and `~/.hbs` elsewhere.
Layout: `<root>/app/dashboard` (server), `<root>/data` (database, reports,
`hbs.env`, `server.log`).

## Build

```bash
cd desktop
bun install                 # only the Tauri CLI
bun run dev                 # live shell against your local install
bun run build               # bundles: nsis+msi (Windows), deb+rpm+appimage
                            # (Linux), universal dmg (macOS)
```

Prerequisites: Rust (stable) + the platform toolchain, and - on Linux -
`libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`.
Users never need any of this: the `release` workflow builds every platform in
`.github/workflows/release.yml` (`desktop-bundles`) and publishes the bundles
as release assets, which `scripts/install-desktop.sh|ps1` and the main
installers consume. The shell runs the standalone `hbs-server` binary from
`<root>/bin` (falling back to Bun-from-source on dev checkouts), so end users
need no runtime either.

## Install / uninstall

- `bash scripts/install-desktop.sh` (Linux/macOS) or
  `powershell -File scripts\install-desktop.ps1` (Windows) - prebuilt bundle
  from the latest release, `--from-source|-FromSource` to build locally.
- Windows: **Settings → Apps → HBS Console**. Linux: your package manager or
  `install-desktop.sh --uninstall`. macOS: drag the app to the bin, or
  `install-desktop.sh --uninstall`.
