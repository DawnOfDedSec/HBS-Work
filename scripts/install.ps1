# HBS Console installer for Windows.
#
#   irm https://raw.githubusercontent.com/DawnOfDedSec/HBS-Tool/main/scripts/install.ps1 | iex
#
# Installs or updates: Bun (runtime), the HBS repo (app), the `hbs` command,
# and a startup tray icon that runs the server in the background.
# Data lives in <install>\data and survives updates.
#
# Flags: -InstallDir PATH | -Port N | -NoTray | -Update | -Uninstall [-Purge]
param(
  [string]$InstallDir = "$env:LOCALAPPDATA\HBS",
  [int]$Port = 3000,
  [switch]$NoTray,
  [switch]$Update,
  [switch]$Uninstall,
  [switch]$Purge,
  [string]$RepoUrl = "https://github.com/DawnOfDedSec/HBS-Tool.git",
  [string]$Branch = "main"
)

$ErrorActionPreference = "Stop"
$AppDir = Join-Path $InstallDir "app"
$DataDir = Join-Path $InstallDir "data"
$BinDir = Join-Path $InstallDir "bin"
$ScriptsDir = Join-Path $InstallDir "scripts"

function Write-Hbs { Write-Host "[hbs] $args" -ForegroundColor Cyan }
function Fail { Write-Host "[hbs] $args" -ForegroundColor Red; exit 1 }

# --- uninstall ---------------------------------------------------------------
if ($Uninstall) {
  Write-Hbs "stopping server and tray…"
  Get-Process -Name bun -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*$InstallDir*" } | Stop-Process -Force -ErrorAction SilentlyContinue
  Get-Process | Where-Object { $_.ProcessName -eq "powershell" } | Out-Null # tray exits via its own menu normally
  $startup = [Environment]::GetFolderPath("Startup")
  Remove-Item (Join-Path $startup "HBS Tray.lnk") -Force -ErrorAction SilentlyContinue
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($userPath -like "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", ($userPath -split ";" | Where-Object { $_ -ne $BinDir }) -join ";", "User")
  }
  if ($Purge) { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue; Write-Hbs "removed $InstallDir (including data)" }
  else { Remove-Item (Join-Path $InstallDir "app") -Recurse -Force -ErrorAction SilentlyContinue; Write-Hbs "removed the app; data kept at $DataDir" }
  Write-Hbs "uninstalled."
  exit 0
}

# --- prerequisites -----------------------------------------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Fail "git is required (install it, then re-run)" }
if (-not (Get-Command bun -ErrorAction SilentlyContinue)) {
  Write-Hbs "installing Bun runtime…"
  powershell -NoProfile -ExecutionPolicy Bypass -Command "irm bun.sh/install.ps1 | iex"
  $env:Path = "$env:USERPROFILE\.bun\bin;$env:Path"
}
if (-not (Get-Command bun -ErrorAction SilentlyContinue)) { Fail "Bun installation failed — open a new terminal and re-run" }

New-Item -ItemType Directory -Force -Path $AppDir, $DataDir, $BinDir, $ScriptsDir | Out-Null

# --- app: clone or update ----------------------------------------------------
if (Test-Path (Join-Path $AppDir ".git")) {
  Write-Hbs "updating app…"
  git -C $AppDir fetch origin $Branch --quiet
  git -C $AppDir reset --hard "origin/$Branch" --quiet
} else {
  Write-Hbs "cloning HBS…"
  git clone --branch $Branch --depth 1 $RepoUrl $AppDir --quiet
}

Write-Hbs "installing dependencies…"
Push-Location (Join-Path $AppDir "dashboard")
bun install --quiet
Pop-Location

# --- env + CLI ---------------------------------------------------------------
$envFile = Join-Path $DataDir "hbs.env"
if (-not (Test-Path $envFile)) {
  "PORT=$Port`nHBS_DATA_ROOT=$DataDir`nHBS_BOOTSTRAP_ADMIN=false" | Set-Content -Encoding ASCII $envFile
  Write-Hbs "wrote $envFile (edit PORT etc. there)"
}

Copy-Item (Join-Path $AppDir "scripts\hbs.ps1") $ScriptsDir -Force
Copy-Item (Join-Path $AppDir "scripts\tray-windows.ps1") $ScriptsDir -Force
$cmdShim = Join-Path $BinDir "hbs.cmd"
@"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "$ScriptsDir\hbs.ps1" %*
"@ | Set-Content -Encoding ASCII $cmdShim

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $userPath -like "*$BinDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$BinDir", "User")
  Write-Hbs "added $BinDir to your PATH (new terminals only)"
}

# --- startup tray shortcut ---------------------------------------------------
if (-not $NoTray) {
  $startup = [Environment]::GetFolderPath("Startup")
  $lnkPath = Join-Path $startup "HBS Tray.lnk"
  $shell = New-Object -ComObject WScript.Shell
  $lnk = $shell.CreateShortcut($lnkPath)
  $lnk.TargetPath = "powershell.exe"
  $lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptsDir\tray-windows.ps1`""
  $lnk.WorkingDirectory = $ScriptsDir
  $lnk.Description = "HBS Console background server + tray icon"
  $lnk.Save()
  Write-Hbs "tray icon enabled (starts with Windows). Start it now with: hbs tray"
}

Write-Hbs "done. console: http://127.0.0.1:$Port"
if (-not $Update) { Write-Hbs "start it with: hbs start   (or run 'hbs tray' for the background tray icon)" }
