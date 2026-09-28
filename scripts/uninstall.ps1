# HBS Console uninstaller for Windows.
#
# This file is copied into <InstallDir>\installer by install.ps1 and
# referenced from Settings > Apps (Add/Remove Programs). It is safe to run
# directly:
#
#   powershell -ExecutionPolicy Bypass -File uninstall.ps1 [-InstallDir PATH] [-Purge] [-Yes]
#
# Without -Purge the app is removed and your data (database, reports) is kept.
param(
  [string]$InstallDir = "$env:LOCALAPPDATA\HBS",
  [switch]$Purge,
  [switch]$Yes,
  [int]$Port = 0
)

$ErrorActionPreference = "SilentlyContinue"
# Resolve the install root: explicit parameter > HBS_INSTALL_DIR > next to this
# script (it ships inside <InstallDir>\installer) > default.
if (-not $PSBoundParameters.ContainsKey("InstallDir")) {
  if ($env:HBS_INSTALL_DIR) {
    $InstallDir = $env:HBS_INSTALL_DIR
  } elseif ($PSScriptRoot) {
    $derived = Split-Path $PSScriptRoot -Parent
    if ((Test-Path (Join-Path $derived "data")) -or (Test-Path (Join-Path $derived "app"))) { $InstallDir = $derived }
  }
}

$AppDir = Join-Path $InstallDir "app"
$DataDir = Join-Path $InstallDir "data"
$BinDir = Join-Path $InstallDir "bin"
$ScriptsDir = if (Test-Path (Join-Path $InstallDir "installer")) { Join-Path $InstallDir "installer" } else { Join-Path $InstallDir "scripts" }

Write-Host ""
Write-Host "  HBS Console - uninstaller"
Write-Host ""

# 1. stop the background server and the tray
Write-Host "  > stopping background processes..."
$pidFile = Join-Path $DataDir "server.pid"
if (Test-Path $pidFile) {
  Stop-Process -Id (Get-Content $pidFile) -Force -ErrorAction SilentlyContinue
  Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}
# Never sweep ourselves or the shell that launched us. Both the path
# separators and the casing in a command line can differ from ours.
$norm = ($InstallDir -replace "/", "\").TrimEnd("\").ToLower()
$protected = @()
$walk = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction SilentlyContinue
while ($walk -and $walk.ParentProcessId) {
  $protected += $walk.ParentProcessId
  $walk = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $walk.ParentProcessId) -ErrorAction SilentlyContinue
}
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object {
    $_.CommandLine -and (($_.CommandLine -replace "/", "\").ToLower().Contains($norm)) -and
    $_.ProcessId -ne $PID -and $_.ProcessId -notin $protected -and
    $_.CommandLine -notmatch "uninstall\.ps1|install(-desktop)?\.ps1"
  } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
# The engine's command line does not mention the install dir - match the image.
Get-Process hbs-server -ErrorAction SilentlyContinue |
  Where-Object { try { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) } catch { $false } } |
  Stop-Process -Force -ErrorAction SilentlyContinue

# 2. remove shortcuts
Write-Host "  > removing shortcuts..."
$startup = [Environment]::GetFolderPath("Startup")
$programs = [Environment]::GetFolderPath("Programs")
$desktop = [Environment]::GetFolderPath("Desktop")
foreach ($p in @(
    (Join-Path $startup "HBS Console Tray.lnk"),
    (Join-Path $programs "HBS Console (dashboard).lnk"),
    (Join-Path $programs "HBS Console.lnk"),
    (Join-Path $programs "HBS Console (tray).lnk"),
    (Join-Path $desktop "HBS Console.lnk"))) {
  Remove-Item $p -Force -ErrorAction SilentlyContinue
}

# 3. remove the Apps & Features entry and PATH entry
Write-Host "  > unregistering..."
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\HBSConsole" -Recurse -Force -ErrorAction SilentlyContinue
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$parts = @($userPath -split ";" | Where-Object { $_ })
if ($parts -contains $BinDir) {
  $kept = $parts | Where-Object { $_ -ne $BinDir }
  [Environment]::SetEnvironmentVariable("Path", ($kept -join ";"), "User")
}

# 4. remove the desktop app (Tauri bundle) if the user installed it
$desktopUninstall = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
  ForEach-Object { Get-ItemProperty $_.PSPath } |
  Where-Object { $_.DisplayName -eq "HBS Console" -and $_.Publisher -eq "PotenFYR Studios" -and $_.UninstallString -and $_.UninstallString -notlike "*uninstall.ps1*" } |
  Select-Object -First 1
if ($desktopUninstall) {
  Write-Host "  > removing the HBS Console desktop app..."
  if ($desktopUninstall.QuietUninstallString) { cmd /c $desktopUninstall.QuietUninstallString | Out-Null }
  elseif ($desktopUninstall.UninstallString) { cmd /c $desktopUninstall.UninstallString | Out-Null }
  # NSIS uninstallers re-launch from %TEMP% and outlive the process we started;
  # give them a moment so the Start menu and registry are actually clean.
  for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    $left = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
      ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
      Where-Object { $_.DisplayName -eq "HBS Console" -and $_.Publisher -eq "PotenFYR Studios" -and $_.UninstallString -notlike "*uninstall.ps1*" }
    if (-not $left) { break }
  }
}

# 5. app + optional data
if ($Purge) {
  Write-Host "  > removing $InstallDir (including data)..."
  Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "  v removed the app and all data."
} else {
  Write-Host "  > removing the application files..."
  Remove-Item $AppDir -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item $BinDir -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item $ScriptsDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "  v removed the app; your reports and database stay in $DataDir"
  Write-Host "    (re-run with -Purge to delete the data too)"
}

Write-Host ""
Write-Host "  v HBS Console uninstalled."
Write-Host ""
