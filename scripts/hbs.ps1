# HBS Console control CLI for Windows. Installed as `hbs` by scripts/install.ps1.
#
#   hbs start|stop|restart|status|logs|open|app|tray|autostart|update|uninstall
#
#   start/stop/restart   control the dashboard server
#   status               health summary
#   logs                 tail the server log
#   open                 open the dashboard in your browser
#   app                  open the HBS Console desktop app (browser fallback)
#   tray                 start the tray icon + hidden background server
#   autostart on|off     start HBS at login
#   update               pull the latest app and restart
#   uninstall [-Purge]   remove HBS (-Purge also deletes the data)
param(
  [Parameter(Position = 0)][string]$Command = "status",
  [Parameter(Position = 1)][string]$Arg = "",
  [switch]$Purge
)

$ErrorActionPreference = "Stop"
$InstallDir = if ($env:HBS_INSTALL_DIR) {
  $env:HBS_INSTALL_DIR
} else {
  $derived = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { $null }
  if ($derived -and (Test-Path (Join-Path $derived "data"))) { $derived } else { Join-Path $env:LOCALAPPDATA "HBS" }
}
$AppDir = Join-Path $InstallDir "app"
$DataDir = Join-Path $InstallDir "data"
$BinDir = Join-Path $InstallDir "bin"
# The installer stages its control scripts under <root>\installer; older
# installs used <root>\scripts. Accept both.
$ScriptsDir = if (Test-Path (Join-Path $InstallDir "installer\hbs.ps1")) { Join-Path $InstallDir "installer" } else { Join-Path $InstallDir "scripts" }
$PidFile = Join-Path $DataDir "server.pid"
$LogFile = Join-Path $DataDir "server.log"
$AutostartLnk = Join-Path ([Environment]::GetFolderPath("Startup")) "HBS Console Tray.lnk"

function Get-EnvValue([string]$key) {
  $envFile = Join-Path $DataDir "hbs.env"
  if (Test-Path $envFile) {
    $line = Get-Content $envFile | Select-String ("^" + [regex]::Escape($key) + "=") | Select-Object -First 1
    if ($line) { return (($line -replace ("^" + [regex]::Escape($key) + "="), "").Trim()) }
  }
  return ""
}
function Get-EnvPort { $p = Get-EnvValue "PORT"; if ($p) { return $p } else { return "3000" } }
function Get-ConsoleScheme { if (Get-EnvValue "HBS_TLS_CERT") { return "https" } else { return "http" } }
function Get-ConsoleHost {
  $h = Get-EnvValue "HOST"
  if (-not $h -or $h -eq "0.0.0.0" -or $h -eq "::" -or $h -eq "*") { return "127.0.0.1" }
  return $h
}
function Get-ConsoleUrl { return "$(Get-ConsoleScheme)://$(Get-ConsoleHost):$(Get-EnvPort)" }
function Server-Running { return (Test-Path $PidFile) -and (Get-Process -Id (Get-Content $PidFile) -ErrorAction SilentlyContinue) }
function Server-Up {
  try {
    if ((Get-ConsoleScheme) -eq "https") {
      # Local self-check only: the certificate may be self-signed.
      [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    $r = Invoke-WebRequest -UseBasicParsing -Uri (Get-ConsoleUrl) -TimeoutSec 2 -ErrorAction Stop
    return $r.StatusCode -eq 200
  } catch { return $false }
}
# True while the dashboard still has no administrator: the console then shows
# its first-run setup wizard instead of a login form.
function Setup-Pending {
  try {
    if ((Get-ConsoleScheme) -eq "https") {
      [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    $status = Invoke-RestMethod -Uri "$(Get-ConsoleUrl)/api/auth/status" -TimeoutSec 2 -ErrorAction Stop
    return ($status.initialized -eq $false)
  } catch { return $false }
}
function Write-Ok([string]$m) { Write-Host "  v $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "  ! $m" -ForegroundColor Yellow }
function Write-Err([string]$m) { Write-Host "  x $m" -ForegroundColor Red }

# Resolves the real bun.exe. A PATH entry can hold a non-executable `bun`
# shim (npm global bin, scoop), which Start-Process rejects with
# "%1 is not a valid Win32 application".
function Get-BunExe {
  foreach ($candidate in @((Join-Path $env:USERPROFILE ".bun\bin\bun.exe"), (Join-Path $InstallDir "bin\bun.exe"))) {
    if (Test-Path $candidate) { return $candidate }
  }
  $exe = Get-Command bun.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($exe) { return $exe.Source }
  $fallback = Get-Command bun -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -match "\.exe$" } | Select-Object -First 1
  if ($fallback) { return $fallback.Source }
  return $null
}

function Start-Server {
  if (Server-Running) { Write-Warn "already running (pid $(Get-Content $PidFile))"; return }
  $serverExe = Join-Path $BinDir "hbs-server.exe"
  $workdir = $DataDir
  $argList = @()
  if (-not (Test-Path $serverExe)) {
    $bunExe = Get-BunExe
    if (-not $bunExe) {
      $env:Path = "$env:USERPROFILE\.bun\bin;$env:Path"
      $bunExe = Get-BunExe
    }
    if (-not $bunExe) { Write-Err "engine not found - re-run the installer"; return }
    $serverExe = $bunExe
    $workdir = Join-Path $AppDir "dashboard"
    $argList = @("run", "server/index.ts")
  }
  # The server reads PORT/HOST/TLS from its environment (or flags); without
  # this the configured binding would be ignored and it would bind 3000 on
  # loopback instead.
  $env:HBS_DATA_ROOT = $DataDir
  $env:PORT = Get-EnvPort
  $bindHost = Get-EnvValue "HOST"
  if ($bindHost) { $env:HOST = $bindHost } else { Remove-Item Env:HOST -ErrorAction SilentlyContinue }
  $tlsCert = Get-EnvValue "HBS_TLS_CERT"
  if ($tlsCert) {
    $env:HBS_TLS_CERT = $tlsCert
    $env:HBS_TLS_KEY = Get-EnvValue "HBS_TLS_KEY"
  } else {
    Remove-Item Env:HBS_TLS_CERT -ErrorAction SilentlyContinue
    Remove-Item Env:HBS_TLS_KEY -ErrorAction SilentlyContinue
  }
  # Start-Process rejects an empty -ArgumentList ("contains a null value"),
  # so only pass it when the engine actually needs arguments.
  $startArgs = @{ FilePath = $serverExe; WorkingDirectory = $workdir; WindowStyle = "Hidden";
    RedirectStandardOutput = $LogFile; RedirectStandardError = (Join-Path $DataDir "server.err.log"); PassThru = $true }
  if ($argList.Count -gt 0) { $startArgs.ArgumentList = $argList }
  $proc = Start-Process @startArgs
  Set-Content -Encoding ASCII $PidFile $proc.Id
  for ($i = 0; $i -lt 40; $i++) { if (Server-Up) { break }; Start-Sleep -Milliseconds 250 }
  Write-Ok "started (pid $($proc.Id)): $(Get-ConsoleUrl)"
}

function Stop-Server {
  if (Server-Running) {
    $p = Get-Content $PidFile
    Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
    Write-Ok "stopped (pid $p)"
  } else { Write-Warn "not running" }
  Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

function Get-DesktopApp {
  # NSIS writes InstallLocation wrapped in quotes - strip them before using it.
  $key = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "HBS Console" -and $_.Publisher -eq "PotenFYR Studios" -and $_.InstallLocation } |
    Select-Object -First 1
  $candidates = @()
  if ($key -and $key.InstallLocation) { $candidates += (Join-Path ($key.InstallLocation.Trim('"')) "hbs-console.exe") }
  $candidates += (Join-Path $env:LOCALAPPDATA "HBS Console\hbs-console.exe")
  $candidates += (Join-Path $env:LOCALAPPDATA "Programs\HBS Console\hbs-console.exe")
  foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
  return $null
}

function Open-Dashboard { Start-Process (Get-ConsoleUrl) }

switch ($Command.ToLower()) {
  "start"   { Start-Server }
  "stop"    { Stop-Server }
  "restart" { Stop-Server; Start-Server }
  "status"  {
    if (Server-Up) {
      Write-Ok "running - $(Get-ConsoleUrl)"
      Write-Host "    install $InstallDir" -ForegroundColor DarkGray
      Write-Host "    data    $DataDir" -ForegroundColor DarkGray
      $app = Get-DesktopApp
      if ($app) { Write-Host "    desktop app: $app" -ForegroundColor DarkGray }
      if (Setup-Pending) { Write-Warn "setup pending - create the administrator account in the console" }
    } elseif (Server-Running) {
      Write-Warn "process running but not answering on $(Get-ConsoleUrl)"
    } else {
      Write-Warn "not running - start it with 'hbs start'"
    }
  }
  "logs" {
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 80 -Wait }
    else { Write-Warn "no log file yet at $LogFile" }
  }
  "open" { Open-Dashboard }
  "app" {
    if (-not (Server-Up)) { Start-Server | Out-Null }
    $app = Get-DesktopApp
    if ($app) {
      Start-Process $app
      Write-Ok "HBS Console desktop app opened."
    } else {
      Open-Dashboard
      Write-Ok "Opened the dashboard in your browser."
      Write-Host ("    Install the optional desktop app with: powershell -File `"" + (Join-Path $AppDir "scripts\install-desktop.ps1") + "`"") -ForegroundColor DarkGray
    }
  }
  "tray" {
    $tray = Join-Path $ScriptsDir "tray-windows.ps1"
    if (-not (Test-Path $tray)) { $tray = Join-Path $AppDir "scripts\tray-windows.ps1" }
    if (Test-Path $tray) {
      Start-Process powershell -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $tray
      Write-Ok "tray icon started - look for the HBS icon in the system tray"
    } else { Write-Err "tray script not found - re-run the installer" }
  }
  "install-app" {
    if (-not (Server-Up)) { Start-Server | Out-Null }
    $di = Join-Path $ScriptsDir "install-desktop.ps1"
    if (-not (Test-Path $di)) { $di = Join-Path $AppDir "scripts\install-desktop.ps1" }
    if (Test-Path $di) {
      & powershell -NoProfile -ExecutionPolicy Bypass -File $di -InstallDir $InstallDir -Port (Get-EnvPort) -Yes
      if ($LASTEXITCODE -eq 0) { Write-Ok "HBS Console desktop app installed." }
    } else { Write-Err "no desktop-app installer found - re-run the HBS installer" }
  }
  "autostart" {
    switch ($Arg.ToLower()) {
      "on" {
        $tray = Join-Path $ScriptsDir "tray-windows.ps1"
        if (-not (Test-Path $tray)) { $tray = Join-Path $AppDir "scripts\tray-windows.ps1" }
        $shell = New-Object -ComObject WScript.Shell
        $lnk = $shell.CreateShortcut($AutostartLnk)
        $lnk.TargetPath = "powershell.exe"
        $lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$tray`""
        $lnk.WorkingDirectory = $InstallDir
        $lnk.Description = "Starts the HBS Console background server at login"
        $lnk.Save()
        Write-Ok "tray starts with Windows"
      }
      "off" {
        Remove-Item $AutostartLnk -Force -ErrorAction SilentlyContinue
        Write-Ok "autostart removed"
      }
      default {
        if (Test-Path $AutostartLnk) { Write-Ok "autostart: on" } else { Write-Warn "autostart: off" }
      }
    }
  }
  "update" {
    Write-Host "  > updating..." -ForegroundColor Cyan
    # Binary installs update by re-running the staged installer: it fetches
    # the latest release assets and re-wires everything in place.
    $installer = Join-Path $ScriptsDir "install.ps1"
    if (Test-Path $installer) {
      & powershell -NoProfile -ExecutionPolicy Bypass -File $installer -Yes
      if ($LASTEXITCODE -eq 0) { Write-Ok "updated." } else { Write-Err "update failed" }
    } elseif (Test-Path (Join-Path $AppDir ".git")) {
      git -C $AppDir fetch origin main --quiet
      git -C $AppDir reset --hard origin/main --quiet
      Push-Location (Join-Path $AppDir "dashboard"); bun install --quiet; bun run build; Pop-Location
      $exe = Join-Path $BinDir "hbs-server.exe"
      if (Test-Path (Join-Path $AppDir "dashboard\server\index.ts")) {
        Push-Location (Join-Path $AppDir "dashboard"); bun run compile; Pop-Location
        $built = Join-Path $AppDir "dashboard\dist-bin\hbs-server.exe"
        if (Test-Path $built) { Copy-Item $built $exe -Force }
      }
      Stop-Server | Out-Null; Start-Server
      Write-Ok "updated and restarted."
    } else { Write-Err "no updater found - re-run the installer to update" }
  }
  "uninstall" {
    $un = Join-Path $ScriptsDir "uninstall.ps1"
    if (-not (Test-Path $un)) { $un = Join-Path $AppDir "scripts\uninstall.ps1" }
    if (-not (Test-Path $un)) { Write-Err "uninstaller not found; remove $InstallDir manually"; break }
    if ($Purge) { & powershell -NoProfile -ExecutionPolicy Bypass -File $un -InstallDir $InstallDir -Purge -Yes }
    else { & powershell -NoProfile -ExecutionPolicy Bypass -File $un -InstallDir $InstallDir }
  }
  default {
    @"
usage: hbs {start|stop|restart|status|logs|open|app|tray|install-app|autostart|update|uninstall}

  start|stop|restart      control the dashboard server
  status                  health summary
  logs                    tail the server log
  open                    open the dashboard in your browser
  app                     open the HBS Console desktop app (browser fallback)
  tray                    start the tray icon + background server
  install-app             install the HBS Console desktop app
  autostart on|off|status start HBS at login
  update                  download the latest release and restart
  uninstall [-Purge]      remove HBS (-Purge deletes the data too)
"@ | Write-Host
  }
}
