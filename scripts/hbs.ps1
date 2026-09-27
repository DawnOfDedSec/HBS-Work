# HBS Console control CLI for Windows. Installed as `hbs` by scripts/install.ps1.
#
#   hbs start|stop|restart|status|logs|open|update|tray
param(
  [Parameter(Position = 0)]
  [string]$Command = "status"
)

$ErrorActionPreference = "Stop"
$InstallDir = if ($env:HBS_INSTALL_DIR) { $env:HBS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "HBS" }
$AppDir = Join-Path $InstallDir "app"
$DataDir = Join-Path $InstallDir "data"
$ScriptsDir = Join-Path $InstallDir "scripts"
$PidFile = Join-Path $DataDir "server.pid"
$LogFile = Join-Path $DataDir "server.log"

function Get-EnvPort { if (Test-Path (Join-Path $DataDir "hbs.env")) { return (Get-Content (Join-Path $DataDir "hbs.env") | Select-String "^PORT=") -replace "^PORT=", "" } return "3000" }
function Server-Running { return (Test-Path $PidFile) -and (Get-Process -Id (Get-Content $PidFile) -ErrorAction SilentlyContinue) }

function Start-Server {
  if (Server-Running) { Write-Host "[hbs] already running (pid $(Get-Content $PidFile))" -ForegroundColor Yellow; return }
  if (-not (Get-Command bun -ErrorAction SilentlyContinue)) { $env:Path = "$env:USERPROFILE\.bun\bin;$env:Path" }
  $env:HBS_DATA_ROOT = $DataDir
  $proc = Start-Process -FilePath "bun" -ArgumentList "run", "server/index.ts" `
    -WorkingDirectory (Join-Path $AppDir "dashboard") -WindowStyle Hidden `
    -RedirectStandardOutput $LogFile -RedirectStandardError (Join-Path $DataDir "server.err.log") `
    -PassThru
  Set-Content -Encoding ASCII $PidFile $proc.Id
  Start-Sleep -Seconds 2
  Write-Host "[hbs] started (pid $($proc.Id)): http://127.0.0.1:$(Get-EnvPort)"
}

function Stop-Server {
  if (Server-Running) {
    $pidValue = Get-Content $PidFile
    Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
    Write-Host "[hbs] stopped (pid $pidValue)"
  } else {
    Write-Host "[hbs] not running" -ForegroundColor Yellow
  }
  Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

switch ($Command) {
  "start"   { Start-Server }
  "stop"    { Stop-Server }
  "restart" { Stop-Server; Start-Server }
  "status" {
    if (Server-Running) { Write-Host "[hbs] running (pid $(Get-Content $PidFile)): http://127.0.0.1:$(Get-EnvPort)" -ForegroundColor Green }
    else { Write-Host "[hbs] not running" -ForegroundColor Yellow }
  }
  "logs" {
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 60 }
    else { Write-Host "[hbs] no log file yet at $LogFile" -ForegroundColor Yellow }
  }
  "open"    { Start-Process "http://127.0.0.1:$(Get-EnvPort)" }
  "tray" {
    Start-Process powershell -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", (Join-Path $ScriptsDir "tray-windows.ps1")
    Write-Host "[hbs] tray icon started — look for the shield icon in the system tray"
  }
  "update" {
    if (Test-Path (Join-Path $AppDir ".git")) {
      git -C $AppDir fetch origin main --quiet
      git -C $AppDir reset --hard origin/main --quiet
      Push-Location (Join-Path $AppDir "dashboard"); bun install --quiet; Pop-Location
      Stop-Server; Start-Server
      Write-Host "[hbs] updated and restarted."
    } else { Write-Host "[hbs] app was not installed via git; re-run the installer to update." -ForegroundColor Yellow }
  }
  default   { Write-Host "usage: hbs {start|stop|restart|status|logs|open|update|tray}" }
}
