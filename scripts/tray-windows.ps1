# HBS Console tray icon (Windows). Manages the dashboard server in the background.
#
# Menu: Open Console / Start / Stop / Restart / Logs / Update / Exit
# Installed into the Startup folder by scripts/install.ps1; start manually with `hbs tray`.

$ErrorActionPreference = "SilentlyContinue"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# single-instance guard
$created = $false
$mutex = New-Object System.Threading.Mutex($true, "HBS-Tray-Mutex", [ref]$created)
if (-not $created) { exit 0 }

$InstallDir = if ($env:HBS_INSTALL_DIR) { $env:HBS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "HBS" }
$AppDir = Join-Path $InstallDir "app"
$DataDir = Join-Path $InstallDir "data"
$ScriptsDir = Join-Path $InstallDir "scripts"
$PidFile = Join-Path $DataDir "server.pid"
$LogFile = Join-Path $DataDir "server.log"

function Get-Port {
  $envFile = Join-Path $DataDir "hbs.env"
  if (Test-Path $envFile) { $line = (Get-Content $envFile | Select-String "^PORT="); if ($line) { return ($line -replace "^PORT=", "").Trim() } }
  return "3000"
}
function Server-Running { return (Test-Path $PidFile) -and (Get-Process -Id (Get-Content $PidFile) -ErrorAction SilentlyContinue) }

function Invoke-ServerControl {
  param([string]$Action)
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptsDir "hbs.ps1") $Action
}

function Show-Balloon {
  param([string]$Text, [string]$Title = "HBS Console")
  $notify.Icon = [System.Drawing.SystemIcons]::Shield
  $notify.BalloonTipTitle = $Title
  $notify.BalloonTipText = $Text
  $notify.ShowBalloonTip(3000)
}

$form = New-Object System.Windows.Forms.Form
$form.WindowState = "Minimized"
$form.ShowInTaskbar = $false
$form.FormBorderStyle = "FixedToolWindow"
$form.opacity = 0
$form.ShowInTaskbar = $false

$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.Text = "HBS Console"
$notify.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$itemConsole = $menu.Items.Add("Open Console")
$itemConsole.Add_Click({ Start-Process "http://127.0.0.1:$(Get-Port)" }.GetNewClosure())

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$itemStart = $menu.Items.Add("Start server")
$itemStart.Add_Click({ Invoke-ServerControl "start"; Show-Balloon "Server started." }.GetNewClosure())
$itemStop = $menu.Items.Add("Stop server")
$itemStop.Add_Click({ Invoke-ServerControl "stop"; Show-Balloon "Server stopped." }.GetNewClosure())
$itemRestart = $menu.Items.Add("Restart server")
$itemRestart.Add_Click({ Invoke-ServerControl "restart"; Show-Balloon "Server restarted." }.GetNewClosure())

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$itemLogs = $menu.Items.Add("View logs")
$itemLogs.Add_Click({ if (Test-Path $LogFile) { Start-Process notepad $LogFile } }.GetNewClosure())
$itemData = $menu.Items.Add("Open data folder")
$itemData.Add_Click({ Start-Process explorer $DataDir }.GetNewClosure())
$itemUpdate = $menu.Items.Add("Update HBS")
$itemUpdate.Add_Click({ Invoke-ServerControl "update"; Show-Balloon "Update finished." }.GetNewClosure())

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$itemExit = $menu.Items.Add("Exit (keeps server running)")
$itemExit.Add_Click({
  $notify.Visible = $false
  $mutex.ReleaseMutex()
  $form.Close()
}.GetNewClosure())

$notify.ContextMenuStrip = $menu
$notify.Add_Click({
  if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
    Start-Process "http://127.0.0.1:$(Get-Port)"
  }
})

# reflect server state in the tooltip every 10s
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 10000
$timer.Add_Tick({
  if (Server-Running) { $notify.Text = "HBS Console - running (port $(Get-Port))" }
  else { $notify.Text = "HBS Console - stopped" }
})
$timer.Start()

# auto-start the server if it is not running yet
if (-not (Server-Running)) { Invoke-ServerControl "start" }
Show-Balloon "HBS Console is running in the background." "Click the icon to open the console."

$form.ShowDialog() | Out-Null
