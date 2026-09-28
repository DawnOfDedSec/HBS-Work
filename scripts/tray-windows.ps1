# HBS Console tray icon (Windows).
#
# Background server + tray menu: Open HBS Console / Open in browser / Start /
# Stop / Restart / Logs / Data folder / Update / Launch at login / Quit.
# Installed into the Startup folder by scripts/install.ps1 (optional);
# start it by hand with `hbs tray`. Closing the window leaves HBS in the tray.
$ErrorActionPreference = "SilentlyContinue"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# single instance
$created = $false
$mutex = New-Object System.Threading.Mutex($true, "HBS-Tray-Mutex", [ref]$created)
if (-not $created) { exit 0 }

$InstallDir = if ($env:HBS_INSTALL_DIR) {
  $env:HBS_INSTALL_DIR
} else {
  $derived = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { $null }
  if ($derived -and ((Test-Path (Join-Path $derived "data")) -or (Test-Path (Join-Path $derived "app")))) { $derived } else { Join-Path $env:LOCALAPPDATA "HBS" }
}
$AppDir = Join-Path $InstallDir "app"
$DataDir = Join-Path $InstallDir "data"
$ScriptsDir = if (Test-Path (Join-Path $InstallDir "installer\hbs.ps1")) { Join-Path $InstallDir "installer" } else { Join-Path $InstallDir "scripts" }
$PidFile = Join-Path $DataDir "server.pid"
$LogFile = Join-Path $DataDir "server.log"
$AutostartLnk = Join-Path ([Environment]::GetFolderPath("Startup")) "HBS Console Tray.lnk"

function Get-Port {
  $envFile = Join-Path $DataDir "hbs.env"
  if (Test-Path $envFile) {
    $line = Get-Content $envFile | Select-String "^PORT=" | Select-Object -First 1
    if ($line) { return (($line -replace "^PORT=", "").Trim()) }
  }
  return "3000"
}
function Server-Running { return (Test-Path $PidFile) -and (Get-Process -Id (Get-Content $PidFile) -ErrorAction SilentlyContinue) }
function Hbs([string]$action) {
  $cmd = Join-Path $ScriptsDir "hbs.ps1"
  if (-not (Test-Path $cmd)) { $cmd = Join-Path $AppDir "scripts\hbs.ps1" }
  # Start-Process (never a pipeline call: the engine would inherit the tray's
  # pipe handles) plus WaitForExit on the launcher only - PowerShell 5's -Wait
  # waits for the whole process tree, and the dashboard engine never exits,
  # which would freeze the tray's message loop for good.
  $child = Start-Process -FilePath "powershell" -WindowStyle Hidden -PassThru -ArgumentList @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $cmd, $action
  )
  $null = $child.WaitForExit(45 * 1000)
}
function Desktop-App {
  # NSIS writes InstallLocation wrapped in quotes - strip them before using it.
  $key = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "HBS Console" -and $_.Publisher -eq "PotenFYR Studios" -and $_.InstallLocation } |
    Select-Object -First 1
  foreach ($c in @(
      $(if ($key -and $key.InstallLocation) { Join-Path ($key.InstallLocation.Trim('"')) "hbs-console.exe" }),
      (Join-Path $env:LOCALAPPDATA "HBS Console\hbs-console.exe"),
      (Join-Path $env:LOCALAPPDATA "Programs\HBS Console\hbs-console.exe"))) {
    if ($c -and (Test-Path $c)) { return $c }
  }
  return $null
}
function Open-Hbs {
  if (-not (Server-Running)) { Hbs "start" | Out-Null }
  $app = Desktop-App
  if ($app) { Start-Process $app }
  else { Start-Process "http://127.0.0.1:$(Get-Port)" }
}
function Show-Balloon([string]$text, [string]$title = "HBS Console") {
  $notify.BalloonTipTitle = $title
  $notify.BalloonTipText = $text
  $notify.ShowBalloonTip(2500)
}

$form = New-Object System.Windows.Forms.Form
$form.WindowState = "Minimized"
$form.ShowInTaskbar = $false
$form.FormBorderStyle = "FixedToolWindow"
$form.Opacity = 0

$notify = New-Object System.Windows.Forms.NotifyIcon
$iconPath = Join-Path $InstallDir "share\icon.ico"
if (-not (Test-Path $iconPath)) { $iconPath = Join-Path $AppDir "desktop\icons\icon.ico" }
if (Test-Path $iconPath) {
  try { $notify.Icon = New-Object System.Drawing.Icon($iconPath) } catch { $notify.Icon = [System.Drawing.SystemIcons]::Shield }
} else {
  $notify.Icon = [System.Drawing.SystemIcons]::Shield
}
$notify.Text = "HBS Console"
$notify.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$itemOpen = $menu.Items.Add("Open HBS Console")
$itemOpen.Add_Click({ Open-Hbs }.GetNewClosure())
$itemBrowser = $menu.Items.Add("Open in browser")
$itemBrowser.Add_Click({ Hbs "start" | Out-Null; Start-Process "http://127.0.0.1:$(Get-Port)" })

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$itemStart = $menu.Items.Add("Start server")
$itemStart.Add_Click({ Hbs "start" | Out-Null; Show-Balloon "Server started." })
$itemStop = $menu.Items.Add("Stop server")
$itemStop.Add_Click({ Hbs "stop" | Out-Null; Show-Balloon "Server stopped." })
$itemRestart = $menu.Items.Add("Restart server")
$itemRestart.Add_Click({ Hbs "restart" | Out-Null; Show-Balloon "Server restarted." })

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$itemLogs = $menu.Items.Add("View logs")
$itemLogs.Add_Click({ if (Test-Path $LogFile) { Start-Process notepad $LogFile } else { Show-Balloon "No log file yet." } })
$itemData = $menu.Items.Add("Open data folder")
$itemData.Add_Click({ Start-Process explorer $DataDir })
$itemUpdate = $menu.Items.Add("Update HBS")
$itemUpdate.Add_Click({ Hbs "update" | Out-Null; Show-Balloon "Update finished." })

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$itemLogin = $menu.Items.Add("Launch at login")
$itemLogin.CheckOnClick = $true
$itemLogin.Checked = Test-Path $AutostartLnk
$itemLogin.Add_Click({
  if ($itemLogin.Checked) { Hbs "autostart" "on" | Out-Null; Show-Balloon "Will start with Windows." }
  else { Hbs "autostart" "off" | Out-Null; Show-Balloon "Autostart disabled." }
}.GetNewClosure())

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$itemExit = $menu.Items.Add("Exit (keep server running)")
$itemExit.Add_Click({
  $notify.Visible = $false
  $mutex.ReleaseMutex()
  $form.Close()
}.GetNewClosure())
$itemQuit = $menu.Items.Add("Quit and stop server")
$itemQuit.Add_Click({
  Hbs "stop" | Out-Null
  $notify.Visible = $false
  $mutex.ReleaseMutex()
  $form.Close()
}.GetNewClosure())

$notify.ContextMenuStrip = $menu
$notify.Add_Click({
  if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Open-Hbs }
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 10000
$timer.Add_Tick({
  if (Server-Running) { $notify.Text = "HBS Console - running (port $(Get-Port))" }
  else { $notify.Text = "HBS Console - stopped" }
})
$timer.Start()

if (-not (Server-Running)) { Hbs "start" | Out-Null }
Show-Balloon "HBS Console is watching the background server. Click to open."

$form.ShowDialog() | Out-Null
