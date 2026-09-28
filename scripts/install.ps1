# HBS Console installer for Windows.
#
#   irm https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.ps1 | iex
#
# Zero dependencies by design: the console engine ships as a single prebuilt
# native binary (no Bun, no Node, no Rust - nothing to install first). This
# script downloads the right release asset for your architecture, verifies its
# checksum, and wires the console into Windows: Start menu entry, desktop
# shortcut, tray icon, launch-at-login and an entry under Settings > Apps.
#
# Interactive runs open a short wizard (arrow keys / number keys). Piped runs
# (irm | iex) never prompt and install the recommended full setup; every
# choice also has a flag, so the same script runs unattended in CI.
#
# Options:
#   -Mode full|dashboard|desktop  what to install
#                                 full:      engine + tray + shortcuts + desktop
#                                            app  (recommended)
#                                 dashboard: engine + tray + shortcuts, no
#                                            desktop app
#                                 desktop:   engine + desktop app only; the app
#                                            owns the tray and shortcuts
#   -InstallDir PATH    install root   (default: %LOCALAPPDATA%\HBS)
#   -Port N             dashboard port (default: 3000)
#   -DesktopIcon / -NoDesktopIcon   desktop shortcut
#   -Autostart / -NoAutostart       start at login
#   -Tray / -NoTray                 tray icon (dashboard mode)
#   -DesktopApp / -NoDesktopApp     HBS Console desktop app
#   -Expose             bind ALL interfaces (0.0.0.0) so the LAN can reach it
#   -BindAddress ADDR   bind one address (implies exposure for that address)
#   -Local              loopback only, remove any previous exposure (default)
#   -TlsCert PATH       TLS certificate (with -TlsKey)
#   -TlsKey PATH        TLS private key
#   -Tls                enable HTTPS (self-signs when openssl is available)
#   -Yes                accept defaults, never prompt
#   -NoStart            install but do not start anything
#   -Tag vX.Y.Z         install a specific release (default: latest)
#   -Uninstall [-Purge] remove the app (and with -Purge, the data)
#   -RepoUrl / -Branch  override the source repository (for -FromSource-style
#                       reinstalls of a checkout)
param(
  [string]$InstallDir = "$env:LOCALAPPDATA\HBS",
  [int]$Port = 3000,
  [string]$Mode = "",
  [switch]$DesktopIcon,
  [switch]$NoDesktopIcon,
  [switch]$Autostart,
  [switch]$NoAutostart,
  [switch]$Tray,
  [switch]$NoTray,
  [switch]$DesktopApp,
  [switch]$NoDesktopApp,
  [string]$BindAddress = $env:HBS_HOST,
  [switch]$Expose,
  [switch]$Local,
  [string]$TlsCert = $env:HBS_TLS_CERT,
  [string]$TlsKey = $env:HBS_TLS_KEY,
  [switch]$Tls,
  [switch]$Yes,
  [switch]$NoStart,
  [switch]$Uninstall,
  [switch]$Purge,
  [string]$Tag = $env:HBS_RELEASE_TAG,
  [string]$AssetBase = $env:HBS_ASSET_BASE,
  [string]$RepoUrl = "https://github.com/PotenFYR-Studios/HBS-Tool.git",
  [string]$Branch = "main"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest is 10x slower otherwise
if ($env:HBS_INSTALL_DIR) { $InstallDir = $env:HBS_INSTALL_DIR }
$AppDir = Join-Path $InstallDir "app"
$DataDir = Join-Path $InstallDir "data"
$BinDir = Join-Path $InstallDir "bin"
$ScriptsDir = Join-Path $InstallDir "installer"
$ShareDir = Join-Path $InstallDir "share"
$UninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\HBSConsole"
$ReleaseBase = $env:HBS_RELEASE_URL
if (-not $ReleaseBase) { $ReleaseBase = "https://github.com/PotenFYR-Studios/HBS-Tool/releases" }
$RawBase = $env:HBS_REPO_RAW
if (-not $RawBase) { $RawBase = "https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main" }

# Child processes (hbs.ps1, the tray, the uninstaller) resolve their install
# root from HBS_INSTALL_DIR, so a custom -InstallDir must travel with them.
$env:HBS_INSTALL_DIR = $InstallDir

# ------------------------------------------------------------------ styling
$VT = $false
try {
  if ($PSVersionTable.PSVersion.Major -ge 7 -or $Host.UI.SupportsVirtualTerminal) { $VT = $true }
} catch { $VT = $false }
if ($env:NO_COLOR) { $VT = $false }
$E = [char]27

function C([string]$code, [string]$text) { if ($VT) { "$E[${code}m$text$E[0m" } else { $text } }
function Step([string]$m) { Write-Host ("  " + (C "38;5;117" ">") + " $m") }
function Ok([string]$m) { Write-Host ("  " + (C "38;5;114" "v") + " $m") }
function Warn([string]$m) { Write-Host ("  " + (C "38;5;221" "!") + " $m") }
function Note([string]$m) { Write-Host ("    " + (C "2" $m)) }
function Blank { Write-Host "" }
function Die([string]$m) { Write-Host ""; Write-Host ("  " + (C "38;5;203" ("x " + $m))); Write-Host ""; exit 1 }
function Banner {
  Write-Host ""
  Write-Host ("  " + (C "1;38;5;141" "  _   _ ____  ____"))
  Write-Host ("  " + (C "1;38;5;205" " | | | | __ )/ ___|") + "   " + (C "1" "HBS") + " " + (C "2" "host baseline security reviews"))
  Write-Host ("  " + (C "1;38;5;205" " | |_| |  _ \___ \ ") + "   " + (C "2" "read-only scans - sealed reports"))
  Write-Host ("  " + (C "1;38;5;209" " |  _  | |_) |___) |"))
  Write-Host ("  " + (C "1;38;5;209" " |_| |_|____/|____/") + "   " + (C "2" "installer for Windows"))
  Write-Host ""
}

$Interactive = -not $Yes
function Ask([string]$q, [string]$default) {
  if (-not $Interactive) { return $default }
  $shown = ""
  if ($default) { $shown = " [$default]" }
  Write-Host ("  " + (C "38;5;205" "?") + " " + (C "1" $q) + $shown + " ") -NoNewline
  $a = Read-Host
  if ([string]::IsNullOrWhiteSpace($a)) { return $default }
  return $a.Trim()
}
function AskYn([string]$q, [bool]$defaultYes) {
  if (-not $Interactive) { return $defaultYes }
  $d = "n"
  if ($defaultYes) { $d = "y" }
  $a = Ask "$q (y/n)" $d
  if ([string]::IsNullOrEmpty($a)) { return $defaultYes }
  return ($a.Substring(0, 1).ToLower() -eq "y")
}

# Arrow-key menu (number keys work too). Returns the 1-based choice; the first
# option when non-interactive.
function Choose([string]$prompt, [string[]]$options) {
  if (-not $Interactive) { return 1 }
  $sel = 1
  $redraw = $false
  try {
    while ($true) {
      if ($redraw) {
        [Console]::CursorTop = [Console]::CursorTop - ($options.Count + 1)
      }
      Write-Host (("  " + (C "38;5;205" "?") + " " + (C "1" $prompt) + " " + (C "2" "(arrows / 1-$($options.Count), Enter)") + $E + "[K"))
      for ($i = 0; $i -lt $options.Count; $i++) {
        if ($i + 1 -eq $sel) { Write-Host ("  " + (C "38;5;205" "> ") + (C "1" $options[$i]) + $E + "[K") }
        else { Write-Host ("    " + (C "2" $options[$i]) + $E + "[K") }
      }
      $redraw = $true
      $key = [Console]::ReadKey($true)
      if ($key.Key -eq "UpArrow" -and $sel -gt 1) { $sel-- }
      elseif ($key.Key -eq "DownArrow" -and $sel -lt $options.Count) { $sel++ }
      elseif ($key.Key -eq "Enter") { break }
      elseif ($key.KeyChar -ge "1" -and [int]$key.KeyChar - [int][char]"1" -lt $options.Count) {
        $sel = [int]$key.KeyChar - [int][char]"1" + 1
        break
      }
    }
  } catch {
    # Host without a real console (IDE terminal, redirected): fall back to text.
    for ($i = 0; $i -lt $options.Count; $i++) { Write-Host ("    " + ($i + 1) + ") " + $options[$i]) }
    $a = Ask $prompt "1"
    $sel = 1
    if ($a -match "^[1-9]$" -and [int]$a -le $options.Count) { $sel = [int]$a }
  }
  return $sel
}

function New-Shortcut([string]$path, [string]$arguments, [string]$description, [string]$icon, [string]$target = "powershell.exe") {
  $shell = New-Object -ComObject WScript.Shell
  $lnk = $shell.CreateShortcut($path)
  $lnk.TargetPath = $target
  $lnk.Arguments = $arguments
  $lnk.WorkingDirectory = $InstallDir
  $lnk.Description = $description
  if ($icon -and (Test-Path ($icon -replace ",.*$", ""))) { $lnk.IconLocation = $icon }
  $lnk.Save()
}

function Decompress-Gzip([string]$gzPath, [string]$outPath) {
  $input = [IO.File]::OpenRead($gzPath)
  try {
    $gz = New-Object IO.Compression.GzipStream($input, [IO.Compression.CompressionMode]::Decompress)
    try {
      $output = [IO.File]::Create($outPath)
      try { $gz.CopyTo($output) } finally { $output.Dispose() }
    } finally { $gz.Dispose() }
  } finally { $input.Dispose() }
}

function Get-Sha256([string]$path) {
  (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLower()
}

function Get-LatestTag {
  # The releases/latest redirect carries the tag - no API, no rate limit.
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseBase/latest" -Method Head -MaximumRedirection 0 -ErrorAction Stop
    if ($r.Headers["Location"]) { return ([string]@($r.Headers["Location"])[0]).TrimEnd("/").Split("/")[-1] }
  } catch {
    $resp = $_.Exception.Response
    if ($resp -and $resp.Headers) {
      $loc = $resp.Headers["Location"]
      if ($loc) { return ([string]@($loc)[0]).TrimEnd("/").Split("/")[-1] }
    }
  }
  try {
    $rel = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/PotenFYR-Studios/HBS-Tool/releases/latest" -Headers @{ "User-Agent" = "hbs-installer" }
    return $rel.tag_name
  } catch { return $null }
}

function Get-Manifest([string]$tag) {
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("hbs-manifest-" + [IO.Path]::GetRandomFileName() + ".json")
  $url = if ($AssetBase) { "$AssetBase/manifest.json" } else { "$ReleaseBase/download/$tag/manifest.json" }
  try {
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp -ErrorAction Stop
    return (Get-Content $tmp -Raw | ConvertFrom-Json)
  } catch {
    return $null
  }
}

function Get-AssetSha($manifest, [string]$name) {
  $entry = $manifest.files | Where-Object { $_.name -eq $name } | Select-Object -First 1
  if ($entry) { return $entry.sha256 }
  return $null
}

# Set/replace or remove one KEY= line in hbs.env. Comments and unknown keys
# survive, so the settings page, the tray and the engine stay in agreement.
function Set-EnvLine([string]$file, [string]$key, [string]$value) {
  $lines = @()
  if (Test-Path $file) { $lines = @(Get-Content $file) }
  $lines = @($lines | Where-Object { $_ -notmatch ("^" + [regex]::Escape($key) + "=") })
  if ($null -ne $value) { $lines += "$key=$value" }
  if ($lines.Count -gt 0) { Set-Content -Path $file -Value $lines -Encoding ASCII }
  else { Set-Content -Path $file -Value "" -Encoding ASCII }
}
function Apply-NetworkEnv([string]$file, [string]$bindHost, [string]$cert, [string]$key) {
  Set-EnvLine $file "HOST" $(if ($bindHost) { $bindHost } else { $null })
  if ($cert -and $key) {
    Set-EnvLine $file "HBS_TLS_CERT" $cert
    Set-EnvLine $file "HBS_TLS_KEY" $key
  } else {
    Set-EnvLine $file "HBS_TLS_CERT" $null
    Set-EnvLine $file "HBS_TLS_KEY" $null
  }
}

# ---------------------------------------------------------------- uninstall
function Remove-Integration {
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
  $startup = [Environment]::GetFolderPath("Startup")
  $programs = [Environment]::GetFolderPath("Programs")
  $desktop = [Environment]::GetFolderPath("Desktop")
  Remove-Item (Join-Path $startup "HBS Console Tray.lnk") -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $programs "HBS Console (dashboard).lnk") -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $programs "HBS Console.lnk") -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $programs "HBS Console (tray).lnk") -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $desktop "HBS Console.lnk") -Force -ErrorAction SilentlyContinue
  Remove-Item $UninstallKey -Recurse -Force -ErrorAction SilentlyContinue
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $parts = @($userPath -split ";" | Where-Object { $_ })
  if ($parts -contains $BinDir) {
    $kept = $parts | Where-Object { $_ -ne $BinDir }
    [Environment]::SetEnvironmentVariable("Path", ($kept -join ";"), "User")
  }
  # The engine process outlives the console that started it, and its command
  # line does not mention the install dir - match on the image path instead.
  Get-Process hbs-server -ErrorAction SilentlyContinue |
    Where-Object { try { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) } catch { $false } } |
    Stop-Process -Force -ErrorAction SilentlyContinue
}

if ($Uninstall) {
  Banner
  Step "Removing HBS Console..."
  $desktopUninstaller = Join-Path $ScriptsDir "install-desktop.ps1"
  if (-not (Test-Path $desktopUninstaller)) { $desktopUninstaller = Join-Path $PSScriptRoot "install-desktop.ps1" }
  if (Test-Path $desktopUninstaller) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $desktopUninstaller -Uninstall -Yes -ErrorAction SilentlyContinue
  }
  Remove-Integration
  if ($Purge) {
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Ok "removed $InstallDir (app and data)"
  } else {
    Remove-Item $AppDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $BinDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $ScriptsDir -Recurse -Force -ErrorAction SilentlyContinue
    Ok "removed the app; your reports and database stay in $DataDir"
    Note "re-run with -Uninstall -Purge to delete the data too"
  }
  Blank; Ok "HBS Console uninstalled. Thanks for using HBS."; Blank
  exit 0
}

# ------------------------------------------------------------------- wizard
Banner
Step "Checking your system..."
$arch = "x64"
$archTarget = "bun-windows-x64"
if ([Environment]::Is64BitOperatingSystem) {
  if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1).Architecture -eq 12) {
    $arch = "arm64 (x64 emulation)"
  }
} else {
  $arch = "x86"; $archTarget = ""
}
$os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
if (-not $os) { $os = "Windows" }
Ok "$os - $arch"
if (-not $archTarget) { Die "no prebuilt server exists for 32-bit Windows - use a 64-bit Windows host" }
if ($arch -like "arm64*") { Warn "Windows on ARM: the engine runs under x64 emulation for now" }

# Mode defaults; explicit flags always win.
switch ($Mode) {
  "full"      { $defAuto = $true;  $defTray = $true;  $defApp = $true;  $defIcon = $true }
  "dashboard" { $defAuto = $true;  $defTray = $true;  $defApp = $false; $defIcon = $true }
  "desktop"   { $defAuto = $true;  $defTray = $false; $defApp = $true;  $defIcon = $false }
  ""          { $defAuto = $true;  $defTray = $true;  $defApp = $true;  $defIcon = $true }
  default { Die "invalid -Mode: $Mode (full | dashboard | desktop)" }
}

if ($Interactive -and -not $Mode) {
  Blank
  $pick = Choose "What do you want to install?" @(
    "Full install - everything (recommended)",
    "Dashboard only - web console + tray",
    "Desktop app only - the native app (includes the engine)")
  $Mode = @("full", "dashboard", "desktop")[$pick - 1]
  switch ($Mode) {
    "full"      { $defAuto = $true;  $defTray = $true;  $defApp = $true;  $defIcon = $true }
    "dashboard" { $defAuto = $true;  $defTray = $true;  $defApp = $false; $defIcon = $true }
    "desktop"   { $defAuto = $true;  $defTray = $false; $defApp = $true;  $defIcon = $false }
  }
}
if (-not $Mode) { $Mode = "full" }

if ($Interactive) {
  Blank
  Write-Host ("  " + (C "1;38;5;141" "Customize") + "  " + (C "2" "(Enter accepts the suggested value)"))
  Blank
  $InstallDir = Ask "Install location" $InstallDir
  $AppDir = Join-Path $InstallDir "app"; $DataDir = Join-Path $InstallDir "data"
  $BinDir = Join-Path $InstallDir "bin"; $ScriptsDir = Join-Path $InstallDir "installer"
  $ShareDir = Join-Path $InstallDir "share"
  $Port = [int](Ask "Dashboard port" "$Port")
  $wantIcon = AskYn "Create a desktop shortcut?" $defIcon
  if ($Mode -ne "desktop") { $wantTray = AskYn "Install the tray icon?" $defTray }
  if ($Mode -ne "dashboard") { $wantApp = AskYn "Install the HBS Console desktop app?" $defApp }
  $wantAutostart = AskYn "Start HBS automatically when you sign in?" $defAuto
} else {
  Note "non-interactive run: defaults used (see the script header for every flag)"
  $wantIcon = $defIcon; $wantTray = $defTray; $wantApp = $defApp; $wantAutostart = $defAuto
}
if ($DesktopIcon) { $wantIcon = $true }
if ($NoDesktopIcon) { $wantIcon = $false }
if ($Autostart) { $wantAutostart = $true }
if ($NoAutostart) { $wantAutostart = $false }
if ($Tray) { $wantTray = $true }
if ($NoTray) { $wantTray = $false }
if ($DesktopApp) { $wantApp = $true }
if ($NoDesktopApp) { $wantApp = $false }
if ($null -eq $wantIcon) { $wantIcon = $defIcon }
if ($null -eq $wantTray) { $wantTray = $defTray }
if ($null -eq $wantApp) { $wantApp = $defApp }
if ($null -eq $wantAutostart) { $wantAutostart = $defAuto }
$env:HBS_INSTALL_DIR = $InstallDir

# ---------------------------------------------------------- network / TLS
# Optional and off by default. hbs.env is only rewritten when the operator
# actually decided, so an unattended update never clobbers a LAN/TLS setup.
$networkChosen = $false
if ($Local) { $BindAddress = ""; $TlsCert = ""; $TlsKey = ""; $networkChosen = $true }
if ($Expose) { $BindAddress = "0.0.0.0"; $networkChosen = $true }
if ($BindAddress) { $networkChosen = $true }
if ($Tls) { $networkChosen = $true }

if ($Interactive) {
  $networkChosen = $true
  if (-not $BindAddress) {
    if (AskYn "Publish the dashboard on your local network?" $false) {
      $BindAddress = Ask "Bind address (0.0.0.0 = every interface)" "0.0.0.0"
    }
  }
  if ($BindAddress -or $Tls) {
    if (-not $TlsCert -and ($Tls -or (AskYn "Serve HTTPS with TLS? (recommended on an untrusted network)" $false))) {
      $TlsCert = Ask "TLS certificate path" (Join-Path $DataDir "tls\hbs.crt")
      $TlsKey = Ask "TLS private key path" (Join-Path $DataDir "tls\hbs.key")
    }
  }
}
if ($Tls -and -not $TlsCert) {
  $TlsCert = Join-Path $DataDir "tls\hbs.crt"
  $TlsKey = Join-Path $DataDir "tls\hbs.key"
}
if ($TlsCert -or $TlsKey) {
  if (-not ($TlsCert -and $TlsKey)) { Die "TLS needs both -TlsCert and -TlsKey" }
  if (-not (Test-Path $TlsCert) -or -not (Test-Path $TlsKey)) {
    if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
      Die "certificate $TlsCert not found and openssl is unavailable - pass existing -TlsCert/-TlsKey paths"
    }
    Step "Generating a self-signed TLS certificate..."
    New-Item -ItemType Directory -Force -Path (Split-Path $TlsCert -Parent), (Split-Path $TlsKey -Parent) | Out-Null
    & openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 -keyout $TlsKey -out $TlsCert `
      -subj "/CN=hbs-console" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>$null
    if ($LASTEXITCODE -ne 0) { Die "could not generate a certificate at $TlsCert" }
    Ok "Self-signed certificate: $TlsCert"
  }
}

Blank
Step "Installing into $InstallDir (port $Port, mode: $Mode)"
Blank

# -------------------------------------------------------------- the engine
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, $BinDir, $ScriptsDir, $ShareDir | Out-Null

$serverExe = Join-Path $BinDir "hbs-server.exe"
if ($Tag -and $Tag -notlike "v*") { $Tag = "v$Tag" }

Step "Fetching the release..."
$relTag = $Tag
if (-not $relTag -and -not $AssetBase) {
  $relTag = Get-LatestTag
  if (-not $relTag) { Die "could not resolve the latest release (offline? pass -Tag)" }
}
if (-not $relTag) { $relTag = "local" }   # AssetBase mirror: tag is cosmetic
$manifest = Get-Manifest $relTag
if (-not $manifest) { Die "could not read the release manifest for $relTag" }
$version = $manifest.version
$assetName = "hbs-server-$version-$archTarget.gz"
$sha = Get-AssetSha $manifest $assetName
if (-not $sha) { Die "release $relTag has no $assetName - see the release page for supported platforms" }
$assetUrl = if ($AssetBase) { "$AssetBase/$assetName" } else { "$ReleaseBase/download/$relTag/$assetName" }
$gzPath = Join-Path $env:TEMP $assetName
$sizeMb = 0
$entry = $manifest.files | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
if ($entry) { $sizeMb = [int]($entry.bytes / 1MB) }
Step "Downloading the console engine ($sizeMb MB)..."
Invoke-WebRequest -UseBasicParsing -Uri $assetUrl -OutFile $gzPath -ErrorAction Stop
if ((Get-Sha256 $gzPath) -ne $sha) { Remove-Item $gzPath -Force -ErrorAction SilentlyContinue; Die "checksum mismatch - download corrupted; re-run the installer" }
Ok "Checksum verified"
Decompress-Gzip $gzPath $serverExe
Remove-Item $gzPath -Force -ErrorAction SilentlyContinue
Ok "Console engine: $serverExe"

# ------------------------------------------------------- companion scripts
function Save-Companion([string]$name) {
  # Keep the control scripts next to the install so hbs update/uninstall work
  # with no repo clone. Sibling files win (running from a checkout).
  $sibling = Join-Path $PSScriptRoot $name
  $dest = Join-Path $ScriptsDir $name
  if (Test-Path $sibling) { Copy-Item $sibling $dest -Force; return $true }
  if ($AssetBase -and (Test-Path (Join-Path $AssetBase $name))) { Copy-Item (Join-Path $AssetBase $name) $dest -Force; return $true }
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "$RawBase/scripts/$name" -OutFile $dest -ErrorAction Stop
    return $true
  } catch {
    $old = Join-Path $AppDir "scripts\$name"
    if (Test-Path $old) { Copy-Item $old $dest -Force; return $true }
  }
  return $false
}
foreach ($f in @("install.ps1", "install-desktop.ps1", "hbs.ps1", "tray-windows.ps1", "uninstall.ps1")) {
  Save-Companion $f | Out-Null
}

# Brand icon for the shortcuts (falls back to a system icon when offline).
$iconPath = Join-Path $ShareDir "icon.ico"
if (-not (Test-Path $iconPath)) {
  $siblingIcon = Join-Path $PSScriptRoot "..\desktop\icons\icon.ico"
  if (Test-Path $siblingIcon) { Copy-Item $siblingIcon $iconPath -Force }
  else {
    try { Invoke-WebRequest -UseBasicParsing -Uri "$RawBase/desktop/icons/icon.ico" -OutFile $iconPath -ErrorAction Stop } catch { }
  }
}
if (-not (Test-Path $iconPath)) { $iconPath = "$env:SystemRoot\System32\shell32.dll,77" }

# ---------------------------------------------------------------- config
$envFile = Join-Path $DataDir "hbs.env"
if (-not (Test-Path $envFile)) {
  @(
    "# HBS Console environment (edit to change the port etc.)",
    "PORT=$Port",
    "HBS_DATA_ROOT=$DataDir",
    "# First launch opens the console setup wizard, where you choose the",
    "# administrator account. Set HBS_BOOTSTRAP_ADMIN=true here (with",
    "# HBS_ADMIN_USERNAME / HBS_ADMIN_PASSWORD) for unattended installs."
  ) | Set-Content -Encoding ASCII $envFile
  Ok "Wrote $envFile (edit it to change the port)"
  $firstRun = $true
} else {
  Ok "Keeping existing $envFile"
  $firstRun = $false
}

# Persist this run's hosting choice, or read back the previous one for the
# summary and the health probe.
if ($networkChosen) {
  Apply-NetworkEnv $envFile $(if ($BindAddress) { $BindAddress } else { $null }) $TlsCert $TlsKey
  if ($BindAddress) {
    Ok "Dashboard listens on ${BindAddress}:$Port$(if ($TlsCert) { ' over HTTPS' })"
  } else {
    Ok "Dashboard is loopback-only (127.0.0.1)"
  }
} elseif (Test-Path $envFile) {
  $envLines = @(Get-Content $envFile)
  $hostLine = $envLines | Where-Object { $_ -match "^HOST=" } | Select-Object -First 1
  if ($hostLine) { $BindAddress = ($hostLine -replace "^HOST=", "").Trim() }
  $certLine = $envLines | Where-Object { $_ -match "^HBS_TLS_CERT=" } | Select-Object -First 1
  if ($certLine) { $TlsCert = ($certLine -replace "^HBS_TLS_CERT=", "").Trim() }
}
$consoleScheme = if ($TlsCert) { "https" } else { "http" }
$probeHost = if ($BindAddress -and $BindAddress -notin @("0.0.0.0", "::", "*")) { $BindAddress } else { "127.0.0.1" }
$consoleUrl = "${consoleScheme}://${probeHost}:$Port"
if ($consoleScheme -eq "https") {
  # Local self-check only: the certificate may be self-signed.
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

# ------------------------------------------------------------- CLI + PATH
@"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "$ScriptsDir\hbs.ps1" %*
"@ | Set-Content -Encoding ASCII (Join-Path $BinDir "hbs.cmd")
@"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$ScriptsDir\hbs.ps1" app
"@ | Set-Content -Encoding ASCII (Join-Path $BinDir "hbs-app.cmd")

# Exact-match edit of the user PATH: a wildcard test silently skipped this
# write on hosts whose PATH is long or where the install dir already appeared
# inside an unrelated entry.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathParts = @($userPath -split ";" | Where-Object { $_ })
if ($pathParts -notcontains $BinDir) {
  $pathParts += $BinDir
  [Environment]::SetEnvironmentVariable("Path", ($pathParts -join ";"), "User")
  Ok "Added $BinDir to your PATH (new terminals only)"
} else {
  Ok "$BinDir is already on your PATH"
}
Ok "Control CLI installed: hbs"

# ------------------------------------------------- shortcuts / tray / login
$programs = [Environment]::GetFolderPath("Programs")
$desktop = [Environment]::GetFolderPath("Desktop")
$startup = [Environment]::GetFolderPath("Startup")
# Shortcuts must work for custom -InstallDir values too: they export
# HBS_INSTALL_DIR before calling the control scripts.
$envPrefix = "`$env:HBS_INSTALL_DIR='$InstallDir'; "
$openArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$envPrefix& '$ScriptsDir\hbs.ps1' app`""
$trayArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$envPrefix& '$ScriptsDir\tray-windows.ps1'`""
$startArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$envPrefix& '$ScriptsDir\hbs.ps1' start`""

New-Shortcut -path (Join-Path $programs "HBS Console (dashboard).lnk") -arguments $openArgs `
  -description "Open the HBS Console dashboard" -icon $iconPath
Ok "Start menu entry installed (HBS Console (dashboard))"

if ($wantTray) {
  New-Shortcut -path (Join-Path $programs "HBS Console (tray).lnk") -arguments $trayArgs `
    -description "HBS Console background server and tray icon" -icon $iconPath
  Ok "Tray helper installed ('hbs tray')"
}

if ($wantAutostart) {
  if ($wantTray) {
    New-Shortcut -path (Join-Path $startup "HBS Console Tray.lnk") -arguments $trayArgs `
      -description "Starts the HBS Console background server at login" -icon $iconPath
    Ok "Tray starts with Windows"
  } else {
    New-Shortcut -path (Join-Path $startup "HBS Console Tray.lnk") `
      -arguments $startArgs `
      -description "Starts the HBS Console background server at login" -icon $iconPath
    Ok "Dashboard starts with Windows"
  }
} else {
  Note "autostart: off - turn it on later with 'hbs autostart on'"
}

# ------------------------------------------------------ apps & features entry
try {
  New-Item -Path $UninstallKey -Force | Out-Null
  $uninstaller = Join-Path $ScriptsDir "uninstall.ps1"
  Set-ItemProperty -Path $UninstallKey -Name "DisplayName" -Value "HBS Console (dashboard)"
  Set-ItemProperty -Path $UninstallKey -Name "DisplayVersion" -Value "$version"
  Set-ItemProperty -Path $UninstallKey -Name "Publisher" -Value "PotenFYR Studios"
  Set-ItemProperty -Path $UninstallKey -Name "InstallLocation" -Value $InstallDir
  Set-ItemProperty -Path $UninstallKey -Name "URLInfoAbout" -Value "https://hbs-tool.docs.potenfyr.in"
  Set-ItemProperty -Path $UninstallKey -Name "DisplayIcon" -Value $iconPath
  Set-ItemProperty -Path $UninstallKey -Name "UninstallString" -Value "powershell -NoProfile -ExecutionPolicy Bypass -File `"$uninstaller`" -InstallDir `"$InstallDir`""
  Set-ItemProperty -Path $UninstallKey -Name "QuietUninstallString" -Value "powershell -NoProfile -ExecutionPolicy Bypass -File `"$uninstaller`" -InstallDir `"$InstallDir`" -Purge -Yes"
  Ok "Registered in Settings > Apps (uninstallable like any program)"
} catch {
  Warn "could not register the uninstaller entry: $_"
}

# -------------------------------------------------------------------- start
if (-not $NoStart -and $Mode -ne "desktop") {
  Step "Starting HBS Console..."
  # Start-Process, never a pipeline call: the engine this launches outlives
  # the call and would inherit the caller's pipe handles, so a piped
  # invocation never sees EOF. And -Wait is off-limits here: PowerShell 5
  # waits for the whole process TREE, and the engine never exits. Wait for
  # the launcher only - it returns once the dashboard answers.
  $launcher = Start-Process -FilePath "powershell" -WindowStyle Hidden -PassThru -ArgumentList @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $ScriptsDir "hbs.ps1"), "start"
  )
  $null = $launcher.WaitForExit(45 * 1000)
  $started = $false
  for ($i = 0; $i -lt 40; $i++) {
    try {
      $r = Invoke-WebRequest -UseBasicParsing -Uri $consoleUrl -TimeoutSec 2 -ErrorAction Stop
      if ($r.StatusCode -eq 200) { $started = $true; break }
    } catch { Start-Sleep -Milliseconds 250 }
  }
  if ($started) { Ok "Dashboard answering on $consoleUrl" } else { Warn "not answering yet - check 'hbs logs'" }
}

# -------------------------------------------------------------- desktop app
$appInstalled = $false
if ($wantApp) {
  Blank
  $desktopInstaller = Join-Path $ScriptsDir "install-desktop.ps1"
  if (Test-Path $desktopInstaller) {
    $dArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $desktopInstaller, "-InstallDir", $InstallDir, "-Port", "$Port", "-Yes")
    if ($relTag) { $dArgs += @("-Tag", $relTag) }
    if ($AssetBase) { $dArgs += @("-AssetBase", $AssetBase) }
    & powershell @dArgs
    if ($LASTEXITCODE -eq 0) { $appInstalled = $true }
  }
  if ($appInstalled) {
    # Belt and braces: NSIS creates the desktop icon; if the user (or a
    # policy) suppressed it, make one pointing at the installed app
    # (Tauri's currentUser NSIS layout is %LOCALAPPDATA%\<product>).
    $appExe = Join-Path $env:LOCALAPPDATA "HBS Console\hbs-console.exe"
    $deskLnk = Join-Path $desktop "HBS Console.lnk"
    if (-not (Test-Path $deskLnk) -and (Test-Path $appExe)) {
      New-Shortcut -path $deskLnk -arguments "" -description "HBS Console" -icon $iconPath -target $appExe
    }
  } else {
    Warn "desktop app not installed - the web console is fully functional without it"
  }
}

# Desktop shortcut for the web console only when there is no app to own it.
if ($wantIcon -and -not $appInstalled) {
  New-Shortcut -path (Join-Path $desktop "HBS Console.lnk") -arguments $openArgs `
    -description "Open the HBS Console dashboard" -icon $iconPath
  Ok "Desktop shortcut created"
}

# Surface the tray right away - launch-at-login only takes effect next login.
# Redirect its output to files so the long-lived tray never inherits (and
# holds open) our pipe handles - a piped install would otherwise never see EOF.
if ($wantTray -and -not $appInstalled -and -not $NoStart) {
  Start-Process powershell -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $DataDir "tray.log") `
    -RedirectStandardError (Join-Path $DataDir "tray.err.log") `
    -ArgumentList @(
      "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", (Join-Path $ScriptsDir "tray-windows.ps1")
    )
  Ok "Tray icon started - look for the HBS icon in the system tray"
}

# ------------------------------------------------------------------ summary
Blank
Write-Host ("  " + (C "1;38;5;141" "+--------------------------------------------------------------+"))
Write-Host ("  " + (C "1;38;5;141" "|") + "  " + (C "1;38;5;114" "v HBS Console installed") + "                                       " + (C "1;38;5;141" "|"))
Write-Host ("  " + (C "1;38;5;141" "+--------------------------------------------------------------+"))
Blank
Write-Host ("    " + (C "1" "Console") + "     $consoleUrl")
if ($appInstalled) {
  Write-Host ("    " + (C "1" "Open it") + "     HBS Console app (desktop + tray) or any browser")
} else {
  Write-Host ("    " + (C "1" "Open it") + "     hbs app   " + (C "2" "(or just open $consoleUrl)"))
}
Write-Host ("    " + (C "1" "Controls") + "    hbs {start|stop|restart|status|logs|open|app|tray|autostart|update|uninstall}")
Write-Host ("    " + (C "1" "Install") + "     $InstallDir   " + (C "2" "(data kept separately)"))
Write-Host ("    " + (C "1" "Uninstall") + "   Settings > Apps > HBS Console (dashboard), or: hbs uninstall")
Write-Host ("    " + (C "1" "Security") + "    no default admin - the setup wizard creates it; Argon2id + peppered hashes")
Write-Host ("    " + (C "1" "AV/EDR") + "      read-only scans, no admin required - docs/security/edr-compatibility.md")
Blank
if ($BindAddress) {
  Note "Listening on ${BindAddress}:$Port$(if ($TlsCert) { ' (HTTPS; self-signed certificate)' }). Open the port in your firewall."
}
if ($firstRun) {
  Note "First launch opens the setup wizard in the console - you choose the admin account."
} else {
  Note "Existing install detected - your users and reports are untouched."
}
Note "Change the admin password after signing in under Admin -> Users."
Note "Installed from release $relTag - mode: $Mode"
Blank
