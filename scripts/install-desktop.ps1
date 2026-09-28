# Install the HBS Console desktop app (Tauri 2) on Windows.
#
#   powershell -ExecutionPolicy Bypass -File scripts\install-desktop.ps1 [-InstallDir %LOCALAPPDATA%\HBS]
#                                                                       [-Port 3000] [-Yes]
#                                                                       [-Tag vX.Y.Z] [-AssetBase DIR]
#                                                                       [-FromSource] [-Uninstall]
#
# Prefers the prebuilt installer published with the project's GitHub release
# (NSIS .exe preferred, then .msi) and can build from source with -FromSource
# when the release has no bundle yet. The dashboard keeps working in a browser
# either way.
param(
  [string]$InstallDir = "$env:LOCALAPPDATA\HBS",
  [int]$Port = 3000,
  [switch]$Yes,
  [switch]$FromSource,
  [switch]$Uninstall,
  [string]$Url = $env:HBS_DESKTOP_URL,
  [string]$Tag = $env:HBS_RELEASE_TAG,
  [string]$AssetBase = $env:HBS_ASSET_BASE,
  [string]$Repo = "PotenFYR-Studios/HBS-Tool"
)

$ErrorActionPreference = "Stop"
if ($env:HBS_INSTALL_DIR) { $InstallDir = $env:HBS_INSTALL_DIR }

function Log([string]$m) { Write-Host ("  [desktop] " + $m) }
function Note([string]$m) { Write-Host ("    " + $m) }

function Get-DesktopUninstallEntry {
  Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
    Where-Object { $_.DisplayName -and $_.DisplayName -like "HBS Console*" -and $_.Publisher -eq "PotenFYR Studios" -and $_.UninstallString -notlike "*uninstall.ps1*" } |
    Select-Object -First 1
}

if ($Uninstall) {
  Log "removing the HBS Console desktop app..."
  $entry = Get-DesktopUninstallEntry
  if ($entry) {
    if ($entry.QuietUninstallString) { cmd /c $entry.QuietUninstallString | Out-Null }
    elseif ($entry.UninstallString) { cmd /c $entry.UninstallString | Out-Null }
    # NSIS uninstallers copy themselves to %TEMP% and re-launch, so the
    # original process exits before the files and registry entry are gone.
    # Wait for the entry to disappear (bounded) before declaring victory.
    for ($i = 0; $i -lt 20 -and (Get-DesktopUninstallEntry); $i++) { Start-Sleep -Milliseconds 500 }
    Log "desktop app removed."
  } else {
    Log "desktop app is not installed."
  }
  Remove-Item "HKCU:\Software\PotenFYR\HBS-Console" -Recurse -Force -ErrorAction SilentlyContinue
  exit 0
}

function Install-FromSource {
  $src = Join-Path $InstallDir "app\desktop"
  if (-not (Test-Path $src)) { throw "no source checkout at $src - run the main installer first" }
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Rust (cargo) is required for -FromSource - install it from https://rustup.rs (needs the MSVC build tools)"
  }
  $bun = "bun"
  if (-not (Get-Command bun -ErrorAction SilentlyContinue)) {
    $candidate = Join-Path $env:USERPROFILE ".bun\bin\bun.exe"
    if (Test-Path $candidate) { $bun = $candidate } else { throw "Bun is required for -FromSource" }
  }
  Log "building the desktop app from source (this takes several minutes)..."
  Push-Location $src
  try {
    & $bun install --silent | Out-Null
    & $bun x --bun "@tauri-apps/cli@^2" build
    if ($LASTEXITCODE -ne 0) { throw "source build failed" }
  } finally { Pop-Location }
  $setup = Get-ChildItem (Join-Path $src "target\release\bundle\nsis") -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $setup) { $setup = Get-ChildItem (Join-Path $src "target\release\bundle\msi") -Filter "*.msi" -ErrorAction SilentlyContinue | Select-Object -First 1 }
  if (-not $setup) { throw "build finished but no installer bundle was found" }
  return $setup.FullName
}

Log "looking for the HBS Console desktop app for windows/x64..."

$file = $null
if (-not $FromSource) {
  if (-not $Url) {
    # Local mirror first (offline installs and CI), then the pinned or latest
    # release feed. NSIS setup.exe preferred over the .msi. Tauri names the
    # bundles after the product ("HBS Console_..."), hence the *hbs*console*
    # match; -like is case-insensitive so it covers both spellings.
    if ($AssetBase -and (Test-Path $AssetBase)) {
      $pick = Get-ChildItem $AssetBase -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*hbs*console*" -and $_.Name -like "*-setup.exe" } | Select-Object -First 1
      if (-not $pick) {
        $pick = Get-ChildItem $AssetBase -File -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -like "*hbs*console*" -and $_.Name -like "*.msi" } | Select-Object -First 1
      }
      if ($pick) { $Url = $pick.FullName }
    } else {
      try {
        $release = if ($Tag) {
          Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/tags/$Tag" -Headers @{ "User-Agent" = "hbs-installer" }
        } else {
          Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "hbs-installer" }
        }
        $assets = $release.assets | Where-Object { $_.name -like "*hbs*console*" }
        $pick = $assets | Where-Object { $_.name -like "*-setup.exe" } | Select-Object -First 1
        if (-not $pick) { $pick = $assets | Where-Object { $_.name -like "*.msi" } | Select-Object -First 1 }
        if ($pick) { $Url = $pick.browser_download_url }
      } catch {
        Note "could not query the release feed: $_"
      }
    }
  }
  if ($Url) {
    $file = Join-Path $env:TEMP ([IO.Path]::GetFileName($Url))
    Log "downloading $([IO.Path]::GetFileName($Url))..."
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $file
    } catch {
      throw "download failed: $Url ($_)"
    }
    if (-not (Test-Path $file) -or (Get-Item $file).Length -eq 0) { throw "downloaded file is empty" }
  }
}

if (-not $file) {
  if ($FromSource -or ($Yes -and -not $Url)) {
    $built = Install-FromSource
    if ($built) { $file = $built }
  } else {
    Write-Host "  No prebuilt desktop app in the latest release." -ForegroundColor Yellow
    Write-Host "  Build it from source now (needs Rust + Bun)? [y/N] " -NoNewline
    $ans = Read-Host
    if ($ans -and $ans.Substring(0, 1).ToLower() -eq "y") {
      $built = Install-FromSource
      if ($built) { $file = $built }
    }
  }
}

if (-not $file) {
  Log "no prebuilt desktop app published for this platform yet - build with -FromSource, or keep using the web console."
  exit 1
}

if ($file -like "*.msi") {
  Log "installing (msi)..."
  $p = Start-Process msiexec.exe -ArgumentList "/i", "`"$file`"", "/qn", "/norestart" -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "msi install failed with exit code $($p.ExitCode)" }
} else {
  Log "installing (NSIS, silent)..."
  $p = Start-Process $file -ArgumentList "/S" -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "installer failed with exit code $($p.ExitCode)" }
}

# Tell the app where the HBS install root lives (the NSIS bundle knows nothing
# about custom -InstallDir values): HKCU\Software\PotenFYR\HBS-Console.
try {
  New-Item -Path "HKCU:\Software\PotenFYR\HBS-Console" -Force | Out-Null
  Set-ItemProperty -Path "HKCU:\Software\PotenFYR\HBS-Console" -Name "InstallRoot" -Value $InstallDir
} catch {
  Note "could not persist the install root hint: $_"
}

Log "done - HBS Console is in the Start menu (and on your desktop)."
exit 0
