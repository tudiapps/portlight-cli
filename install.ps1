# Installs the portlight CLI from its GitHub release (Windows).
#
# From Command Prompt (cmd) or PowerShell:
#
#   powershell -ExecutionPolicy Bypass -c "& ([scriptblock]::Create((irm https://raw.githubusercontent.com/tudiapps/portlight-cli/main/install.ps1)))"
#
# Not `irm … | iex` on the command line: endpoint protection on managed
# Windows machines refuses to start a process whose command line is that
# download-and-run pattern ("Access is denied"). Inside an already open
# PowerShell, `irm … | iex` still works.
#
# Options, as environment variables:
#   PORTLIGHT_VERSION      a tag such as v0.1.0 (default: the latest release)
#   PORTLIGHT_INSTALL_DIR  where portlight.exe goes
#                          (default: %LOCALAPPDATA%\Programs\portlight)
#
# The archive is checked against the release's checksums.txt before anything
# is installed; the install directory is added to the user PATH.
#
# Everything runs inside a script block so that `iex` leaves no variables or
# preferences behind in the caller's session.
& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Windows PowerShell 5.1 on older .NET still offers TLS 1.0 first, which
# GitHub refuses.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = 'tudiapps/portlight-cli'

# A 32-bit PowerShell on 64-bit Windows reports x86; the real CPU is in
# PROCESSOR_ARCHITEW6432.
$cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$arch = switch ($cpu) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "portlight install: unsupported CPU $cpu" }
}

$tag = $env:PORTLIGHT_VERSION
if (-not $tag) {
    # releases/latest redirects to releases/tag/vX.Y.Z; following it needs no
    # API call, so the unauthenticated API rate limit cannot get in the way.
    $req = [Net.WebRequest]::Create("https://github.com/$repo/releases/latest")
    $req.Method = 'HEAD'
    $resp = $req.GetResponse()
    $tag = ($resp.ResponseUri.AbsolutePath -split '/')[-1]
    $resp.Close()
}
if ($tag -notmatch '^v\d') { throw "portlight install: could not find the latest release (got '$tag')" }
$version = $tag.Substring(1)

$archive = "portlight_${version}_windows_${arch}.zip"
$base = "https://github.com/$repo/releases/download/$tag"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("portlight-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading portlight $tag for windows/$arch"
    Invoke-WebRequest "$base/$archive" -OutFile (Join-Path $tmp $archive) -UseBasicParsing
    Invoke-WebRequest "$base/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt') -UseBasicParsing

    $line = Get-Content (Join-Path $tmp 'checksums.txt') | Where-Object { ($_ -split '\s+')[1] -eq $archive }
    if (-not $line) { throw "portlight install: $archive is not in checksums.txt" }
    $expected = ($line -split '\s+')[0]
    $actual = (Get-FileHash (Join-Path $tmp $archive) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw "portlight install: checksum mismatch for $archive" }

    # ZipFile rather than Expand-Archive: the Archive module is missing or
    # blocked on some locked-down machines.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $tmp $archive), (Join-Path $tmp 'x'))

    $dir = $env:PORTLIGHT_INSTALL_DIR
    if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Programs\portlight' }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item (Join-Path $tmp 'x\portlight.exe') (Join-Path $dir 'portlight.exe') -Force
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$exe = Join-Path $dir 'portlight.exe'
if (-not (Test-Path $exe)) {
    throw "portlight install: $exe disappeared after copying; your antivirus may have quarantined it"
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $dir).TrimStart(';'), 'User')
    Write-Host "Added $dir to your user PATH."
}
if (($env:Path -split ';') -notcontains $dir) { $env:Path = "$env:Path;$dir" }

Write-Host "Installed $(& $exe version) to $exe"
Write-Host ''
Write-Host 'Open a NEW terminal window, then run:  portlight pair'
}
