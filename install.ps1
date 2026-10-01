# Installs the portlight CLI from its GitHub release (Windows).
#
#   irm https://raw.githubusercontent.com/tudiapps/portlight-cli/main/install.ps1 | iex
#
# Options, as environment variables:
#   PORTLIGHT_VERSION      a tag such as v0.1.0 (default: the latest release)
#   PORTLIGHT_INSTALL_DIR  where portlight.exe goes
#                          (default: %LOCALAPPDATA%\Programs\portlight)
#
# The archive is checked against the release's checksums.txt before anything
# is installed; the install directory is added to the user PATH.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = 'tudiapps/portlight-cli'

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "portlight install: unsupported CPU $env:PROCESSOR_ARCHITECTURE" }
}

$tag = $env:PORTLIGHT_VERSION
if (-not $tag) {
    $latest = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'portlight-install' }
    $tag = $latest.tag_name
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

    Expand-Archive (Join-Path $tmp $archive) -DestinationPath (Join-Path $tmp 'x') -Force

    $dir = $env:PORTLIGHT_INSTALL_DIR
    if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Programs\portlight' }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item (Join-Path $tmp 'x\portlight.exe') (Join-Path $dir 'portlight.exe') -Force
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $dir).TrimStart(';'), 'User')
    $env:Path = "$env:Path;$dir"
    Write-Host "Added $dir to your user PATH (new terminals pick it up)."
}

Write-Host "Installed $(& (Join-Path $dir 'portlight.exe') version) to $dir"
