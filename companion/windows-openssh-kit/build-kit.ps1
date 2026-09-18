#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the HostTraceAI Windows SSH kit distributable.

.DESCRIPTION
    Downloads the three pinned upstream Win32-OpenSSH releases, verifies every
    archive against a hard-coded SHA-256 digest, lays the extracted trees out
    under bin\<version>\, and packs the whole kit into
    HostTraceAI-WindowsSSHKit-<version>.zip.

    This script only downloads, verifies and packages. It installs nothing,
    registers no service and modifies no system state, so it is safe to run on
    an ordinary workstation.

    The upstream binaries are deliberately NOT version controlled. They are
    third-party redistributables and belong in a versioned build artefact
    rather than in git history. Either run this script, or download the
    ready-made zip from the Releases page.

.PARAMETER OutputDirectory
    Directory the finished .zip is written to. Defaults to the folder that
    contains this script.

.PARAMETER CacheDirectory
    Where downloaded upstream archives are cached between runs.
    Defaults to .\_build\cache.

.PARAMETER Force
    Ignore the cache and re-download every archive.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\build-kit.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\build-kit.ps1 -Force -OutputDirectory D:\dist

.NOTES
    This file is intentionally ASCII-only. Windows PowerShell 5.1 decodes .ps1
    files that carry no BOM using the system ANSI code page, so non-ASCII
    source can corrupt on some hosts. Localised documentation lives in
    README_CN.md instead.
#>

[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [string] $CacheDirectory,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

if (-not $OutputDirectory) { $OutputDirectory = $PSScriptRoot }
if (-not $CacheDirectory)  { $CacheDirectory  = Join-Path $PSScriptRoot '_build\cache' }

# ---------------------------------------------------------------------------
# Pinned build inputs
# ---------------------------------------------------------------------------

$KitVersion = '1.0.0'
$KitName    = 'HostTraceAI-WindowsSSHKit'

$UpstreamOwner = 'PowerShell'
$UpstreamRepo  = 'Win32-OpenSSH'

$UserAgent = 'HostTraceAI-WindowsSSHKit-Builder/1.0'

# The SHA-256 digests below were computed from the archives exactly as
# published by the upstream project. They are re-checked on every run, so if
# upstream ever replaces an asset the build fails loudly instead of quietly
# shipping different binaries.
$Sources = @(
    [pscustomobject]@{
        Bin    = '7.7.2.0'
        Tag    = 'v7.7.2.0p1-Beta'
        Asset  = 'OpenSSH-Win64.zip'
        Sha256 = '8631F00013116388362CB06F3E6FD2C44C8E57D8F857033111F98FEB34FA5BCE'
        Bytes  = 3302851
        Files  = 19
        Role   = 'single-process sshd; Windows 7 / Server 2008 R2 through 2016'
    }
    [pscustomobject]@{
        Bin    = '8.9.1.0'
        Tag    = 'v8.9.1.0p1-Beta'
        Asset  = 'OpenSSH-Win64.zip'
        Sha256 = 'B3D31939ACB93C34236F420A6F1396E7CF2EEAD7069EF67742857A5A0BEFB9FC'
        Bytes  = 4353706
        Files  = 26
        Role   = 'fallback; last release before the 9.8 sshd split'
    }
    [pscustomobject]@{
        Bin    = '10.0.0.0'
        Tag    = '10.0.0.0p2-Preview'
        Asset  = 'OpenSSH-Win64.zip'
        Sha256 = '23F50F3458C4C5D0B12217C6A5DDFDE0137210A30FA870E98B29827F7B43ABA5'
        Bytes  = 5704583
        Files  = 33
        Role   = 'split sshd + sshd-session; Windows 10 1809+ / Server 2019+'
    }
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step {
    param([Parameter(Mandatory)] [string] $Message)
    Write-Host ('==> ' + $Message) -ForegroundColor Cyan
}

function Write-Info {
    param([Parameter(Mandatory)] [string] $Message)
    Write-Host ('    ' + $Message)
}

function Format-Size {
    param([Parameter(Mandatory)] [long] $Bytes)
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N1} KB' -f ($Bytes / 1KB)) }
    return ('{0} B' -f $Bytes)
}

function Get-UpstreamArchive {
    param(
        [Parameter(Mandatory)] $Source,
        [Parameter(Mandatory)] [string] $CacheDirectory,
        [switch] $Force
    )

    if (-not (Test-Path -LiteralPath $CacheDirectory)) {
        New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null
    }

    $archive = Join-Path $CacheDirectory ($Source.Tag + '.zip')
    $url = 'https://github.com/{0}/{1}/releases/download/{2}/{3}' -f `
        $UpstreamOwner, $UpstreamRepo, $Source.Tag, $Source.Asset

    if ((Test-Path -LiteralPath $archive) -and (-not $Force)) {
        $cached = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        if ($cached -eq $Source.Sha256) {
            Write-Info ('cached    ' + $Source.Tag)
            return $archive
        }
        Write-Info ('cache miss for ' + $Source.Tag + ', downloading again')
        Remove-Item -LiteralPath $archive -Force
    }

    Write-Info ('download  ' + $Source.Tag)
    Write-Info ('          ' + $url)

    $attempts = 3
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        $client = New-Object System.Net.WebClient
        $client.Headers.Add('User-Agent', $UserAgent)
        try {
            $client.DownloadFile($url, $archive)
            break
        }
        catch {
            if ($attempt -eq $attempts) { throw }
            Write-Info ('          attempt ' + $attempt + ' failed, retrying')
            Start-Sleep -Seconds (2 * $attempt)
        }
        finally {
            $client.Dispose()
        }
    }

    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($actual -ne $Source.Sha256) {
        Remove-Item -LiteralPath $archive -Force
        throw ('SHA-256 mismatch for {0}{1}  expected {2}{1}  actual   {3}' -f `
            $Source.Tag, [Environment]::NewLine, $Source.Sha256, $actual)
    }

    $size = (Get-Item -LiteralPath $archive).Length
    if ($size -ne $Source.Bytes) {
        Write-Warning ('{0}: size is {1} bytes, recorded value was {2}' -f `
            $Source.Tag, $size, $Source.Bytes)
    }

    Write-Info ('verified  ' + $actual.Substring(0, 24) + '...')
    return $archive
}

function Expand-UpstreamArchive {
    param(
        [Parameter(Mandatory)] [string] $Archive,
        [Parameter(Mandatory)] [string] $Destination
    )

    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)

    # Every pinned archive wraps its payload in one top-level folder
    # ("OpenSSH-Win64"). Return that folder so the caller can flatten it.
    $children = @(Get-ChildItem -LiteralPath $Destination -Force)
    if (($children.Count -eq 1) -and $children[0].PSIsContainer) {
        return $children[0].FullName
    }
    return $Destination
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host ('HostTraceAI Windows SSH kit builder  --  kit version ' + $KitVersion) -ForegroundColor White
Write-Host ''

$binRoot = Join-Path $PSScriptRoot 'bin'
$scratch = Join-Path $PSScriptRoot '_build\extract'
$stage   = Join-Path $PSScriptRoot ('_build\stage\' + $KitName + '-' + $KitVersion)

Write-Step 'Fetching pinned upstream releases'
foreach ($source in $Sources) {
    $archive = Get-UpstreamArchive -Source $source -CacheDirectory $CacheDirectory -Force:$Force

    Write-Step ('Laying out bin\' + $source.Bin + '  (' + $source.Role + ')')
    $extracted = Expand-UpstreamArchive -Archive $archive -Destination (Join-Path $scratch $source.Bin)

    $target = Join-Path $binRoot $source.Bin
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Copy-Item -Path (Join-Path $extracted '*') -Destination $target -Recurse -Force

    $copied = @(Get-ChildItem -LiteralPath $target -Recurse -File)
    Write-Info ('files     ' + $copied.Count + '  (' + (Format-Size (($copied | Measure-Object -Property Length -Sum).Sum)) + ')')

    if ($copied.Count -ne $source.Files) {
        Write-Warning ('{0}: expected {1} files, found {2}' -f $source.Bin, $source.Files, $copied.Count)
    }
}

# The kit's own files, plus the bin\ tree that was just materialised. Build
# scratch, VCS metadata and any previously produced zip are left out.
Write-Step 'Staging kit contents'
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$excludedNames = @('_build', '.git')
$included = @(Get-ChildItem -LiteralPath $PSScriptRoot -Force | Where-Object {
    ($excludedNames -notcontains $_.Name) -and ($_.Extension -ne '.zip')
})
foreach ($item in $included) {
    Copy-Item -LiteralPath $item.FullName -Destination $stage -Recurse -Force
    Write-Info ('added     ' + $item.Name)
}

$stageFiles = @(Get-ChildItem -LiteralPath $stage -Recurse -File)

Write-Step 'Packing distributable'
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$zipPath = Join-Path $OutputDirectory ($KitName + '-' + $KitVersion + '.zip')
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# ZipFile.CreateFromDirectory is used instead of Compress-Archive on purpose.
# Passing an explicit UTF-8 encoding makes the writer set the ZIP
# language-encoding flag on every entry, so the Chinese file names survive
# extraction on Windows 10 and later. Compress-Archive on Windows PowerShell
# 5.1 does not reliably set that flag.
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $stage,
    $zipPath,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $true,
    [System.Text.Encoding]::UTF8
)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

$zipInfo = Get-Item -LiteralPath $zipPath

Write-Host ''
Write-Host 'Build complete.' -ForegroundColor Green
Write-Host ''
Write-Host ('  archive : ' + $zipInfo.FullName)
Write-Host ('  size    : ' + (Format-Size $zipInfo.Length))
Write-Host ('  files   : ' + $stageFiles.Count)
Write-Host ('  sha256  : ' + (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash)
Write-Host ''
Write-Host '  contents:'
Write-Host ('    ' + $KitName + '-' + $KitVersion + '\')
foreach ($item in $included) {
    Write-Host ('      ' + $item.Name)
}
Write-Host '      bin\'
foreach ($source in $Sources) {
    Write-Host ('        ' + $source.Bin + '\  (' + $source.Files + ' files)')
}
Write-Host ''
Write-Host '  The kit directory now also contains bin\, so this checkout is'
Write-Host '  directly usable. bin\ and _build\ are git-ignored.'
Write-Host ''
