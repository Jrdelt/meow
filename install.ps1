#Requires -Version 5.1
<#
.SYNOPSIS
    Builds and installs meow on Windows with everything it uses: a C compiler,
    the Rust toolchain, the scanners `meow recon` drives (nmap, katana,
    feroxbuster), and the pinned SecLists wordlist.

.EXAMPLE
    .\install.ps1               # show the plan, ask once, then do it
    .\install.ps1 -Yes          # do not ask
    .\install.ps1 -DryRun       # only show what would be done
    .\install.ps1 -NoTools      # leave out the scanners and the wordlist
    .\install.ps1 -NoGeo        # leave out the location database
    .\install.ps1 -ToolsOnly    # only install scanners, wordlist, and location database
#>

[CmdletBinding()]
param(
    [Alias('y')]
    [switch]$Yes,
    [Alias('n')]
    [switch]$DryRun,
    [switch]$NoTools,
    [switch]$WithTools,
    [switch]$ToolsOnly,
    [switch]$NoGeo,
    [Alias('h')]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$MIN_RUST_MINOR = 89
$IsArm64 = ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') -or ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64')
$RUSTUP_URL = if ($IsArm64) { "https://win.rustup.rs/aarch64" } else { "https://win.rustup.rs/x86_64" }
$WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/0c618cfc28d1e68811b95c61cc9ab05bc10b0a02/Discovery/Web-Content/common.txt"
$WORDLIST_SHA256 = "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a"
$KATANA_GO = "github.com/projectdiscovery/katana/cmd/katana@v1.1.2"
$FEROXBUSTER_VERSION = "2.11.0"
# The most a location database file may weigh, packed (200 MB) and unpacked (512 MB).
$GEO_MAX_PACKED = 209715200
$GEO_MAX_BYTES = 536870912

function Say([string]$Message) {
    Write-Host "[+] $Message"
}

function Warn([string]$Message) {
    [Console]::Error.WriteLine("[!] $Message")
}

function Die([string]$Message) {
    Warn $Message
    exit 1
}

function Have([string]$Name) {
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-IsReparsePoint([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $Item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $Item) {
        return $false
    }
    return [bool]($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

# Whether $Path is owned by this user (or by SYSTEM, Administrators or
# TrustedInstaller, which can change any file anyway) and no other account
# may change it: write, append, delete, or change its access list or owner.
function Test-OwnPath([string]$Path) {
    try {
        $Acl = Get-Acl -LiteralPath $Path
        $Trusted = @(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
            'S-1-5-18',
            'S-1-5-32-544',
            'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        )
        $Owner = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($Trusted -notcontains $Owner) {
            return $false
        }
        # CREATOR OWNER and OWNER RIGHTS stand for the owner.
        $Trusted += @('S-1-3-0', 'S-1-3-4')
        $Change = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
        foreach ($Rule in $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            # An inherit-only entry is for what is made inside, not for this.
            if (($Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and
                (([int]$Rule.PropagationFlags -band 2) -eq 0) -and
                (([int]$Rule.FileSystemRights -band $Change) -ne 0) -and
                ($Trusted -notcontains $Rule.IdentityReference.Value)) {
                return $false
            }
        }
        return $true
    } catch {
        return $false
    }
}

# Cargo and rustup take settings, which can name programs to run, from
# .cargo\config.toml and rust-toolchain.toml here and in every folder above,
# and any account may make a folder in C:\. Stop if another account owns or
# can change one of them.
function Assert-OwnCargoSettings {
    $Dir = (Get-Location).ProviderPath
    while ($Dir) {
        foreach ($Name in @('.cargo', '.cargo\config', '.cargo\config.toml', 'rust-toolchain', 'rust-toolchain.toml')) {
            $Candidate = [System.IO.Path]::Combine($Dir, $Name)
            if ((Test-Path -LiteralPath $Candidate) -and
                ((Test-IsReparsePoint $Candidate) -or -not (Test-OwnPath $Candidate))) {
                Die "$Candidate can be changed by another account, and cargo would obey it. Have it removed, then run this again."
            }
        }
        $Dir = [System.IO.Path]::GetDirectoryName($Dir)
    }
}

# Strip empty and relative PATH segments so command lookups never run binaries from CWD.
if ($env:PATH) {
    $CleanPathEntries = @()
    foreach ($Entry in ($env:PATH -split ';')) {
        if ($Entry -and [System.IO.Path]::IsPathRooted($Entry) -and ($Entry -match '^[A-Za-z]:\\')) {
            $CleanPathEntries += $Entry
        }
    }
    $env:PATH = $CleanPathEntries -join ';'
}

if ($Help) {
    Write-Host @"
Builds and installs meow with everything it uses on Windows: a C compiler,
the Rust toolchain, the scanners meow recon drives (nmap, katana, feroxbuster),
and a wordlist for the directory stage.

  .\install.ps1               show the plan, ask once, then do it
  .\install.ps1 -Yes          do not ask
  .\install.ps1 -DryRun       only show what would be done
  .\install.ps1 -NoTools      leave out the scanners and the wordlist
  .\install.ps1 -NoGeo        leave out the location database
  .\install.ps1 -ToolsOnly    only the scanners, wordlist, and location database
"@
    exit 0
}

$InstallTools = -not $NoTools
if ($WithTools -or $ToolsOnly) {
    $InstallTools = $true
}

if (-not $ToolsOnly) {
    Set-Location -LiteralPath $PSScriptRoot
    if (-not (Test-Path -LiteralPath "Cargo.toml") -or -not (Select-String -Path "Cargo.toml" -Pattern '^name = "meow"' -Quiet)) {
        Die "Run this script from the meow repository (Cargo.toml not found next to it)."
    }
} else {
    # Nothing below needs the folder the user is in, and rustup's cargo and
    # rustc would obey a rust-toolchain.toml found there; use SystemRoot
    # rather than a potentially shared temp folder.
    $SafeWorkDir = if ($env:SystemRoot -and (Test-Path -LiteralPath $env:SystemRoot)) { $env:SystemRoot } else { $HOME }
    Set-Location -LiteralPath $SafeWorkDir
}
# Before rustc or cargo first runs here.
Assert-OwnCargoSettings

$CargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME ".cargo" }
$CargoBin = Join-Path $CargoHome "bin"
if (-not (Have "cargo") -and (Test-Path -LiteralPath (Join-Path $CargoBin "cargo.exe"))) {
    $env:PATH = "$CargoBin;$env:PATH"
}

$Pm = if (Have "winget") {
    "winget"
} elseif (Have "scoop") {
    "scoop"
} else {
    ""
}

function Test-MsvcInstalled {
    if ((Have "cl") -or (Have "gcc") -or (Have "clang")) {
        return $true
    }
    $Pf86 = ${env:ProgramFiles(x86)}
    if ($Pf86) {
        $VsWhere = Join-Path $Pf86 "Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path -LiteralPath $VsWhere) {
            try {
                $Found = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Workload.VCTools -property installationPath 2>$null
                if ($Found) { return $true }
            } catch {}
        }
    }
    return $false
}

function Get-RustMinor {
    if (-not (Have "rustc")) {
        return $null
    }
    try {
        $ver = & rustc --version 2>$null
        if ($ver -match '^rustc 1\.(\d+)\.') {
            return [int]$Matches[1]
        }
    } catch {}
    return $null
}

$NeedCompiler = $false
$NeedRust = $false
$UpdateRust = $false
$FoundRust = $null

if (-not $ToolsOnly) {
    $NeedCompiler = -not (Test-MsvcInstalled)
    $FoundRust = Get-RustMinor
    if (-not (Have "cargo") -or $null -eq $FoundRust) {
        $NeedRust = $true
    } elseif ($FoundRust -lt $MIN_RUST_MINOR) {
        if (Have "rustup") {
            $UpdateRust = $true
        } else {
            $NeedRust = $true
        }
    }
}

$MissingTools = @()
foreach ($tool in @("nmap", "katana", "feroxbuster")) {
    if (-not (Have $tool)) {
        $MissingTools += $tool
    }
}

$MeowHome = if ($env:MEOW_HOME) { $env:MEOW_HOME } else { Join-Path $HOME ".meow" }
$WordlistDir = Join-Path $MeowHome "wordlists"
$ExistingWordlists = @()
if (Test-Path -LiteralPath $WordlistDir) {
    $ExistingWordlists = @(
        Get-ChildItem -LiteralPath $WordlistDir -Filter "*.txt" -File -ErrorAction SilentlyContinue |
            Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $_.Length -gt 0 }
    )
}
$NeedWordlist = $InstallTools -and ($ExistingWordlists.Count -eq 0)

# The location database (DB-IP Lite, CC BY 4.0) puts scanned servers on the
# map without sending their addresses anywhere; a copy younger than 30 days
# is kept.
$GeoDir = Join-Path $MeowHome "geo"
$GeoCity = Join-Path $GeoDir "dbip-city-lite.mmdb"
$GeoAsn = Join-Path $GeoDir "dbip-asn-lite.mmdb"
$NeedGeo = -not $NoGeo
if ((Test-Path -LiteralPath $GeoCity) -and (Test-Path -LiteralPath $GeoAsn) -and
    ((Get-Item -LiteralPath $GeoCity).LastWriteTime -gt (Get-Date).AddDays(-30)) -and
    ((Get-Item -LiteralPath $GeoAsn).LastWriteTime -gt (Get-Date).AddDays(-30))) {
    $NeedGeo = $false
}

Write-Host "   /\_/\    _ __ ___   ___  _____      __" -ForegroundColor Cyan
Write-Host "  ( o.o )  | '_ `` _ \ / _ \/ _ \ \ /\ / /" -ForegroundColor Cyan
Write-Host "   > ^ <   | | | | | |  __/ (_) \ V  V /" -ForegroundColor Cyan
Write-Host "  /|   |\  |_| |_| |_|\___|\___/ \_/\_/" -ForegroundColor Cyan
Write-Host " (_|   |_)  local security triage & topology shell" -ForegroundColor Cyan
Write-Host ""
Say "meow installer for windows"
Write-Host "This will:"
if ($NeedCompiler) {
    Write-Host "  - install Visual Studio C++ Build Tools (or check that MSVC/MinGW C compiler is on PATH)"
}
if ($NeedRust) {
    Write-Host "  - install the Rust toolchain with rustup into $CargoHome and ~/.rustup"
    Write-Host "    (without modifying your shell profile; add $CargoBin to PATH)"
}
if ($UpdateRust) {
    Write-Host "  - update Rust to the latest stable (meow needs 1.$MIN_RUST_MINOR or newer; found 1.$FoundRust)"
}
$InstalledExe = Join-Path $CargoBin "meow.exe"
if (-not $ToolsOnly) {
    Write-Host "  - build meow in release mode and install it to $InstalledExe"
}
if ($InstallTools -and $MissingTools.Count -gt 0) {
    Write-Host "  - install the scanners meow recon drives: $($MissingTools -join ' ')"
}
if ($NeedWordlist) {
    Write-Host "  - download the SecLists web-content wordlist from GitHub to $(Join-Path $WordlistDir 'common.txt')"
}
if ($NeedGeo) {
    Write-Host "  - download the DB-IP Lite location database (about 65 MB, 135 MB unpacked) to $GeoDir"
}
if (-not $ToolsOnly -and -not $NeedCompiler -and -not $NeedRust -and -not $UpdateRust) {
    Write-Host "The C compiler and Rust are already installed."
}
if ($ToolsOnly -and $MissingTools.Count -eq 0 -and -not $NeedWordlist -and -not $NeedGeo) {
    Say "Every tool meow recon uses is already installed."
    exit 0
}

if ($DryRun) {
    Say "Dry run: nothing was changed."
    exit 0
}

if (-not $Yes) {
    if ([Console]::IsInputRedirected) {
        Die "Not running in a terminal, so I cannot ask. Rerun with -Yes to proceed."
    }
    Write-Host -NoNewline "Proceed? [Y/n] "
    $answer = [Console]::ReadLine()
    if ($null -eq $answer -or $answer.Trim() -match '^(n|no)$') {
        Die "Cancelled; nothing was changed."
    }
}

# Downloads an HTTPS resource to a brand-new file (`FileMode::CreateNew`),
# enforcing HTTPS on every redirect hop and aborting immediately if the body
# exceeds `$MaxBytes`.
function Invoke-SafeDownload([string]$Url, [string]$OutFile, [long]$MaxBytes) {
    $Current = New-Object System.Uri($Url)
    if ($Current.Scheme -ne 'https') {
        throw "Refusing non-HTTPS URL: $Url"
    }
    for ($Hop = 0; $Hop -le 5; $Hop++) {
        $Req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Current)
        $Req.AllowAutoRedirect = $false
        $Req.Timeout = 300000
        $Req.ReadWriteTimeout = 60000
        $Req.UserAgent = "meow-installer"
        $Resp = [System.Net.HttpWebResponse]$Req.GetResponse()
        try {
            $Code = [int]$Resp.StatusCode
            if ($Code -in @(301, 302, 303, 307, 308)) {
                if ($Hop -eq 5) {
                    throw "Too many HTTP redirects for $Url"
                }
                $Loc = $Resp.Headers["Location"]
                if (-not $Loc) {
                    throw "Redirect without Location header for $Url"
                }
                $Next = New-Object System.Uri($Current, $Loc)
                if ($Next.Scheme -ne 'https') {
                    throw "Refusing HTTPS downgrade redirect for $Url"
                }
                $Current = $Next
                continue
            }
            if ($Code -ne 200) {
                throw "Unexpected HTTP status $Code for $Url"
            }
            if ($Resp.ContentLength -gt $MaxBytes) {
                throw "Download from $Url exceeds size limit ($($Resp.ContentLength) > $MaxBytes)"
            }
            $Stream = $Resp.GetResponseStream()
            $Out = New-Object System.IO.FileStream(
                $OutFile,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None
            )
            $Complete = $false
            try {
                $Buf = New-Object byte[] 65536
                $Total = 0L
                while (($Read = $Stream.Read($Buf, 0, $Buf.Length)) -gt 0) {
                    $Total += $Read
                    if ($Total -gt $MaxBytes) {
                        throw "Download from $Url exceeds size limit ($MaxBytes bytes)"
                    }
                    $Out.Write($Buf, 0, $Read)
                }
                $Complete = $true
                return
            } finally {
                $Out.Dispose()
                # A body cut short by the size limit or a dropped connection
                # is not left behind for the caller to clean up. Only a file
                # this call created is removed.
                if (-not $Complete) {
                    Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
                }
            }
        } finally {
            $Resp.Dispose()
        }
    }
}

$RustupInit = $null
$WordlistPart = $null
$GeoPart = $null

try {
    $TlsProto = [Net.SecurityProtocolType]::Tls12
    # Looked up by name: Windows PowerShell 5.1 runs on .NET Framework, which
    # has no Enum.TryParse(Type, string, out object), and older versions of it
    # have no Tls13 at all.
    if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
        $TlsProto = $TlsProto -bor [Net.SecurityProtocolType]'Tls13'
    }
    [Net.ServicePointManager]::SecurityProtocol = $TlsProto

    if ($NeedCompiler) {
        if ($Pm -eq "winget") {
            Say "Installing Visual Studio C++ Build Tools with winget"
            & winget install --id Microsoft.VisualStudio.2022.BuildTools --exact --silent --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
        } else {
            Warn "No C compiler (cl.exe, gcc.exe, or clang.exe) found on PATH. If the build below fails, install Visual Studio C++ Build Tools."
        }
    }

    if ($NeedRust) {
        Say "Installing Rust with rustup"
        $RustupInit = Join-Path ([System.IO.Path]::GetTempPath()) ("rustup-init-" + [System.Guid]::NewGuid().ToString("N") + ".exe")
        Invoke-SafeDownload -Url $RUSTUP_URL -OutFile $RustupInit -MaxBytes 67108864
        & $RustupInit -y --profile minimal --no-modify-path
        if ($LASTEXITCODE -ne 0) {
            Die "The Rust installer failed."
        }
        $env:PATH = "$CargoBin;$env:PATH"
    }

    if ($UpdateRust) {
        Say "Updating Rust"
        & rustup update stable
        if ($LASTEXITCODE -ne 0) {
            Die "Could not update Rust."
        }
    }

    if (-not $ToolsOnly) {
        if (-not (Have "cargo")) {
            Die "Rust is installed but cargo is not on PATH. Open a new terminal and rerun this script."
        }
        $NowRust = Get-RustMinor
        if ($null -eq $NowRust -or $NowRust -lt $MIN_RUST_MINOR) {
            Die "meow needs Rust 1.$MIN_RUST_MINOR or newer. Run: rustup update stable"
        }

        Assert-OwnCargoSettings
        Say "Building meow (release). The first build takes a few minutes."
        & cargo install --path . --locked
        if ($LASTEXITCODE -ne 0) {
            Die "The build failed. The messages above say why."
        }
        if (-not (Test-Path -LiteralPath $InstalledExe)) {
            Die "The build finished but $InstalledExe is missing."
        }
        $VerOut = (& $InstalledExe --version) -join ""
        Say "Installed $VerOut at $InstalledExe"
    }

    function Install-Tool([string]$Tool) {
        if ($Pm -eq "scoop") {
            & scoop install $Tool
            if ($LASTEXITCODE -eq 0) { return $true }
        } elseif ($Pm -eq "winget") {
            $WingetId = switch ($Tool) {
                "nmap" { "Insecure.Nmap" }
                "feroxbuster" { "epi052.feroxbuster" }
                default { $null }
            }
            if ($WingetId) {
                & winget install --id $WingetId --exact --silent
                if ($LASTEXITCODE -eq 0) { return $true }
            }
        }
        switch ($Tool) {
            "feroxbuster" {
                if (Have "cargo") {
                    Say "Building feroxbuster with cargo (a few minutes)"
                    & cargo install feroxbuster --locked --version $FEROXBUSTER_VERSION
                    return ($LASTEXITCODE -eq 0)
                }
                return $false
            }
            "katana" {
                if (Have "go") {
                    Say "Building katana with go"
                    & go install $KATANA_GO
                    return ($LASTEXITCODE -eq 0)
                }
                return $false
            }
            default { return $false }
        }
    }

    if ($InstallTools -and $MissingTools.Count -gt 0) {
        foreach ($Tool in $MissingTools) {
            Say "Installing $Tool"
            if (-not (Install-Tool $Tool)) {
                Warn "Could not install $Tool automatically. Install it yourself when needed."
            }
        }
    }

    if ($NeedWordlist) {
        Say "Downloading the wordlist"
        $Dest = Join-Path $WordlistDir "common.txt"
        if ((Test-IsReparsePoint $MeowHome) -or (Test-IsReparsePoint $WordlistDir) -or (Test-IsReparsePoint $Dest)) {
            Warn "Refusing to write wordlist through a symbolic link or junction under $MeowHome."
        } else {
            New-Item -ItemType Directory -Force -Path $WordlistDir | Out-Null
            $WordlistPart = Join-Path $WordlistDir (".common.txt." + [System.Guid]::NewGuid().ToString("N"))
            try {
                Invoke-SafeDownload -Url $WORDLIST_URL -OutFile $WordlistPart -MaxBytes 16777216
                $Sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $Stream = [System.IO.File]::OpenRead($WordlistPart)
                    try {
                        $ActualHash = ([System.BitConverter]::ToString($Sha.ComputeHash($Stream))).Replace("-", "").ToLowerInvariant()
                    } finally {
                        $Stream.Dispose()
                    }
                } finally {
                    $Sha.Dispose()
                }
                $ContentHead = Get-Content -LiteralPath $WordlistPart -TotalCount 5 -ErrorAction SilentlyContinue
                if ((Get-Item -LiteralPath $WordlistPart).Length -gt 0 -and
                    -not ($ContentHead -match '<html') -and
                    ($ActualHash -eq $WORDLIST_SHA256) -and
                    -not (Test-IsReparsePoint $Dest)) {
                    Move-Item -LiteralPath $WordlistPart -Destination $Dest -Force
                    $WordlistPart = $null
                    Say "Wordlist saved to $Dest"
                } else {
                    Warn "Could not download the wordlist from $WORDLIST_URL (or its SHA-256 digest did not match). Put any .txt wordlist in $WordlistDir and meow will use it."
                }
            } catch {
                Warn "Could not download the wordlist from $WORDLIST_URL. Put any .txt wordlist in $WordlistDir and meow will use it."
            }
        }
    }

    # This month's file, or last month's early in a month before it is out.
    function Get-GeoFile([string]$Name) {
        $TargetMmdb = Join-Path $GeoDir "$Name.mmdb"
        if (Test-IsReparsePoint $TargetMmdb) {
            return $false
        }
        $NowUtc = [DateTime]::UtcNow
        $Months = @(
            $NowUtc.ToString("yyyy-MM"),
            (New-Object DateTime($NowUtc.Year, $NowUtc.Month, 1)).AddMonths(-1).ToString("yyyy-MM")
        )
        $script:GeoPart = Join-Path $GeoDir (".$Name." + [System.Guid]::NewGuid().ToString("N"))
        foreach ($Month in $Months) {
            $GzPath = "$($script:GeoPart).gz"
            try {
                Invoke-SafeDownload -Url "https://download.db-ip.com/free/$Name-$Month.mmdb.gz" -OutFile $GzPath -MaxBytes $GEO_MAX_PACKED
                if ((Get-Item -LiteralPath $GzPath).Length -gt $GEO_MAX_PACKED) {
                    Remove-Item -LiteralPath $GzPath -Force -ErrorAction SilentlyContinue
                    continue
                }
                $In = [System.IO.File]::OpenRead($GzPath)
                $ValidSize = $true
                try {
                    $Unzip = New-Object System.IO.Compression.GZipStream($In, [System.IO.Compression.CompressionMode]::Decompress)
                    $Out = New-Object System.IO.FileStream(
                        $script:GeoPart,
                        [System.IO.FileMode]::CreateNew,
                        [System.IO.FileAccess]::Write,
                        [System.IO.FileShare]::None
                    )
                    try {
                        $Buf = New-Object byte[] 65536
                        $Total = 0L
                        while (($Read = $Unzip.Read($Buf, 0, $Buf.Length)) -gt 0) {
                            $Total += $Read
                            if ($Total -gt $GEO_MAX_BYTES) {
                                $ValidSize = $false
                                break
                            }
                            $Out.Write($Buf, 0, $Read)
                        }
                    } finally {
                        $Out.Dispose()
                        $Unzip.Dispose()
                    }
                } finally {
                    $In.Dispose()
                }
                if (-not $ValidSize) {
                    Remove-Item -LiteralPath $script:GeoPart, $GzPath -Force -ErrorAction SilentlyContinue
                    continue
                }
                $Check = [System.IO.File]::OpenRead($script:GeoPart)
                $HasMarker = $false
                try {
                    $TailLen = [int][Math]::Min(100000L, $Check.Length)
                    if ($TailLen -gt 0) {
                        [void]$Check.Seek(-$TailLen, [System.IO.SeekOrigin]::End)
                        $TailBuf = New-Object byte[] $TailLen
                        $Got = 0
                        while ($Got -lt $TailLen) {
                            $Step = $Check.Read($TailBuf, $Got, $TailLen - $Got)
                            if ($Step -le 0) { break }
                            $Got += $Step
                        }
                        $Tail = [System.Text.Encoding]::ASCII.GetString($TailBuf, 0, $Got)
                        $HasMarker = $Tail.Contains("MaxMind.com")
                    }
                } finally {
                    $Check.Dispose()
                }
                if ($HasMarker -and -not (Test-IsReparsePoint $TargetMmdb)) {
                    Move-Item -LiteralPath $script:GeoPart -Destination $TargetMmdb -Force
                    Remove-Item -LiteralPath $GzPath -Force -ErrorAction SilentlyContinue
                    $script:GeoPart = $null
                    return $true
                }
            } catch {
                # Try last month's file, then give up.
            }
            Remove-Item -LiteralPath $script:GeoPart, $GzPath -Force -ErrorAction SilentlyContinue
        }
        $script:GeoPart = $null
        return $false
    }

    if ($NeedGeo) {
        Say "Downloading the location database (IP Geolocation by DB-IP, https://db-ip.com)"
        if ((Test-IsReparsePoint $MeowHome) -or (Test-IsReparsePoint $GeoDir)) {
            Warn "Refusing to write location database through a symbolic link or junction under $MeowHome."
        } else {
            New-Item -ItemType Directory -Force -Path $GeoDir | Out-Null
            if ((Get-GeoFile "dbip-city-lite") -and (Get-GeoFile "dbip-asn-lite")) {
                Say "Location database saved to $GeoDir"
            } else {
                Warn "Could not download the location database from download.db-ip.com. The map still shows your own place; run this again later."
            }
        }
    }

    if ($ToolsOnly) {
        Say "Done."
    } else {
        Say "Ready. Run 'meow' for the interactive setup GUI, or 'meow <name>' to open a session"
    }
} finally {
    if ($RustupInit -and (Test-Path -LiteralPath $RustupInit)) {
        Remove-Item -LiteralPath $RustupInit -Force -ErrorAction SilentlyContinue
    }
    if ($WordlistPart -and (Test-Path -LiteralPath $WordlistPart)) {
        Remove-Item -LiteralPath $WordlistPart -Force -ErrorAction SilentlyContinue
    }
    if ($GeoPart) {
        Remove-Item -LiteralPath $GeoPart, "$GeoPart.gz" -Force -ErrorAction SilentlyContinue
    }
}
