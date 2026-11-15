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
#>

[CmdletBinding()]
param(
    [Alias('y')]
    [switch]$Yes,
    [Alias('n')]
    [switch]$DryRun,
    [switch]$NoTools,
    [switch]$WithTools,
    [switch]$NoGeo,
    [Alias('h')]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'

$MIN_RUST_MINOR = 89
$RUSTUP_URL = "https://win.rustup.rs/x86_64"
$WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/f68bef9c49622d9f76c7cae7a8c2dae24da2d236/Discovery/Web-Content/common.txt"
$WORDLIST_SHA256 = "78e7be2efbbbfef8ef1eb02116189087fd9205ef2bf997e68b29b45bfeb8ab52"
$KATANA_GO = "github.com/projectdiscovery/katana/cmd/katana@v1.1.2"

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
"@
    exit 0
}

$InstallTools = -not $NoTools
if ($WithTools) {
    $InstallTools = $true
}

Set-Location -LiteralPath $PSScriptRoot
if (-not (Test-Path -LiteralPath "Cargo.toml") -or -not (Select-String -Path "Cargo.toml" -Pattern '^name = "meow"' -Quiet)) {
    Die "Run this script from the meow repository (Cargo.toml not found next to it)."
}

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

$NeedCompiler = -not ((Have "cl") -or (Have "gcc") -or (Have "clang"))
$NeedRust = $false
$UpdateRust = $false
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
    $ExistingWordlists = @(Get-ChildItem -LiteralPath $WordlistDir -Filter "*.txt" -File -ErrorAction SilentlyContinue)
}
$NeedWordlist = $InstallTools -and ($ExistingWordlists.Count -eq 0)

# The location database (DB-IP Lite, CC BY 4.0) puts scanned servers on the
# map without sending their addresses anywhere; a copy younger than 30 days
# is kept.
$GeoDir = Join-Path $MeowHome "geo"
$GeoCity = Join-Path $GeoDir "dbip-city-lite.mmdb"
$NeedGeo = -not $NoGeo
if ((Test-Path -LiteralPath $GeoCity) -and
    ((Get-Item -LiteralPath $GeoCity).LastWriteTime -gt (Get-Date).AddDays(-30))) {
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
Write-Host "  - build meow in release mode and install it to $InstalledExe"
if ($InstallTools -and $MissingTools.Count -gt 0) {
    Write-Host "  - install the scanners meow recon drives: $($MissingTools -join ' ')"
}
if ($NeedWordlist) {
    Write-Host "  - download the SecLists web-content wordlist from GitHub to $(Join-Path $WordlistDir 'common.txt')"
}
if ($NeedGeo) {
    Write-Host "  - download the DB-IP Lite location database (about 65 MB, 135 MB unpacked) to $GeoDir"
}
if (-not $NeedCompiler -and -not $NeedRust -and -not $UpdateRust) {
    Write-Host "The C compiler and Rust are already installed."
}

if ($DryRun) {
    Say "Dry run: nothing was changed."
    exit 0
}

if (-not $Yes) {
    $answer = Read-Host "Proceed? [Y/n]"
    if ($answer -match '^(n|no)$') {
        Die "Cancelled; nothing was changed."
    }
}

$RustupInit = $null
$WordlistPart = $null

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

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
        Invoke-WebRequest -Uri $RUSTUP_URL -OutFile $RustupInit -UseBasicParsing
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

    if (-not (Have "cargo")) {
        Die "Rust is installed but cargo is not on PATH. Open a new terminal and rerun this script."
    }
    $NowRust = Get-RustMinor
    if ($null -eq $NowRust -or $NowRust -lt $MIN_RUST_MINOR) {
        Die "meow needs Rust 1.$MIN_RUST_MINOR or newer. Run: rustup update stable"
    }

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
                Say "Building feroxbuster with cargo (a few minutes)"
                & cargo install feroxbuster --locked
                return ($LASTEXITCODE -eq 0)
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
        New-Item -ItemType Directory -Force -Path $WordlistDir | Out-Null
        $WordlistPart = Join-Path $WordlistDir (".common.txt." + [System.Guid]::NewGuid().ToString("N"))
        try {
            Invoke-WebRequest -Uri $WORDLIST_URL -OutFile $WordlistPart -UseBasicParsing
            $ActualHash = (Get-FileHash -LiteralPath $WordlistPart -Algorithm SHA256).Hash.ToLowerInvariant()
            $ContentHead = Get-Content -LiteralPath $WordlistPart -TotalCount 5 -ErrorAction SilentlyContinue
            if ((Get-Item -LiteralPath $WordlistPart).Length -gt 0 -and
                -not ($ContentHead -match '<html') -and
                ($ActualHash -eq $WORDLIST_SHA256)) {
                $Dest = Join-Path $WordlistDir "common.txt"
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

    # This month's file, or last month's early in a month before it is out.
    function Get-GeoFile([string]$Name) {
        $Part = Join-Path $GeoDir (".$Name." + [System.Guid]::NewGuid().ToString("N"))
        foreach ($Month in @((Get-Date).ToString("yyyy-MM"), (Get-Date).AddMonths(-1).ToString("yyyy-MM"))) {
            try {
                Invoke-WebRequest -Uri "https://download.db-ip.com/free/$Name-$Month.mmdb.gz" -OutFile "$Part.gz" -UseBasicParsing
                $In = [System.IO.File]::OpenRead("$Part.gz")
                try {
                    $Unzip = New-Object System.IO.Compression.GZipStream($In, [System.IO.Compression.CompressionMode]::Decompress)
                    $Out = [System.IO.File]::Create($Part)
                    try { $Unzip.CopyTo($Out) } finally { $Out.Dispose(); $Unzip.Dispose() }
                } finally { $In.Dispose() }
                $Bytes = [System.IO.File]::ReadAllBytes($Part)
                $Tail = [System.Text.Encoding]::ASCII.GetString($Bytes, [Math]::Max(0, $Bytes.Length - 100000), [Math]::Min(100000, $Bytes.Length))
                if ($Tail.Contains("MaxMind.com")) {
                    Move-Item -LiteralPath $Part -Destination (Join-Path $GeoDir "$Name.mmdb") -Force
                    Remove-Item -LiteralPath "$Part.gz" -Force -ErrorAction SilentlyContinue
                    return $true
                }
            } catch {
                # Try last month's file, then give up.
            }
        }
        Remove-Item -LiteralPath $Part, "$Part.gz" -Force -ErrorAction SilentlyContinue
        return $false
    }

    if ($NeedGeo) {
        Say "Downloading the location database (IP Geolocation by DB-IP, https://db-ip.com)"
        New-Item -ItemType Directory -Force -Path $GeoDir | Out-Null
        if ((Get-GeoFile "dbip-city-lite") -and (Get-GeoFile "dbip-asn-lite")) {
            Say "Location database saved to $GeoDir"
        } else {
            Warn "Could not download the location database from download.db-ip.com. The map still shows your own place; run this again later."
        }
    }

    Say "Ready. Run 'meow' for the interactive setup GUI, or 'meow <name>' to open a session"
} finally {
    if ($RustupInit -and (Test-Path -LiteralPath $RustupInit)) {
        Remove-Item -LiteralPath $RustupInit -Force -ErrorAction SilentlyContinue
    }
    if ($WordlistPart -and (Test-Path -LiteralPath $WordlistPart)) {
        Remove-Item -LiteralPath $WordlistPart -Force -ErrorAction SilentlyContinue
    }
}
