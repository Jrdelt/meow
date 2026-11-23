#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the downloads in install.ps1 on Windows: HTTPS only, size limits
    that hold, and no partial file left behind when a download fails. Also
    its check of who may change the Cargo settings above it (Test-OwnPath,
    Get-CargoSettingProblem).

.DESCRIPTION
    The installer is never run. Only the functions and constants these checks
    need are taken from it, through the PowerShell parser, so the checks test
    the installer's own code without installing anything. The pinned wordlist
    and the smallest DB-IP Lite database are downloaded a few times into a
    temporary folder that is removed at the end. Exits 1 if any check fails.
    Runs on Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .github\scripts\install-ps1-checks.ps1
    pwsh -NoProfile -File .github/scripts/install-ps1-checks.ps1
#>

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Failures = New-Object 'System.Collections.Generic.List[string]'
# What each download Get-GeoFile started did, so a check can tell a size
# limit from a network failure (Get-GeoFile itself only says yes or no).
$DownloadLog = New-Object 'System.Collections.Generic.List[string]'
$Work = $null
# Get-GeoFile reads these from the scope it is called from.
$GeoDir = $null
$GeoPart = $null
$GEO_MAX_PACKED = 0L
$GEO_MAX_BYTES = 0L

function Pass([string]$Message) {
    Write-Host "ok    $Message"
}

function Fail([string]$Message) {
    Write-Host "FAIL  $Message"
    $script:Failures.Add($Message)
}

# Every node of install.ps1 the predicate accepts, nested ones included.
# Callers wrap the call in @() because one result comes back unwrapped.
function Find-InstallerNode([scriptblock]$Predicate) {
    return @($script:InstallerAst.FindAll($Predicate, $true))
}

function Get-InstallerFunction([string]$Name) {
    $Found = @(Find-InstallerNode {
            param($Node)
            ($Node -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and ($Node.Name -eq $Name)
        })
    if ($Found.Count -ne 1) {
        throw "install.ps1 defines $Name $($Found.Count) times; expected once"
    }
    return $Found[0]
}

# The value of a constant install.ps1 assigns exactly once, read from the
# syntax tree so it is never copied here.
function Get-InstallerConstant([string]$Name) {
    $Found = @(Find-InstallerNode {
            param($Node)
            ($Node -is [System.Management.Automation.Language.AssignmentStatementAst]) -and
                ($Node.Left -is [System.Management.Automation.Language.VariableExpressionAst]) -and
                ($Node.Left.VariablePath.UserPath -eq $Name)
        })
    if ($Found.Count -ne 1) {
        throw "install.ps1 assigns `$$Name $($Found.Count) times; expected once"
    }
    $Right = $Found[0].Right
    if (($Right -is [System.Management.Automation.Language.CommandExpressionAst]) -and
        ($Right.Expression -is [System.Management.Automation.Language.ConstantExpressionAst])) {
        return $Right.Expression.Value
    }
    throw "install.ps1 sets `$$Name to something other than a constant: $($Right.Extent.Text)"
}

# The argument given to -Parameter in a command, as written (-Name value or
# -Name:value), or $null.
function Get-NamedArgument($Call, [string]$Parameter) {
    $Elements = $Call.CommandElements
    for ($i = 1; $i -lt $Elements.Count; $i++) {
        $Element = $Elements[$i]
        if (($Element -is [System.Management.Automation.Language.CommandParameterAst]) -and
            ($Element.ParameterName -eq $Parameter)) {
            if ($null -ne $Element.Argument) {
                return $Element.Argument
            }
            if ($i + 1 -lt $Elements.Count) {
                return $Elements[$i + 1]
            }
        }
    }
    return $null
}

# The message of the error $Action stops with, or $null when it succeeds.
function Get-ErrorMessage([scriptblock]$Action) {
    try {
        $null = & $Action
    } catch {
        return $_.Exception.Message
    }
    return $null
}

function New-CheckFolder([string]$Name) {
    $Dir = Join-Path $script:Work $Name
    New-Item -ItemType Directory -Path $Dir | Out-Null
    return $Dir
}

function Get-Leftovers([string]$Dir) {
    return @(Get-ChildItem -LiteralPath $Dir -Force | ForEach-Object { $_.Name })
}

# Stands in for the installer's Invoke-SafeDownload when Get-GeoFile calls
# it, and records how each download ended.
function Invoke-SafeDownload([string]$Url, [string]$OutFile, [long]$MaxBytes) {
    try {
        Invoke-InstallerDownload -Url $Url -OutFile $OutFile -MaxBytes $MaxBytes
    } catch {
        $script:DownloadLog.Add("failed: $($_.Exception.Message)")
        throw
    }
    $script:DownloadLog.Add('done')
}

# Runs the installer's Get-GeoFile for one database with the given limits in
# a folder of its own, and returns that folder and what Get-GeoFile returned.
function Invoke-GeoFile([string]$Folder, [string]$Name, [long]$MaxPacked, [long]$MaxBytes) {
    $script:GeoDir = New-CheckFolder $Folder
    $script:GEO_MAX_PACKED = $MaxPacked
    $script:GEO_MAX_BYTES = $MaxBytes
    $script:DownloadLog.Clear()
    $Returned = @(Get-GeoFile $Name)
    if (($Returned.Count -ne 1) -or ($Returned[0] -isnot [bool])) {
        Fail "Get-GeoFile $Name wrote $($Returned.Count) values to its output; expected one true or false"
    }
    if ($null -ne $script:GeoPart) {
        Fail "Get-GeoFile $Name left `$GeoPart set to $($script:GeoPart)"
    }
    return New-Object PSObject -Property @{
        Dir = $script:GeoDir
        Saved = (($Returned.Count -eq 1) -and ($Returned[0] -eq $true))
    }
}

try {
    Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    $InstallerPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\install.ps1')).ProviderPath
    $Tokens = $null
    $ParseErrors = $null
    $InstallerAst = [System.Management.Automation.Language.Parser]::ParseFile($InstallerPath, [ref]$Tokens, [ref]$ParseErrors)
    if (@($ParseErrors).Count -gt 0) {
        throw "install.ps1 does not parse: $(@($ParseErrors)[0].Message)"
    }

    # Every download in the installer goes through Invoke-SafeDownload with a
    # size limit; nothing fetches a URL another way.
    $Downloads = @(Find-InstallerNode {
            param($Node)
            ($Node -is [System.Management.Automation.Language.CommandAst]) -and
                ($Node.GetCommandName() -eq 'Invoke-SafeDownload')
        })
    if ($Downloads.Count -eq 0) {
        Fail 'install.ps1 never calls Invoke-SafeDownload'
    }
    foreach ($Call in $Downloads) {
        $Line = "install.ps1 line $($Call.Extent.StartLineNumber)"
        $Limit = Get-NamedArgument $Call 'MaxBytes'
        if ($null -eq $Limit) {
            Fail "$Line downloads without -MaxBytes"
        } elseif (($Limit -is [System.Management.Automation.Language.ConstantExpressionAst]) -and
            ([long]$Limit.Value -le 0)) {
            Fail "$Line downloads with -MaxBytes $($Limit.Extent.Text)"
        } else {
            Pass "$Line downloads with -MaxBytes $($Limit.Extent.Text)"
        }
    }
    $Unchecked = @('Invoke-WebRequest', 'iwr', 'Invoke-RestMethod', 'irm', 'curl', 'curl.exe',
        'wget', 'wget.exe', 'Start-BitsTransfer', 'bitsadmin', 'bitsadmin.exe')
    $Other = @(Find-InstallerNode {
            param($Node)
            (($Node -is [System.Management.Automation.Language.CommandAst]) -and
                ($Unchecked -contains $Node.GetCommandName())) -or
            (($Node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and
                ($Node.Member.Extent.Text -match '^Download(File|String|Data)'))
        })
    foreach ($Node in $Other) {
        Fail "install.ps1 line $($Node.Extent.StartLineNumber) downloads without a size limit: $($Node.Extent.Text)"
    }

    # The installer's own functions. Its Invoke-SafeDownload is loaded as
    # Invoke-InstallerDownload; the stand-in above takes its name.
    foreach ($Name in @('Test-IsReparsePoint', 'Get-GeoFile', 'Test-OwnPath', 'Get-CargoSettingProblem')) {
        . ([ScriptBlock]::Create((Get-InstallerFunction $Name).Extent.Text))
    }
    $Download = Get-InstallerFunction 'Invoke-SafeDownload'
    $Definition = 'function Invoke-InstallerDownload'
    if ($null -ne $Download.Parameters) {
        $Definition += '(' + ((@($Download.Parameters) | ForEach-Object { $_.Extent.Text }) -join ', ') + ')'
    }
    . ([ScriptBlock]::Create($Definition + ' ' + $Download.Body.Extent.Text))

    $WordlistUrl = [string](Get-InstallerConstant 'WORDLIST_URL')
    $WordlistSha256 = [string](Get-InstallerConstant 'WORDLIST_SHA256')
    $RealGeoMaxPacked = [long](Get-InstallerConstant 'GEO_MAX_PACKED')
    $RealGeoMaxBytes = [long](Get-InstallerConstant 'GEO_MAX_BYTES')
    $WordlistLimit = $null
    foreach ($Call in $Downloads) {
        $Url = Get-NamedArgument $Call 'Url'
        $Limit = Get-NamedArgument $Call 'MaxBytes'
        if (($null -ne $Url) -and ($Url.Extent.Text -eq '$WORDLIST_URL') -and
            ($Limit -is [System.Management.Automation.Language.ConstantExpressionAst])) {
            $WordlistLimit = [long]$Limit.Value
        }
    }
    if ($null -eq $WordlistLimit) {
        throw 'install.ps1 has no Invoke-SafeDownload -Url $WORDLIST_URL call with a constant -MaxBytes'
    }
    # The smallest database the installer fetches.
    $GeoNames = @(Find-InstallerNode {
            param($Node)
            ($Node -is [System.Management.Automation.Language.CommandAst]) -and
                ($Node.GetCommandName() -eq 'Get-GeoFile') -and
                ($Node.CommandElements.Count -eq 2) -and
                ($Node.CommandElements[1] -is [System.Management.Automation.Language.StringConstantExpressionAst])
        } | ForEach-Object { $_.CommandElements[1].Value })
    $GeoName = @($GeoNames | Where-Object { $_ -match '-asn-' }) + $GeoNames | Select-Object -First 1
    if (-not $GeoName) {
        throw 'install.ps1 never calls Get-GeoFile with a database name'
    }

    # The installer's TLS setup, run as written, since Windows PowerShell 5.1
    # may not offer TLS 1.2 on its own: the statements in the same block
    # that lead up to setting SecurityProtocol. If it fails, TLS 1.2 is set
    # here so the download checks still run.
    $Assignments = @(Find-InstallerNode {
            param($Node)
            ($Node -is [System.Management.Automation.Language.AssignmentStatementAst]) -and
                ($Node.Left -is [System.Management.Automation.Language.MemberExpressionAst]) -and
                ($Node.Left.Member.Extent.Text -eq 'SecurityProtocol')
        })
    if ($Assignments.Count -ne 1) {
        throw "install.ps1 sets SecurityProtocol $($Assignments.Count) times; expected once"
    }
    $Statements = @($Assignments[0].Parent.Statements)
    $End = -1
    for ($i = 0; $i -lt $Statements.Count; $i++) {
        if ($Statements[$i].Extent.StartOffset -eq $Assignments[0].Extent.StartOffset) {
            $End = $i
        }
    }
    if ($End -lt 0) {
        throw 'cannot find the SecurityProtocol assignment among its own block'
    }
    $Start = $End
    while (($Start -gt 0) -and ($Statements[$Start - 1].Extent.Text -match 'Tls')) {
        $Start--
    }
    $TlsSetup = @($Statements[$Start..$End] | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
    $Message = Get-ErrorMessage { . ([ScriptBlock]::Create($TlsSetup)) }
    $Protocols = [Net.ServicePointManager]::SecurityProtocol
    # A lookup that quietly fails on one runtime still leaves TLS 1.2, so
    # TLS 1.3 is checked on its own wherever this runtime knows it.
    $KnowsTls13 = [Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13'
    if ($null -ne $Message) {
        Fail "the installer's TLS setup fails: $Message"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } elseif (-not $Protocols.HasFlag([Net.SecurityProtocolType]::Tls12)) {
        Fail "the installer's TLS setup leaves $Protocols, without TLS 1.2"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } elseif ($KnowsTls13 -and (-not $Protocols.HasFlag([Net.SecurityProtocolType]'Tls13'))) {
        Fail "the installer's TLS setup leaves $Protocols, without TLS 1.3, which this runtime has"
    } else {
        Pass "the installer's TLS setup runs and offers $Protocols"
    }

    $Work = Join-Path ([System.IO.Path]::GetTempPath()) ('meow-install-checks-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $Work | Out-Null

    # The check of the Cargo settings in the folders above the installer:
    # what this user made is its own; once every account may change it, not.
    $Dir = New-CheckFolder 'owner'
    $Target = Join-Path $Dir 'config.toml'
    [System.IO.File]::WriteAllText($Target, '')
    if ((Test-OwnPath $Dir) -and (Test-OwnPath $Target)) {
        Pass 'Test-OwnPath counts a folder and a file this user made as its own'
    } else {
        Fail 'Test-OwnPath does not count a folder and a file this user made as its own'
    }
    $Acl = Get-Acl -LiteralPath $Target
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Everyone, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.AccessControlType]::Allow)
    $Acl.AddAccessRule($Rule)
    Set-Acl -LiteralPath $Target -AclObject $Acl
    if (Test-OwnPath $Target) {
        Fail 'Test-OwnPath counts a file every account may change as its own'
    } else {
        Pass 'Test-OwnPath does not count a file every account may change as its own'
    }
    if (Test-OwnPath (Join-Path $Dir 'missing')) {
        Fail 'Test-OwnPath counts a file it cannot read as its own'
    } else {
        Pass 'Test-OwnPath does not count a file it cannot read as its own'
    }

    # A .cargo the user keeps on another disk through a junction of their
    # own is taken while what it leads to is theirs alone and a folder; a
    # link in a folder others can change, to the wrong kind of thing, or
    # that leads nowhere, is not.
    $UserDir = New-CheckFolder 'profile'
    $CargoHome = New-CheckFolder 'cargo-home'
    New-Item -ItemType Junction -Path (Join-Path $UserDir '.cargo') -Target $CargoHome | Out-Null
    $Problem = Get-CargoSettingProblem $UserDir '.cargo'
    if ($null -eq $Problem) {
        Pass 'a .cargo junction to a folder of the user''s own is taken'
    } else {
        Fail "a .cargo junction to a folder of the user's own is refused: $Problem"
    }
    if ($null -eq (Get-CargoSettingProblem $UserDir 'rust-toolchain.toml')) {
        Pass 'nothing is wrong with settings that are not there'
    } else {
        Fail 'settings that are not there are refused'
    }
    $Acl = Get-Acl -LiteralPath $CargoHome
    $Acl.AddAccessRule($Rule)
    Set-Acl -LiteralPath $CargoHome -AclObject $Acl
    $Problem = Get-CargoSettingProblem $UserDir '.cargo'
    if (($null -ne $Problem) -and ($Problem -match '^leads to ')) {
        Pass "a .cargo junction to a folder every account may change is refused: $Problem"
    } else {
        Fail "a .cargo junction to a folder every account may change is not refused: $Problem"
    }
    # A settings file may be a link of the user's own, but only to a file.
    New-Item -ItemType Junction -Path (Join-Path $UserDir 'rust-toolchain') -Target $CargoHome | Out-Null
    $Problem = Get-CargoSettingProblem $UserDir 'rust-toolchain'
    if (($null -ne $Problem) -and ($Problem -match 'which is not a file$')) {
        Pass "a rust-toolchain link to a folder is refused: $Problem"
    } else {
        Fail "a rust-toolchain link to a folder is not refused: $Problem"
    }
    # A link in a folder other accounts can change is refused, wherever it leads.
    $OpenDir = New-CheckFolder 'open'
    $OwnCargo = New-CheckFolder 'own-cargo'
    New-Item -ItemType Junction -Path (Join-Path $OpenDir '.cargo') -Target $OwnCargo | Out-Null
    $Acl = Get-Acl -LiteralPath $OpenDir
    $Acl.AddAccessRule($Rule)
    Set-Acl -LiteralPath $OpenDir -AclObject $Acl
    $Problem = Get-CargoSettingProblem $OpenDir '.cargo'
    if ($Problem -eq 'is a link') {
        Pass 'a .cargo junction in a folder every account may change is refused'
    } else {
        Fail "a .cargo junction in a folder every account may change is not refused: $Problem"
    }
    $Gone = New-CheckFolder 'gone'
    $Dangling = New-CheckFolder 'dangling'
    New-Item -ItemType Junction -Path (Join-Path $Dangling '.cargo') -Target $Gone | Out-Null
    [System.IO.Directory]::Delete($Gone)
    if ((Get-CargoSettingProblem $Dangling '.cargo') -eq 'is a link that leads nowhere') {
        Pass 'a .cargo junction that leads nowhere is refused'
    } else {
        Fail 'a .cargo junction that leads nowhere is not refused'
    }

    # Only HTTPS is fetched; nothing is requested or written for another scheme.
    $Dir = New-CheckFolder 'scheme'
    $Target = Join-Path $Dir 'download'
    foreach ($Url in @(($WordlistUrl -replace '^https:', 'http:'), 'file:///C:/Windows/win.ini')) {
        $Message = Get-ErrorMessage { Invoke-InstallerDownload -Url $Url -OutFile $Target -MaxBytes $WordlistLimit }
        $Left = @(Get-Leftovers $Dir)
        if (($null -eq $Message) -or ($Message -notmatch 'non-HTTPS')) {
            Fail "Invoke-SafeDownload did not refuse $Url (error: $Message)"
        } elseif ($Left.Count -ne 0) {
            Fail "Invoke-SafeDownload refused $Url but left $($Left -join ', ')"
        } else {
            Pass "Invoke-SafeDownload refuses $Url"
        }
    }

    # A body over the limit stops the download with the size-limit error and
    # leaves no file.
    $Dir = New-CheckFolder 'wordlist-limit'
    $Target = Join-Path $Dir 'common.txt'
    $Message = Get-ErrorMessage { Invoke-InstallerDownload -Url $WordlistUrl -OutFile $Target -MaxBytes 1000 }
    $Left = @(Get-Leftovers $Dir)
    if (($null -eq $Message) -or ($Message -notmatch 'exceeds size limit')) {
        Fail "a 1000-byte limit did not stop the wordlist download (error: $Message)"
    } elseif ($Left.Count -ne 0) {
        Fail "the wordlist download stopped at its limit but left $($Left -join ', ')"
    } else {
        Pass 'a 1000-byte limit stops the wordlist download and leaves no file'
    }

    # The installer's own limit lets the wordlist through, and it is the
    # file the installer pins.
    $Dir = New-CheckFolder 'wordlist'
    $Target = Join-Path $Dir 'common.txt'
    $Message = Get-ErrorMessage { Invoke-InstallerDownload -Url $WordlistUrl -OutFile $Target -MaxBytes $WordlistLimit }
    if ($null -ne $Message) {
        Fail "the wordlist download failed within its $WordlistLimit-byte limit: $Message"
    } else {
        $Hash = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash
        if ($Hash -ne $WordlistSha256) {
            Fail "the wordlist's SHA-256 is $Hash; install.ps1 pins $WordlistSha256"
        } else {
            Pass "the wordlist downloads within its $WordlistLimit-byte limit and matches its pinned SHA-256"
        }
    }

    # Get-GeoFile with a packed limit too small for the file: the download
    # stops at the limit and nothing is left in the folder.
    $Geo = Invoke-GeoFile 'geo-packed' $GeoName 1000 $RealGeoMaxBytes
    $Left = @(Get-Leftovers $Geo.Dir)
    $Stops = @($DownloadLog | Where-Object { $_ -match 'exceeds size limit' })
    if ($Geo.Saved) {
        Fail "Get-GeoFile $GeoName saved the database despite a 1000-byte packed limit"
    } elseif ($Stops.Count -eq 0) {
        Fail "Get-GeoFile $GeoName failed, but not at the packed limit: $($DownloadLog -join '; ')"
    } elseif ($Left.Count -ne 0) {
        Fail "Get-GeoFile $GeoName stopped at the packed limit but left $($Left -join ', ')"
    } else {
        Pass "Get-GeoFile $GeoName stops at a 1000-byte packed limit and leaves nothing"
    }

    # The packed file within its limit but an unpacked limit too small: the
    # download completes, unpacking stops, and nothing is left.
    $Geo = Invoke-GeoFile 'geo-unpacked' $GeoName $RealGeoMaxPacked 1000
    $Left = @(Get-Leftovers $Geo.Dir)
    $Done = @($DownloadLog | Where-Object { $_ -eq 'done' })
    if ($Geo.Saved) {
        Fail "Get-GeoFile $GeoName saved the database despite a 1000-byte unpacked limit"
    } elseif ($Done.Count -eq 0) {
        Fail "Get-GeoFile $GeoName never got the packed file, so the unpacked limit went untested: $($DownloadLog -join '; ')"
    } elseif ($Left.Count -ne 0) {
        Fail "Get-GeoFile $GeoName stopped at the unpacked limit but left $($Left -join ', ')"
    } else {
        Pass "Get-GeoFile $GeoName stops at a 1000-byte unpacked limit and leaves nothing"
    }

    # The installer's own limits: the database is saved, and only it is left.
    $Geo = Invoke-GeoFile 'geo' $GeoName $RealGeoMaxPacked $RealGeoMaxBytes
    $Left = @(Get-Leftovers $Geo.Dir)
    if (-not $Geo.Saved) {
        Fail "Get-GeoFile $GeoName failed within the installer's limits: $($DownloadLog -join '; ')"
    } elseif (($Left.Count -ne 1) -or ($Left[0] -ne "$GeoName.mmdb")) {
        Fail "Get-GeoFile $GeoName saved the database but the folder holds $($Left -join ', ')"
    } else {
        Pass "Get-GeoFile $GeoName saves $GeoName.mmdb within the installer's limits and leaves nothing else"
    }
} catch {
    Fail "stopped at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
} finally {
    if ($Work -and (Test-Path -LiteralPath $Work)) {
        Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($Failures.Count -gt 0) {
    Write-Host "$($Failures.Count) install.ps1 check(s) failed."
    exit 1
}
Write-Host 'All install.ps1 checks passed.'
exit 0
