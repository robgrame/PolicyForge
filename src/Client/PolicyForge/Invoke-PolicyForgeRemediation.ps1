<#
.SYNOPSIS
    PolicyForge multi-provider client dispatcher (detection + inline remediation).

.DESCRIPTION
    Converges a Windows device to the desired-state configuration produced by the PolicyForge
    server. The server compiles authored configuration items into a flat ResolvedConfiguration:

        {
          "deviceId": "...",
          "hash": "....",
          "instructions": [
            { "provider": "RegistryValue", "action": "Set",
              "data": { "hive": "Hklm", "key": "SOFTWARE\\...", "name": "...", "type": "Dword", "data": 2 } },
            { "provider": "EnvironmentVariable", "action": "Set",
              "data": { "name": "PF_HOME", "scope": "Machine", "value": "C:\\PolicyForge" } },
            ...
          ]
        }

    Each instruction is dispatched to a provider handler that implements Test (detect drift) and
    Apply (remediate). Supported providers: RegistryValue, WindowsService, ScheduledTask,
    FileResource, LocalGroupMembership, EnvironmentVariable. AdmxPolicy items are compiled to
    RegistryValue instructions server-side, so this client never needs Chrome/ADMX-specific logic.

.PARAMETER ApiBaseUrl
    Base URL of the PolicyForge API. The resolved configuration is fetched from
    "$ApiBaseUrl/api/configuration/resolve/$DeviceId". Ignored when -InputJson is supplied.

.PARAMETER DeviceId
    Entra device registration id (from dsregcmd). Defaults to the value reported by dsregcmd.

.PARAMETER Mode
    Detect  - report compliance only (no changes). Exit 1 if any drift is found (Intune detection).
    Enforce - apply remediations for any drift, capture a rollback snapshot, then re-test.
    Undo    - restore the prior state captured by the most recent (or -SnapshotPath) Enforce snapshot.

.PARAMETER InputJson
    Optional path to a local ResolvedConfiguration JSON file. Bypasses the API call (for testing).

.PARAMETER SnapshotPath
    Undo mode: explicit snapshot file to restore from. Defaults to the most recent snapshot in
    %ProgramData%\PolicyForge\snapshots.

.PARAMETER NoSnapshot
    Enforce mode: skip writing the rollback snapshot (and skip uploading it to the server).

.PARAMETER LogPath
    Optional log file path. Defaults to %ProgramData%\PolicyForge\client.log.

.NOTES
    Designed to run as SYSTEM (Intune Proactive Remediation). HKCU / per-user items require a
    user-context runner and are out of scope for the SYSTEM pass.

    Rollback model: before remediating, the dispatcher computes an "inverse instruction" capturing
    the current state of each drifted item. The inverses form a ResolvedConfiguration that the SAME
    dispatcher can apply to restore the prior state (Undo mode). Snapshots are stored locally and,
    when an API base URL is available, uploaded to the server for audit/visibility.
#>
[CmdletBinding()]
param(
    [string]$ApiBaseUrl,
    [string]$DeviceId,
    [ValidateSet('Detect', 'Enforce', 'Undo')]
    [string]$Mode = 'Detect',
    [string]$InputJson,
    [string]$SnapshotPath,
    [switch]$NoSnapshot,
    [string]$LogPath = (Join-Path $env:ProgramData 'PolicyForge\client.log')
)

$ErrorActionPreference = 'Stop'
$script:SnapshotDir = Join-Path $env:ProgramData 'PolicyForge\snapshots'

# ---------------------------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------------------------

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        $dir = Split-Path -Parent $LogPath
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -LiteralPath $LogPath -Value $line -ErrorAction SilentlyContinue
    } catch { }
    Write-Verbose $line
}

function Get-DsregDeviceId {
    try {
        $out = & dsregcmd /status 2>$null
        $m = $out | Select-String -Pattern 'DeviceId\s*:\s*([0-9a-fA-F-]{36})'
        if ($m) { return $m.Matches[0].Groups[1].Value }
    } catch { }
    return $null
}

# Status values for a single instruction result.
#   Compliant  - already in desired state
#   Drifted    - not in desired state (Detect mode, or before Enforce)
#   Remediated - was drifted, Apply succeeded and re-test passed
#   Error      - handler threw or re-test failed
function New-Result {
    param($Instruction, [string]$Status, [string]$Detail = '')
    [pscustomobject]@{
        SourceItemId = $Instruction.sourceItemId
        Provider     = $Instruction.provider
        Action       = $Instruction.action
        Name         = $Instruction.name
        Status       = $Status
        Detail       = $Detail
    }
}

# ---------------------------------------------------------------------------------------------
# Registry helpers (shared by RegistryValue; AdmxPolicy compiles to RegistryValue server-side)
# ---------------------------------------------------------------------------------------------

$script:HiveDriveMap = @{
    'Hklm' = 'HKLM:'; 'Hkcu' = 'HKCU:'; 'Hkcr' = 'HKCR:'; 'Hku' = 'HKU:'; 'Hkcc' = 'HKCC:'
}
$script:RegKindMap = @{
    'String' = 'String'; 'ExpandString' = 'ExpandString'; 'MultiString' = 'MultiString'
    'Dword' = 'DWord'; 'Qword' = 'QWord'; 'Binary' = 'Binary'
}

function Resolve-RegPath {
    param($Data)
    $drive = $script:HiveDriveMap[[string]$Data.hive]
    if (-not $drive) { throw "Unknown registry hive '$($Data.hive)'." }
    $key = ([string]$Data.key).TrimStart('\')
    return "$drive\$key"
}

function ConvertTo-RegValue {
    param($Data)
    switch ([string]$Data.type) {
        'Dword' { return [int64]$Data.data }
        'Qword' { return [int64]$Data.data }
        'MultiString' { return [string[]]$Data.data }
        'Binary' {
            if ($Data.data -is [string]) { return [byte[]][Convert]::FromBase64String($Data.data) }
            return [byte[]]$Data.data
        }
        default { return [string]$Data.data }
    }
}

function Test-RegistryValueInstruction {
    param($Data, [string]$Action)
    $path = Resolve-RegPath $Data
    $name = [string]$Data.name

    if ($Action -eq 'Remove') {
        if (-not (Test-Path $path)) { return $true }
        if ([string]::IsNullOrEmpty($name)) { return -not (Test-Path $path) }
        $existing = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue
        return ($null -eq $existing)
    }

    if (-not (Test-Path $path)) { return $false }
    $current = (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue)
    if ($null -eq $current) { return $false }
    $currentValue = $current.$name
    $expected = ConvertTo-RegValue $Data

    if ($expected -is [array]) {
        if ($currentValue -isnot [array]) { return $false }
        return (@(Compare-Object $currentValue $expected -SyncWindow 0).Count -eq 0)
    }
    return ([string]$currentValue -eq [string]$expected)
}

function Set-RegistryValueInstruction {
    param($Data, [string]$Action)
    $path = Resolve-RegPath $Data
    $name = [string]$Data.name

    if ($Action -eq 'Remove') {
        if ([string]::IsNullOrEmpty($name)) {
            if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force }
        } elseif (Test-Path $path) {
            Remove-ItemProperty -LiteralPath $path -Name $name -Force -ErrorAction SilentlyContinue
        }
        return
    }

    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    $propType = $script:RegKindMap[[string]$Data.type]
    if (-not $propType) { $propType = 'String' }
    $value = ConvertTo-RegValue $Data
    New-ItemProperty -LiteralPath $path -Name $name -Value $value -PropertyType $propType -Force | Out-Null
}

# ---------------------------------------------------------------------------------------------
# EnvironmentVariable
# ---------------------------------------------------------------------------------------------

function Get-EnvScope {
    param($Data)
    if ([string]$Data.scope -eq 'User') { return [System.EnvironmentVariableTarget]::User }
    return [System.EnvironmentVariableTarget]::Machine
}

function Test-EnvironmentVariableInstruction {
    param($Data, [string]$Action)
    $scope = Get-EnvScope $Data
    $current = [Environment]::GetEnvironmentVariable([string]$Data.name, $scope)
    if ($Action -eq 'Remove') { return ($null -eq $current) }
    return ([string]$current -eq [string]$Data.value)
}

function Set-EnvironmentVariableInstruction {
    param($Data, [string]$Action)
    $scope = Get-EnvScope $Data
    if ($Action -eq 'Remove') {
        [Environment]::SetEnvironmentVariable([string]$Data.name, $null, $scope)
    } else {
        [Environment]::SetEnvironmentVariable([string]$Data.name, [string]$Data.value, $scope)
    }
}

# ---------------------------------------------------------------------------------------------
# WindowsService
# ---------------------------------------------------------------------------------------------

$script:StartupTypeMap = @{
    'Automatic' = 'Automatic'; 'AutomaticDelayedStart' = 'Automatic'; 'Manual' = 'Manual'; 'Disabled' = 'Disabled'
}

function Test-WindowsServiceInstruction {
    param($Data, [string]$Action)
    $svc = Get-Service -Name ([string]$Data.name) -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return $false }

    $startup = [string]$Data.startupType
    if ($startup -and $startup -ne 'Unchanged') {
        $desired = $script:StartupTypeMap[$startup]
        if ($desired -and ([string]$svc.StartType -ne $desired)) { return $false }
    }
    $state = [string]$Data.state
    if ($state -eq 'Running' -and $svc.Status -ne 'Running') { return $false }
    if ($state -eq 'Stopped' -and $svc.Status -ne 'Stopped') { return $false }
    return $true
}

function Set-WindowsServiceInstruction {
    param($Data, [string]$Action)
    $name = [string]$Data.name
    $startup = [string]$Data.startupType

    if ($startup -and $startup -ne 'Unchanged') {
        if ($startup -eq 'AutomaticDelayedStart') {
            & sc.exe config $name start= delayed-auto | Out-Null
        } else {
            Set-Service -Name $name -StartupType $script:StartupTypeMap[$startup]
        }
    }
    if ($Data.account) {
        & sc.exe config $name obj= ([string]$Data.account) | Out-Null
    }
    $state = [string]$Data.state
    if ($state -eq 'Running') { Start-Service -Name $name }
    elseif ($state -eq 'Stopped') { Stop-Service -Name $name -Force }
}

# ---------------------------------------------------------------------------------------------
# ScheduledTask
# ---------------------------------------------------------------------------------------------

function Test-ScheduledTaskInstruction {
    param($Data, [string]$Action)
    $path = [string]$Data.path; if (-not $path) { $path = '\' }
    $task = Get-ScheduledTask -TaskName ([string]$Data.name) -TaskPath $path -ErrorAction SilentlyContinue

    if ($Action -eq 'Remove') { return ($null -eq $task) }
    if ($null -eq $task) { return $false }

    $state = [string]$Data.state
    if ($state -eq 'Enabled' -and $task.State -eq 'Disabled') { return $false }
    if ($state -eq 'Disabled' -and $task.State -ne 'Disabled') { return $false }
    return $true
}

function Set-ScheduledTaskInstruction {
    param($Data, [string]$Action)
    $name = [string]$Data.name
    $path = [string]$Data.path; if (-not $path) { $path = '\' }

    if ($Action -eq 'Remove') {
        Unregister-ScheduledTask -TaskName $name -TaskPath $path -Confirm:$false -ErrorAction SilentlyContinue
        return
    }
    if ($Data.definitionXml) {
        Register-ScheduledTask -TaskName $name -TaskPath $path -Xml ([string]$Data.definitionXml) -Force | Out-Null
    }
    $state = [string]$Data.state
    if ($state -eq 'Enabled') { Enable-ScheduledTask -TaskName $name -TaskPath $path | Out-Null }
    elseif ($state -eq 'Disabled') { Disable-ScheduledTask -TaskName $name -TaskPath $path | Out-Null }
}

# ---------------------------------------------------------------------------------------------
# FileResource
# ---------------------------------------------------------------------------------------------

function Get-DesiredFileContent {
    param($Data)
    if ([string]$Data.contentEncoding -eq 'Base64') {
        return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$Data.content))
    }
    return [string]$Data.content
}

function Test-FileResourceInstruction {
    param($Data, [string]$Action)
    $target = [string]$Data.targetPath
    $type = [string]$Data.resourceType

    if ($Action -eq 'Remove') { return -not (Test-Path -LiteralPath $target) }

    switch ($type) {
        'Directory' { return (Test-Path -LiteralPath $target -PathType Container) }
        'Shortcut'  { return (Test-Path -LiteralPath $target) }
        default {
            if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { return $false }
            if ($Data.sourceUrl) { return $true } # remote source: presence is enough
            $desired = Get-DesiredFileContent $Data
            $current = Get-Content -LiteralPath $target -Raw -ErrorAction SilentlyContinue
            return ([string]$current -eq [string]$desired)
        }
    }
}

function Set-FileResourceInstruction {
    param($Data, [string]$Action)
    $target = [string]$Data.targetPath
    $type = [string]$Data.resourceType

    if ($Action -eq 'Remove') {
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
        return
    }

    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

    switch ($type) {
        'Directory' {
            if (-not (Test-Path -LiteralPath $target)) { New-Item -ItemType Directory -Path $target -Force | Out-Null }
        }
        'Shortcut' {
            $shell = New-Object -ComObject WScript.Shell
            $lnk = $shell.CreateShortcut($target)
            $lnk.TargetPath = [string]$Data.targetExecutable
            if ($Data.arguments) { $lnk.Arguments = [string]$Data.arguments }
            if ($Data.workingDirectory) { $lnk.WorkingDirectory = [string]$Data.workingDirectory }
            if ($Data.iconPath) { $lnk.IconLocation = [string]$Data.iconPath }
            if ($Data.description) { $lnk.Description = [string]$Data.description }
            $lnk.Save()
        }
        default {
            if ($Data.sourceUrl) {
                Invoke-WebRequest -Uri ([string]$Data.sourceUrl) -OutFile $target -UseBasicParsing
            } else {
                Set-Content -LiteralPath $target -Value (Get-DesiredFileContent $Data) -NoNewline -Force
            }
        }
    }
}

# ---------------------------------------------------------------------------------------------
# LocalGroupMembership
# ---------------------------------------------------------------------------------------------

function Get-GroupMemberNames {
    param([string]$Group)
    try {
        return @(Get-LocalGroupMember -Group $Group -ErrorAction Stop | ForEach-Object { $_.Name })
    } catch {
        return @()
    }
}

function Test-LocalGroupMembershipInstruction {
    param($Data, [string]$Action)
    $group = [string]$Data.group
    $members = @($Data.members)
    $current = Get-GroupMemberNames -Group $group
    $leaf = { param($n) ($n -split '\\')[-1] }
    $currentLeaf = @($current | ForEach-Object { & $leaf $_ })
    $desiredLeaf = @($members | ForEach-Object { & $leaf $_ })

    switch ([string]$Data.action) {
        'Remove'  { return -not ($desiredLeaf | Where-Object { $currentLeaf -contains $_ }) }
        'Replace' {
            if ($currentLeaf.Count -ne $desiredLeaf.Count) { return $false }
            return (@(Compare-Object $currentLeaf $desiredLeaf).Count -eq 0)
        }
        default   { return -not ($desiredLeaf | Where-Object { $currentLeaf -notcontains $_ }) } # Add
    }
}

function Set-LocalGroupMembershipInstruction {
    param($Data, [string]$Action)
    $group = [string]$Data.group
    $members = @($Data.members)

    switch ([string]$Data.action) {
        'Remove' {
            foreach ($m in $members) { Remove-LocalGroupMember -Group $group -Member $m -ErrorAction SilentlyContinue }
        }
        'Replace' {
            $current = Get-GroupMemberNames -Group $group
            foreach ($m in $current) { Remove-LocalGroupMember -Group $group -Member $m -ErrorAction SilentlyContinue }
            foreach ($m in $members) { Add-LocalGroupMember -Group $group -Member $m -ErrorAction SilentlyContinue }
        }
        default {
            foreach ($m in $members) { Add-LocalGroupMember -Group $group -Member $m -ErrorAction SilentlyContinue }
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Inverse capture (rollback). Each function returns an instruction object that, when applied by
# the same dispatcher, restores the item's CURRENT state. Called just BEFORE remediation, so the
# captured state is the pre-change state. Returns $null when the item cannot be safely snapshotted.
# ---------------------------------------------------------------------------------------------

function Get-RegistryValueInverse {
    param($Data, [string]$Action)
    $path = Resolve-RegPath $Data
    $name = [string]$Data.name

    $exists = $false; $prevValue = $null; $prevKind = $null
    if (Test-Path $path) {
        $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($item -and ($item.GetValueNames() -contains $name)) {
            try { $prevKind = $item.GetValueKind($name); $prevValue = $item.GetValue($name); $exists = $true } catch { }
        }
    }

    if ($exists) {
        $typeStr = switch ([string]$prevKind) {
            'DWord' { 'Dword' } 'QWord' { 'Qword' } default { [string]$prevKind }
        }
        $dataVal = $prevValue
        if ([string]$prevKind -eq 'Binary') { $dataVal = [Convert]::ToBase64String([byte[]]$prevValue) }
        return [pscustomobject]@{
            provider = 'RegistryValue'; action = 'Set'; name = $Data.name
            data = [pscustomobject]@{ hive = $Data.hive; key = $Data.key; name = $name; type = $typeStr; data = $dataVal }
        }
    }
    # Value/key didn't exist -> inverse removes what Enforce created.
    return [pscustomobject]@{
        provider = 'RegistryValue'; action = 'Remove'; name = $Data.name
        data = [pscustomobject]@{ hive = $Data.hive; key = $Data.key; name = $name }
    }
}

function Get-EnvironmentVariableInverse {
    param($Data, [string]$Action)
    $scope = Get-EnvScope $Data
    $prev = [Environment]::GetEnvironmentVariable([string]$Data.name, $scope)
    if ($null -eq $prev) {
        return [pscustomobject]@{
            provider = 'EnvironmentVariable'; action = 'Remove'; name = $Data.name
            data = [pscustomobject]@{ name = $Data.name; scope = $Data.scope }
        }
    }
    return [pscustomobject]@{
        provider = 'EnvironmentVariable'; action = 'Set'; name = $Data.name
        data = [pscustomobject]@{ name = $Data.name; scope = $Data.scope; value = $prev }
    }
}

function Get-WindowsServiceInverse {
    param($Data, [string]$Action)
    $svc = Get-Service -Name ([string]$Data.name) -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return $null } # cannot recreate a missing service

    $startMap = @{ 'Automatic' = 'Automatic'; 'Manual' = 'Manual'; 'Disabled' = 'Disabled' }
    $prevStartup = $startMap[[string]$svc.StartType]; if (-not $prevStartup) { $prevStartup = 'Unchanged' }
    $prevState = if ($svc.Status -eq 'Running') { 'Running' } elseif ($svc.Status -eq 'Stopped') { 'Stopped' } else { 'Unchanged' }
    return [pscustomobject]@{
        provider = 'WindowsService'; action = 'Set'; name = $Data.name
        data = [pscustomobject]@{ name = $Data.name; startupType = $prevStartup; state = $prevState }
    }
}

function Get-ScheduledTaskInverse {
    param($Data, [string]$Action)
    $path = [string]$Data.path; if (-not $path) { $path = '\' }
    $task = Get-ScheduledTask -TaskName ([string]$Data.name) -TaskPath $path -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        return [pscustomobject]@{
            provider = 'ScheduledTask'; action = 'Remove'; name = $Data.name
            data = [pscustomobject]@{ name = $Data.name; path = $path }
        }
    }
    $prevState = if ($task.State -eq 'Disabled') { 'Disabled' } else { 'Enabled' }
    return [pscustomobject]@{
        provider = 'ScheduledTask'; action = 'Set'; name = $Data.name
        data = [pscustomobject]@{ name = $Data.name; path = $path; state = $prevState }
    }
}

function Get-FileResourceInverse {
    param($Data, [string]$Action)
    $target = [string]$Data.targetPath
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        try {
            $bytes = [IO.File]::ReadAllBytes($target)
            if ($bytes.Length -le 1MB) {
                return [pscustomobject]@{
                    provider = 'FileResource'; action = 'Set'; name = $Data.name
                    data = [pscustomobject]@{ targetPath = $target; resourceType = 'File'; contentEncoding = 'Base64'; content = [Convert]::ToBase64String($bytes) }
                }
            }
        } catch { }
        return $null # too large / unreadable to snapshot safely
    }
    if (Test-Path -LiteralPath $target -PathType Container) { return $null } # directory restore non-trivial
    # Didn't exist -> inverse removes what Enforce created.
    return [pscustomobject]@{
        provider = 'FileResource'; action = 'Remove'; name = $Data.name
        data = [pscustomobject]@{ targetPath = $target; resourceType = [string]$Data.resourceType }
    }
}

function Get-LocalGroupMembershipInverse {
    param($Data, [string]$Action)
    $group = [string]$Data.group
    $current = Get-GroupMemberNames -Group $group
    return [pscustomobject]@{
        provider = 'LocalGroupMembership'; action = 'Set'; name = $Data.name
        data = [pscustomobject]@{ group = $group; action = 'Replace'; members = @($current) }
    }
}

# ---------------------------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------------------------

$script:Handlers = @{
    'RegistryValue'        = @{ Test = ${function:Test-RegistryValueInstruction};        Apply = ${function:Set-RegistryValueInstruction} }
    'EnvironmentVariable'  = @{ Test = ${function:Test-EnvironmentVariableInstruction};  Apply = ${function:Set-EnvironmentVariableInstruction} }
    'WindowsService'       = @{ Test = ${function:Test-WindowsServiceInstruction};       Apply = ${function:Set-WindowsServiceInstruction} }
    'ScheduledTask'        = @{ Test = ${function:Test-ScheduledTaskInstruction};        Apply = ${function:Set-ScheduledTaskInstruction} }
    'FileResource'         = @{ Test = ${function:Test-FileResourceInstruction};         Apply = ${function:Set-FileResourceInstruction} }
    'LocalGroupMembership' = @{ Test = ${function:Test-LocalGroupMembershipInstruction}; Apply = ${function:Set-LocalGroupMembershipInstruction} }
}

# Inverse capture for rollback. Providers without an inverter cannot be rolled back.
$script:Inverters = @{
    'RegistryValue'        = ${function:Get-RegistryValueInverse}
    'EnvironmentVariable'  = ${function:Get-EnvironmentVariableInverse}
    'WindowsService'       = ${function:Get-WindowsServiceInverse}
    'ScheduledTask'        = ${function:Get-ScheduledTaskInverse}
    'FileResource'         = ${function:Get-FileResourceInverse}
    'LocalGroupMembership' = ${function:Get-LocalGroupMembershipInverse}
}

function Invoke-Instruction {
    param($Instruction, [string]$Mode)
    $provider = [string]$Instruction.provider
    $handler = $script:Handlers[$provider]
    if ($null -eq $handler) {
        return New-Result -Instruction $Instruction -Status 'Error' -Detail "No client handler for provider '$provider'."
    }

    $data = $Instruction.data
    $action = [string]$Instruction.action

    try {
        $compliant = & $handler.Test $data $action
        if ($compliant) { return New-Result -Instruction $Instruction -Status 'Compliant' }
        if ($Mode -eq 'Detect') { return New-Result -Instruction $Instruction -Status 'Drifted' }

        # Enforce: capture the inverse (pre-change state) BEFORE applying, for rollback.
        $inverse = $null
        if (-not $NoSnapshot) {
            $inverter = $script:Inverters[$provider]
            if ($inverter) { try { $inverse = & $inverter $data $action } catch { Write-Log "Inverse capture failed for $provider/$($Instruction.name): $($_.Exception.Message)" 'WARN' } }
        }

        & $handler.Apply $data $action
        $recheck = & $handler.Test $data $action
        if ($recheck) {
            $r = New-Result -Instruction $Instruction -Status 'Remediated'
            $r | Add-Member -NotePropertyName Inverse -NotePropertyValue $inverse -Force
            return $r
        }
        return New-Result -Instruction $Instruction -Status 'Error' -Detail 'Re-test failed after apply.'
    } catch {
        return New-Result -Instruction $Instruction -Status 'Error' -Detail $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------------------------
# Snapshot / rollback persistence
# ---------------------------------------------------------------------------------------------

function Write-Snapshot {
    param([string]$DeviceId, [string]$Hash, $Inverses)
    $list = @($Inverses | Where-Object { $_ })
    if ($list.Count -eq 0) { return $null }

    if (-not (Test-Path $script:SnapshotDir)) { New-Item -ItemType Directory -Path $script:SnapshotDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $shortHash = if ($Hash) { $Hash.Substring(0, [Math]::Min(8, $Hash.Length)) } else { 'nohash' }
    $file = Join-Path $script:SnapshotDir ("{0}_{1}.json" -f $stamp, $shortHash)

    # Apply inverses in reverse order of how the forward instructions were applied.
    [array]::Reverse($list)
    $snap = [pscustomobject]@{
        deviceId     = $DeviceId
        capturedAt   = (Get-Date).ToString('o')
        forwardHash  = $Hash
        instructions = $list
    }
    $snap | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $file -Encoding UTF8
    Write-Log "Rollback snapshot written: $file ($($list.Count) item(s))"
    return $file
}

function Send-SnapshotToServer {
    param([string]$File)
    if (-not $File -or -not $ApiBaseUrl -or $InputJson) { return }
    try {
        $body = Get-Content -LiteralPath $File -Raw
        $uri = "$ApiBaseUrl/api/configuration/snapshots"
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -UseBasicParsing | Out-Null
        Write-Log "Snapshot uploaded to $uri"
    } catch {
        Write-Log "Snapshot upload failed: $($_.Exception.Message)" 'WARN'
    }
}

function Resolve-SnapshotFile {
    if ($SnapshotPath) {
        if (-not (Test-Path -LiteralPath $SnapshotPath)) { throw "Snapshot file not found: $SnapshotPath" }
        return $SnapshotPath
    }
    if (-not (Test-Path $script:SnapshotDir)) { return $null }
    $f = Get-ChildItem -Path $script:SnapshotDir -Filter '*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    return $f.FullName
}

function Invoke-Undo {
    $file = Resolve-SnapshotFile
    if (-not $file) { throw 'No rollback snapshot found to undo.' }
    Write-Log "Restoring prior state from snapshot: $file"
    $snap = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    $instructions = @($snap.instructions)

    $results = foreach ($instruction in $instructions) {
        $provider = [string]$instruction.provider
        $handler = $script:Handlers[$provider]
        if ($null -eq $handler) { New-Result -Instruction $instruction -Status 'Error' -Detail "No handler for '$provider'."; continue }
        try {
            & $handler.Apply $instruction.data ([string]$instruction.action)
            if (& $handler.Test $instruction.data ([string]$instruction.action)) {
                New-Result -Instruction $instruction -Status 'Remediated' -Detail 'Restored'
            } else {
                New-Result -Instruction $instruction -Status 'Error' -Detail 'Re-test failed after restore.'
            }
        } catch {
            New-Result -Instruction $instruction -Status 'Error' -Detail $_.Exception.Message
        }
    }
    $results = @($results)

    $hadError = @($results | Where-Object { $_.Status -eq 'Error' }).Count -gt 0
    if (-not $hadError) {
        $restored = "$file.restored"
        Move-Item -LiteralPath $file -Destination $restored -Force -ErrorAction SilentlyContinue
    }

    [pscustomobject]@{
        DeviceId  = $snap.deviceId
        Mode      = 'Undo'
        Snapshot  = $file
        Compliant = -not $hadError
        Results   = $results
    } | ConvertTo-Json -Depth 6

    if ($hadError) { exit 1 }
    exit 0
}

function Get-ResolvedConfiguration {
    if ($InputJson) {
        Write-Log "Loading resolved configuration from $InputJson"
        return Get-Content -LiteralPath $InputJson -Raw | ConvertFrom-Json
    }
    if (-not $DeviceId) { $DeviceId = Get-DsregDeviceId }
    if (-not $DeviceId) { throw 'DeviceId could not be determined (dsregcmd) and was not supplied.' }
    if (-not $ApiBaseUrl) { throw 'ApiBaseUrl is required when -InputJson is not supplied.' }

    $uri = "$ApiBaseUrl/api/configuration/resolve/$DeviceId"
    Write-Log "Fetching resolved configuration from $uri"
    return Invoke-RestMethod -Uri $uri -Method Get -UseBasicParsing
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

try {
    Write-Log "PolicyForge client starting (Mode=$Mode)"

    if ($Mode -eq 'Undo') { Invoke-Undo }

    $config = Get-ResolvedConfiguration
    $instructions = @($config.instructions)
    Write-Log "Resolved $($instructions.Count) instruction(s), hash=$($config.hash)"

    $results = foreach ($instruction in $instructions) { Invoke-Instruction -Instruction $instruction -Mode $Mode }
    $results = @($results)

    $summary = $results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Log "Result: $($summary -join ', ')"

    # Enforce: persist the rollback snapshot from any remediated items, then upload for audit.
    if ($Mode -eq 'Enforce' -and -not $NoSnapshot) {
        $inverses = @($results | Where-Object { $_.Status -eq 'Remediated' -and $_.PSObject.Properties['Inverse'] } | ForEach-Object { $_.Inverse })
        $snapFile = Write-Snapshot -DeviceId $config.deviceId -Hash $config.hash -Inverses $inverses
        Send-SnapshotToServer -File $snapFile
    }

    $hasDrift = @($results | Where-Object { $_.Status -in @('Drifted', 'Error') }).Count -gt 0

    [pscustomobject]@{
        DeviceId    = $config.deviceId
        Hash        = $config.hash
        Mode        = $Mode
        Compliant   = -not $hasDrift
        Results     = $results | Select-Object SourceItemId, Provider, Action, Name, Status, Detail
    } | ConvertTo-Json -Depth 6

    if ($Mode -eq 'Detect' -and $hasDrift) { exit 1 }
    exit 0
} catch {
    Write-Log "FATAL: $($_.Exception.Message)" 'ERROR'
    Write-Error $_
    exit 1
}
