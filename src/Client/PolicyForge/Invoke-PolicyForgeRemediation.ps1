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
    Detect    - report compliance only (no changes). Exit 1 if any drift is found (Intune detection).
    Enforce   - apply remediations for any drift, capture a rollback snapshot, then re-test.
    Undo      - restore the prior state captured by the most recent (or -SnapshotPath) Enforce snapshot.
    ApplyUser - internal: apply the staged user-scope configuration in the current user's context
                (invoked by the per-user logon scheduled task registered during an Enforce pass).

.PARAMETER InputJson
    Optional path to a local ResolvedConfiguration JSON file. Bypasses the API call (for testing).

.PARAMETER SnapshotPath
    Undo mode: explicit snapshot file to restore from. Defaults to the most recent snapshot in
    %ProgramData%\PolicyForge\snapshots.

.PARAMETER UserScopePath
    Path of the staged user-scope ResolvedConfiguration consumed by ApplyUser mode. Defaults to
    %ProgramData%\PolicyForge\user-scope.json.

.PARAMETER NoSnapshot
    Enforce mode: skip writing the rollback snapshot (and skip uploading it to the server).

.PARAMETER LogPath
    Optional log file path. Defaults to %ProgramData%\PolicyForge\client.log.

.NOTES
    Designed to run as SYSTEM (Intune Proactive Remediation). User-scope items (HKCU registry and
    per-user environment variables) cannot be applied to the right profile from the SYSTEM context.
    The dispatcher handles them two ways:
      1. Immediately, for every currently-loaded user hive, by retargeting the instruction to
         HKEY_USERS\<sid> (so logged-in users converge during the SYSTEM pass).
      2. For future logons / not-loaded profiles, by staging the user-scope config and registering a
         per-user logon scheduled task that re-runs this script in ApplyUser mode (user context).

    Rollback model: before remediating, the dispatcher computes an "inverse instruction" capturing
    the current state of each drifted item. The inverses form a ResolvedConfiguration that the SAME
    dispatcher can apply to restore the prior state (Undo mode). Snapshots are stored locally and,
    when an API base URL is available, uploaded to the server for audit/visibility.
#>
[CmdletBinding()]
param(
    [string]$ApiBaseUrl,
    [string]$DeviceId,
    [ValidateSet('Detect', 'Enforce', 'Undo', 'ApplyUser')]
    [string]$Mode = 'Detect',
    [string]$InputJson,
    [string]$SnapshotPath,
    [string]$UserScopePath = (Join-Path $env:ProgramData 'PolicyForge\user-scope.json'),
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
    'Hklm' = 'Registry::HKEY_LOCAL_MACHINE'
    'Hkcu' = 'Registry::HKEY_CURRENT_USER'
    'Hkcr' = 'Registry::HKEY_CLASSES_ROOT'
    'Hku'  = 'Registry::HKEY_USERS'
    'Hkcc' = 'Registry::HKEY_CURRENT_CONFIG'
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
# User-scope handling (HKCU registry + per-user environment variables)
#
# The SYSTEM context cannot target a user's HKCU/profile directly. We converge user-scope items
# by (1) retargeting them onto every currently-loaded user hive (HKEY_USERS\<sid>) during the
# SYSTEM pass and (2) staging them for a per-user logon scheduled task (ApplyUser mode) so that
# not-loaded and future profiles also converge.
# ---------------------------------------------------------------------------------------------

function Test-IsSystem {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return ($id.User.Value -eq 'S-1-5-18')
    } catch { return $false }
}

function Test-IsUserScopeInstruction {
    param($Instruction)
    $provider = [string]$Instruction.provider
    $data = $Instruction.data
    if ($provider -eq 'RegistryValue' -and ([string]$data.hive -eq 'Hkcu')) { return $true }
    if ($provider -eq 'EnvironmentVariable' -and ([string]$data.scope -eq 'User')) { return $true }
    return $false
}

function Get-LoadedUserSid {
    # Real, interactive user profiles currently loaded under HKEY_USERS (exclude system + _Classes).
    # Includes both on-prem AD/local SIDs (S-1-5-21-...) and Entra ID / Azure AD SIDs (S-1-12-1-...).
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        ForEach-Object { $_.PSChildName } |
        Where-Object { $_ -match '^(S-1-5-21-|S-1-12-1-)' -and $_ -notmatch '_Classes$' }
}

function Copy-Instruction {
    param($Instruction)
    return ($Instruction | ConvertTo-Json -Depth 10 | ConvertFrom-Json)
}

function ConvertTo-UserHiveInstruction {
    # Retarget a user-scope instruction onto a specific loaded user hive (HKEY_USERS\<sid>).
    param($Instruction, [string]$Sid)
    $provider = [string]$Instruction.provider
    $data = $Instruction.data
    $action = [string]$Instruction.action
    $label = [string]$Instruction.name

    if ($provider -eq 'RegistryValue') {
        $clone = Copy-Instruction $Instruction
        $clone.data.hive = 'Hku'
        $clone.data.key = "$Sid\" + ([string]$data.key).TrimStart('\')
        $clone.name = if ($label) { "$label [user $Sid]" } else { "[user $Sid]" }
        return $clone
    }

    if ($provider -eq 'EnvironmentVariable') {
        # Per-user env vars live in HKEY_USERS\<sid>\Environment as registry values.
        $regData = [pscustomobject]@{
            hive   = 'Hku'
            key    = "$Sid\Environment"
            name   = [string]$data.name
            type   = 'String'
            data   = [string]$data.value
            ensure = if ($action -eq 'Remove') { 'Absent' } else { 'Present' }
        }
        return [pscustomobject]@{
            provider     = 'RegistryValue'
            action       = $action
            data         = $regData
            sourceItemId = $Instruction.sourceItemId
            name         = if ($label) { "$label [user $Sid]" } else { "[user $Sid]" }
        }
    }

    return $Instruction
}

function Expand-UserScopeForLoadedUsers {
    # Replace each user-scope instruction with one retargeted instruction per loaded user hive.
    param($Instructions)
    $sids = @(Get-LoadedUserSid)
    $expanded = New-Object System.Collections.Generic.List[object]
    foreach ($i in $Instructions) {
        if (Test-IsUserScopeInstruction $i) {
            if ($sids.Count -eq 0) {
                Write-Log "User-scope item '$($i.name)' has no loaded user hive to apply to now; deferred to logon task." 'WARN'
                continue
            }
            foreach ($sid in $sids) { $expanded.Add((ConvertTo-UserHiveInstruction -Instruction $i -Sid $sid)) }
        } else {
            $expanded.Add($i)
        }
    }
    return $expanded
}

function Save-StableScriptCopy {
    # Intune runs the script from a transient path; the logon task needs a stable on-disk copy.
    $dir = Join-Path $env:ProgramData 'PolicyForge'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $dest = Join-Path $dir 'Invoke-PolicyForgeRemediation.ps1'
    try {
        if ($PSCommandPath -and (Test-Path $PSCommandPath) -and
            ((Resolve-Path $PSCommandPath).Path -ne (Resolve-Path -LiteralPath $dest -ErrorAction SilentlyContinue).Path)) {
            Copy-Item -LiteralPath $PSCommandPath -Destination $dest -Force
        }
    } catch { Write-Log "Could not copy script to stable path: $($_.Exception.Message)" 'WARN' }
    return $dest
}

function Save-UserScopeConfig {
    param([string]$DeviceId, [string]$Hash, $UserInstructions)
    $dir = Split-Path -Parent $UserScopePath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [pscustomobject]@{
        deviceId     = $DeviceId
        hash         = $Hash
        instructions = @($UserInstructions)
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $UserScopePath -Encoding UTF8
    Write-Log "Staged user-scope config ($(@($UserInstructions).Count) item(s)) at $UserScopePath"
}

function Register-UserScopeLogonTask {
    param([string]$ScriptPath)
    $taskName = 'PolicyForge User Apply'
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`" -Mode ApplyUser -UserScopePath `"$UserScopePath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        # Run in the context of any interactive user (BUILTIN\Users), with their (limited) token.
        $principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description 'Applies PolicyForge user-scope configuration at logon.'
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
        Write-Log "Registered per-user logon task '$taskName' -> $ScriptPath"
    } catch {
        Write-Log "Failed to register per-user logon task: $($_.Exception.Message)" 'WARN'
    }
}

function Invoke-ApplyUser {
    # Runs in the actual user's context (logon task): HKCU and User env target the right profile.
    if (-not (Test-Path -LiteralPath $UserScopePath)) {
        Write-Log "No staged user-scope config at $UserScopePath; nothing to apply." 'WARN'
        exit 0
    }
    $cfg = Get-Content -LiteralPath $UserScopePath -Raw | ConvertFrom-Json
    $instructions = @($cfg.instructions)
    Write-Log "ApplyUser: $($instructions.Count) user-scope instruction(s) as $($env:USERNAME)"

    $results = foreach ($i in $instructions) { Invoke-Instruction -Instruction $i -Mode 'Enforce' }
    $results = @($results)
    $summary = $results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Log "ApplyUser result: $($summary -join ', ')"

    [pscustomobject]@{
        Mode      = 'ApplyUser'
        User      = $env:USERNAME
        Compliant = (@($results | Where-Object { $_.Status -eq 'Error' }).Count -eq 0)
        Results   = $results | Select-Object SourceItemId, Provider, Action, Name, Status, Detail
    } | ConvertTo-Json -Depth 6
    exit 0
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

try {
    Write-Log "PolicyForge client starting (Mode=$Mode)"

    if ($Mode -eq 'Undo') { Invoke-Undo }
    if ($Mode -eq 'ApplyUser') { Invoke-ApplyUser }

    $config = Get-ResolvedConfiguration
    $rawInstructions = @($config.instructions)
    Write-Log "Resolved $($rawInstructions.Count) instruction(s), hash=$($config.hash)"

    $userScopeItems = @($rawInstructions | Where-Object { Test-IsUserScopeInstruction $_ })
    $runningAsSystem = Test-IsSystem

    # Build the effective instruction set actually executed in this (SYSTEM or user) context.
    if ($runningAsSystem -and $userScopeItems.Count -gt 0) {
        Write-Log "$($userScopeItems.Count) user-scope item(s); running as SYSTEM -> retargeting loaded hives + staging logon task."
        $instructions = @(Expand-UserScopeForLoadedUsers $rawInstructions)
    } else {
        # Either no user-scope items, or already running in a user context (HKCU resolves correctly).
        $instructions = $rawInstructions
    }
    Write-Log "Executing $($instructions.Count) effective instruction(s)"

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

    # Enforce as SYSTEM: stage user-scope items and (re)register the per-user logon task so that
    # not-currently-loaded and future user profiles converge too.
    if ($Mode -eq 'Enforce' -and $runningAsSystem -and $userScopeItems.Count -gt 0) {
        Save-UserScopeConfig -DeviceId $config.deviceId -Hash $config.hash -UserInstructions $userScopeItems
        $stableScript = Save-StableScriptCopy
        Register-UserScopeLogonTask -ScriptPath $stableScript
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
