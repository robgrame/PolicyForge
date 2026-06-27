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
    Enforce - apply remediations for any drift, then re-test.

.PARAMETER InputJson
    Optional path to a local ResolvedConfiguration JSON file. Bypasses the API call (for testing).

.PARAMETER LogPath
    Optional log file path. Defaults to %ProgramData%\PolicyForge\client.log.

.NOTES
    Designed to run as SYSTEM (Intune Proactive Remediation). HKCU / per-user items require a
    user-context runner and are out of scope for the SYSTEM pass.
#>
[CmdletBinding()]
param(
    [string]$ApiBaseUrl,
    [string]$DeviceId,
    [ValidateSet('Detect', 'Enforce')]
    [string]$Mode = 'Detect',
    [string]$InputJson,
    [string]$LogPath = (Join-Path $env:ProgramData 'PolicyForge\client.log')
)

$ErrorActionPreference = 'Stop'

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

        & $handler.Apply $data $action
        $recheck = & $handler.Test $data $action
        if ($recheck) { return New-Result -Instruction $Instruction -Status 'Remediated' }
        return New-Result -Instruction $Instruction -Status 'Error' -Detail 'Re-test failed after apply.'
    } catch {
        return New-Result -Instruction $Instruction -Status 'Error' -Detail $_.Exception.Message
    }
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
    $config = Get-ResolvedConfiguration
    $instructions = @($config.instructions)
    Write-Log "Resolved $($instructions.Count) instruction(s), hash=$($config.hash)"

    $results = foreach ($instruction in $instructions) { Invoke-Instruction -Instruction $instruction -Mode $Mode }
    $results = @($results)

    $summary = $results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Log "Result: $($summary -join ', ')"

    $hasDrift = @($results | Where-Object { $_.Status -in @('Drifted', 'Error') }).Count -gt 0

    [pscustomobject]@{
        DeviceId    = $config.deviceId
        Hash        = $config.hash
        Mode        = $Mode
        Compliant   = -not $hasDrift
        Results     = $results
    } | ConvertTo-Json -Depth 6

    if ($Mode -eq 'Detect' -and $hasDrift) { exit 1 }
    exit 0
} catch {
    Write-Log "FATAL: $($_.Exception.Message)" 'ERROR'
    Write-Error $_
    exit 1
}
