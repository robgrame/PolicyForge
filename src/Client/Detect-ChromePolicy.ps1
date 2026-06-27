<#
.SYNOPSIS
    Chrome Policy Manager - Detection Script (with Inline Remediation)
    Checks whether Chrome policies on this device match the expected state from the central API.
    When drift is detected, applies policies inline without relying on Intune's remediation trigger.

.DESCRIPTION
    This script is deployed via Intune Proactive Remediation (Detection).
    It contacts the Chrome Policy Manager API to get the effective policy for this device,
    then compares it against the currently applied registry state.

    If EnableInlineRemediation is true and a policy mismatch is detected, the script
    applies the policies directly (writing Chrome registry keys) and verifies the result.
    
    Exit 0 = Compliant (either already compliant or successfully remediated inline)
    Exit 1 = Non-compliant (remediation failed or inline remediation disabled)

.NOTES
    Requires: 64-bit PowerShell execution
    Registry: HKLM\SOFTWARE\Policies\Google\Chrome
    Manifest: HKLM\SOFTWARE\ChromePolicyManager\Manifest
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# Script version — reported to server for fleet-wide visibility
$ScriptVersion = "13"

# Configuration
# API base URL is provisioned as a machine-scope environment variable (CPM_API_URL)
# by the companion 'Set CPM API endpoint' Intune remediation. There is NO hardcoded
# fallback: if the variable is missing the script aborts (drives the provisioning remediation).
$ApiUrlEnvVar = "CPM_API_URL"
$ApiBaseUrl = $null
foreach ($scope in @("Machine", "Process", "User")) {
    $candidate = [Environment]::GetEnvironmentVariable($ApiUrlEnvVar, $scope)
    if (-not [string]::IsNullOrWhiteSpace($candidate)) { $ApiBaseUrl = $candidate; break }
}
if ([string]::IsNullOrWhiteSpace($ApiBaseUrl)) {
    Write-Host "FATAL: environment variable '$ApiUrlEnvVar' is not set. Deploy the 'Set CPM API endpoint' remediation first."
    exit 1
}
$ApiBaseUrl = $ApiBaseUrl.TrimEnd('/')

# Client certificate selector — issuer DN substring of the Sub CA that signs device certs.
# Overridable via the CPM_CERT_ISSUER_LIKE machine env var (provisioned alongside CPM_API_URL).
$CertIssuerMatch = [Environment]::GetEnvironmentVariable("CPM_CERT_ISSUER_LIKE", "Machine")
if ([string]::IsNullOrWhiteSpace($CertIssuerMatch)) { $CertIssuerMatch = "CN=MSLABS-SUBCA01" }
$CertSubjectPrefix = "CN="              # Device certs have CN=<deviceId>

# Retry/jitter settings for rate limiting (429) responses
$MaxRetries = 3
$BaseJitterSeconds = 5

# Inline remediation — applies policies during detection, bypassing Intune's runRemediationScript flag
$EnableInlineRemediation = $true

# Paths
$ChromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$ChromeRecommendedPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended"
$ManifestPath = "HKLM:\SOFTWARE\ChromePolicyManager"
$ManifestValueName = "PolicyHash"
$ManifestKeysValue = "ManagedKeys"
$ManifestHashValue = "PolicyHash"
$ManifestTimestamp = "LastApplied"
$LogPath = "$env:ProgramData\ChromePolicyManager\detection.log"
$MaxLogSizeMB = 5
# Cached copy of the last effective policy — enables registry verification
# (tamper/drift detection) on 304 Not Modified and offline runs.
$CachedPolicyPath = "$env:ProgramData\ChromePolicyManager\effective-policy.json"

# Log buffer for batch upload
$script:LogBuffer = [System.Collections.Generic.List[hashtable]]::new()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to local file
    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    # Rotate if over max size
    if ((Test-Path $LogPath) -and ((Get-Item $LogPath).Length / 1MB) -gt $MaxLogSizeMB) {
        $archivePath = $LogPath -replace '\.log$', "-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        Rename-Item $LogPath $archivePath -ErrorAction SilentlyContinue
    }
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    
    # Buffer for batch upload
    $script:LogBuffer.Add(@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        level     = $Level
        message   = $Message
    })
}

function Get-DeviceInfo {
    $info = @{
        OsVersion = [Environment]::OSVersion.Version.ToString()
        OsBuild = ""
        Manufacturer = ""
        Model = ""
        ChromeVersion = "Unknown"
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property BuildNumber -ErrorAction SilentlyContinue
        if ($os) { $info.OsBuild = $os.BuildNumber }
    } catch { }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -Property Manufacturer, Model -ErrorAction SilentlyContinue
        if ($cs) { $info.Manufacturer = $cs.Manufacturer; $info.Model = $cs.Model }
    } catch { }
    try {
        $chromePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
        if (Test-Path $chromePath) {
            $exePath = (Get-ItemProperty $chromePath -ErrorAction SilentlyContinue).'(default)'
            if ($exePath -and (Test-Path $exePath)) { $info.ChromeVersion = (Get-Item $exePath).VersionInfo.ProductVersion }
        }
    } catch { }
    return $info
}

function Send-LogBatch {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCert,
        [string]$DeviceId
    )
    if ($script:LogBuffer.Count -eq 0) { return }
    try {
        $di = Get-DeviceInfo
        $body = @{
            deviceName = $env:COMPUTERNAME
            scriptType = if ($EnableInlineRemediation) { "Detection+InlineRemediation" } else { "Detection" }
            chromeVersion = $di.ChromeVersion
            osVersion = $di.OsVersion
            osBuild = $di.OsBuild
            manufacturer = $di.Manufacturer
            model = $di.Model
            scriptVersion = $ScriptVersion
            entries    = @($script:LogBuffer)
        } | ConvertTo-Json -Depth 3 -Compress

        Invoke-RestMethod -Uri "$ApiBaseUrl/api/devices/$DeviceId/logs" `
            -Method POST -Body $body -ContentType "application/json" `
            -Certificate $ClientCert -TimeoutSec 10 -ErrorAction Stop | Out-Null
    }
    catch {
        # Log upload failure is non-fatal — already persisted locally
        Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARN] Log batch upload failed: $_" -ErrorAction SilentlyContinue
    }
}

function Get-DeviceId {
    # Get Entra device ID from dsregcmd
    try {
        $dsregOutput = dsregcmd /status 2>&1
        $deviceIdLine = $dsregOutput | Select-String "DeviceId\s*:\s*(.+)"
        if ($deviceIdLine) {
            return $deviceIdLine.Matches[0].Groups[1].Value.Trim()
        }
    }
    catch {
        Write-Log "Failed to get device ID from dsregcmd: $_" "ERROR"
    }
    return $null
}

function Get-ClientCertificate {
    # Find the client certificate issued by the CPM Root CA (deployed via Intune PKCS/SCEP)
    try {
        $cert = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Issuer -match $CertIssuerMatch -and $_.NotAfter -gt (Get-Date) } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

        if ($cert) {
            Write-Log "Found client certificate: Subject=$($cert.Subject), Thumbprint=$($cert.Thumbprint), Expires=$($cert.NotAfter)"
            return $cert
        }
        Write-Log "No valid client certificate found (issuer: $CertIssuerMatch)" "WARN"
    }
    catch {
        Write-Log "Error searching for client certificate: $_" "ERROR"
    }
    return $null
}

function Get-CurrentPolicyHash {
    # Read the stored hash of last applied policy
    try {
        if (Test-Path $ManifestPath) {
            return (Get-ItemProperty -Path $ManifestPath -Name $ManifestValueName -ErrorAction SilentlyContinue).$ManifestValueName
        }
    }
    catch { }
    return $null
}

# ============ Inline Remediation Functions ============

function Get-ChromeVersion {
    try {
        $chromePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
        if (Test-Path $chromePath) {
            $exePath = (Get-ItemProperty $chromePath).'(default)'
            if ($exePath -and (Test-Path $exePath)) {
                return (Get-Item $exePath).VersionInfo.ProductVersion
            }
        }
    }
    catch { }
    return "Unknown"
}

function Get-ManagedKeys {
    try {
        if (Test-Path $ManifestPath) {
            $json = (Get-ItemProperty -Path $ManifestPath -Name $ManifestKeysValue -ErrorAction SilentlyContinue).$ManifestKeysValue
            if ($json) { return ($json | ConvertFrom-Json) }
        }
    }
    catch { }
    return @{ mandatory = @(); recommended = @() }
}

function Set-ManagedKeys {
    param([hashtable]$Keys)
    if (-not (Test-Path $ManifestPath)) { New-Item -Path $ManifestPath -Force | Out-Null }
    $json = $Keys | ConvertTo-Json -Compress
    Set-ItemProperty -Path $ManifestPath -Name $ManifestKeysValue -Value $json
}

# ============================================================================
#  Chrome-faithful registry application & verification
#  Modeled on Chromium components/policy/core/common/registry_dict.cc and
#  policy_loader_win.cc. The Chrome policy loader:
#   * Reads ONLY REG_SZ / REG_EXPAND_SZ / REG_DWORD. REG_QWORD, REG_MULTI_SZ
#     and every other type are SILENTLY IGNORED -> we must never emit them.
#   * Booleans -> REG_DWORD 0/1   (BOOLEAN schema also accepts "0"/"1").
#   * Integers -> REG_DWORD       (INTEGER schema also accepts a numeric
#                                   REG_SZ; values outside signed 32-bit are
#                                   written as REG_SZ because there is no
#                                   REG_QWORD support in Chrome).
#   * Doubles  -> REG_SZ (invariant culture); coerced by the DOUBLE schema.
#   * Strings  -> REG_SZ.
#   * Lists of scalars -> a subkey named after the policy holding numbered
#                         values "1".."N" (Chrome ignores non-numeric names).
#   * Lists containing objects / Dictionaries -> a single REG_SZ holding
#                         compact JSON (Chrome parses JSON strings for the
#                         LIST/DICT schemas).
#  Every write first clears BOTH a value and a subkey of the same name, so a
#  change of shape (scalar <-> list <-> dict) never leaves stale data behind.
# ============================================================================

function Test-IsScalarValue {
    param([object]$Value)
    return ($Value -is [bool] -or $Value -is [string] -or $Value -is [int] -or
            $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or
            $Value -is [double] -or $Value -is [single] -or $Value -is [decimal] -or
            $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [sbyte])
}

function Test-IsListValue {
    param([object]$Value)
    return (($Value -is [System.Array]) -or
            (($Value -is [System.Collections.IEnumerable]) -and
             -not ($Value -is [string]) -and
             -not ($Value -is [System.Collections.IDictionary])))
}

function ConvertTo-ChromeScalar {
    # Returns @{ Type='DWord'|'String'; Data=<value> } describing how this scalar
    # should land in the registry so Chrome's loader can read it.
    param([object]$Value)
    if ($Value -is [bool]) { return @{ Type = 'DWord'; Data = [int][bool]$Value } }
    if ($Value -is [int] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [uint16]) {
        return @{ Type = 'DWord'; Data = [int]$Value }
    }
    if ($Value -is [long] -or $Value -is [uint32]) {
        $l = [long]$Value
        if ($l -ge [int]::MinValue -and $l -le [int]::MaxValue) { return @{ Type = 'DWord'; Data = [int]$l } }
        # No REG_QWORD support -> numeric string (INTEGER schema coerces it).
        return @{ Type = 'String'; Data = $l.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        return @{ Type = 'String'; Data = ([double]$Value).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    }
    return @{ Type = 'String'; Data = [string]$Value }
}

function Remove-PolicyEntry {
    # Remove any existing value AND subkey with this name (shape-conflict cleanup).
    param([string]$BasePath, [string]$Name)
    $subPath = Join-Path $BasePath $Name
    if (Test-Path $subPath) { Remove-Item -Path $subPath -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $BasePath) {
        $props = Get-ItemProperty -Path $BasePath -ErrorAction SilentlyContinue
        if ($props -and ($props.PSObject.Properties.Name -contains $Name)) {
            Remove-ItemProperty -Path $BasePath -Name $Name -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-RegistryPolicy {
    param([string]$BasePath, [string]$PolicyName, [object]$Value)

    if (-not (Test-Path $BasePath)) { New-Item -Path $BasePath -Force | Out-Null }

    # Clear any previous representation so shape/type changes leave no stale data.
    Remove-PolicyEntry -BasePath $BasePath -Name $PolicyName

    if ($null -eq $Value) { return }

    if (Test-IsScalarValue $Value) {
        $s = ConvertTo-ChromeScalar $Value
        New-ItemProperty -Path $BasePath -Name $PolicyName -Value $s.Data -PropertyType $s.Type -Force | Out-Null
        return
    }

    if (Test-IsListValue $Value) {
        $items = @($Value)
        $allScalar = $true
        foreach ($it in $items) { if (-not (Test-IsScalarValue $it)) { $allScalar = $false; break } }
        if ($allScalar) {
            # Canonical Chrome list form: subkey with numbered REG_SZ/REG_DWORD values.
            $listPath = Join-Path $BasePath $PolicyName
            New-Item -Path $listPath -Force | Out-Null
            for ($i = 0; $i -lt $items.Count; $i++) {
                $s = ConvertTo-ChromeScalar $items[$i]
                New-ItemProperty -Path $listPath -Name (($i + 1).ToString()) -Value $s.Data -PropertyType $s.Type -Force | Out-Null
            }
        }
        else {
            # Complex list -> Chrome accepts a whole list encoded as a JSON string.
            $json = ConvertTo-Json -InputObject $items -Compress -Depth 20
            New-ItemProperty -Path $BasePath -Name $PolicyName -Value $json -PropertyType String -Force | Out-Null
        }
        return
    }

    # Dictionary / object -> Chrome accepts a JSON string for the DICT schema.
    $json = $Value | ConvertTo-Json -Compress -Depth 20
    New-ItemProperty -Path $BasePath -Name $PolicyName -Value $json -PropertyType String -Force | Out-Null
}

function Get-ScalarCanonical {
    # Canonical token for a scalar already read from the registry (int or string).
    param([object]$Value)
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [uint32]) {
        return "i:$([long]$Value)"
    }
    return "s:$([string]$Value)"
}

function Get-IntendedCanonical {
    # Canonical token for an intended value, mirroring Write-RegistryPolicy exactly.
    param([object]$Value)
    if ($null -eq $Value) { return '<null>' }
    if (Test-IsScalarValue $Value) {
        $s = ConvertTo-ChromeScalar $Value
        if ($s.Type -eq 'DWord') { return "i:$([long]$s.Data)" }
        return "s:$([string]$s.Data)"
    }
    if (Test-IsListValue $Value) {
        $items = @($Value)
        $allScalar = $true
        foreach ($it in $items) { if (-not (Test-IsScalarValue $it)) { $allScalar = $false; break } }
        if ($allScalar) {
            $tokens = @()
            foreach ($it in $items) {
                $s = ConvertTo-ChromeScalar $it
                if ($s.Type -eq 'DWord') { $tokens += "i:$([long]$s.Data)" } else { $tokens += "s:$([string]$s.Data)" }
            }
            return "L:[" + ($tokens -join ',') + "]"
        }
        return "s:$(ConvertTo-Json -InputObject $items -Compress -Depth 20)"
    }
    return "s:$($Value | ConvertTo-Json -Compress -Depth 20)"
}

function Read-AppliedPolicy {
    # Reads a policy back the way Chrome's loader interprets the registry and
    # returns @{ Found=$bool; Canonical=<token> }.
    param([string]$BasePath, [string]$PolicyName)
    $subPath = Join-Path $BasePath $PolicyName
    if (Test-Path $subPath) {
        $props = Get-ItemProperty -Path $subPath -ErrorAction SilentlyContinue
        $tokens = @()
        if ($props) {
            $numeric = $props.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | Sort-Object { [int]$_.Name }
            foreach ($p in $numeric) { $tokens += (Get-ScalarCanonical $p.Value) }
        }
        return @{ Found = $true; Canonical = "L:[" + ($tokens -join ',') + "]" }
    }
    if (Test-Path $BasePath) {
        $props = Get-ItemProperty -Path $BasePath -ErrorAction SilentlyContinue
        if ($props -and ($props.PSObject.Properties.Name -contains $PolicyName)) {
            return @{ Found = $true; Canonical = (Get-ScalarCanonical $props.$PolicyName) }
        }
    }
    return @{ Found = $false; Canonical = $null }
}

function Test-PolicyApplied {
    # True if the registry reflects the intended value the way Chrome reads it.
    param([string]$BasePath, [string]$PolicyName, [object]$IntendedValue)
    $actual = Read-AppliedPolicy -BasePath $BasePath -PolicyName $PolicyName
    if (-not $actual.Found) { return $false }
    return ($actual.Canonical -eq (Get-IntendedCanonical $IntendedValue))
}

function Test-AllPoliciesApplied {
    # Verifies every policy in the effective-policy object is applied as Chrome
    # would read it. Returns @{ Compliant=$bool; Mismatches=@(names) }.
    param([object]$EffectivePolicy)
    $mismatches = @()
    if ($EffectivePolicy.mandatoryPolicies -is [PSCustomObject]) {
        foreach ($p in $EffectivePolicy.mandatoryPolicies.PSObject.Properties) {
            if (-not (Test-PolicyApplied -BasePath $ChromePolicyPath -PolicyName $p.Name -IntendedValue $p.Value)) { $mismatches += $p.Name }
        }
    }
    if ($EffectivePolicy.recommendedPolicies -is [PSCustomObject]) {
        foreach ($p in $EffectivePolicy.recommendedPolicies.PSObject.Properties) {
            if (-not (Test-PolicyApplied -BasePath $ChromeRecommendedPath -PolicyName $p.Name -IntendedValue $p.Value)) { $mismatches += $p.Name }
        }
    }
    return @{ Compliant = ($mismatches.Count -eq 0); Mismatches = $mismatches }
}

function Save-CachedPolicy {
    # Persist the full effective policy so 304/offline runs can still verify the
    # registry against intended values (tamper/drift detection).
    param([object]$EffectivePolicy)
    try {
        $dir = Split-Path $CachedPolicyPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        ($EffectivePolicy | ConvertTo-Json -Depth 20 -Compress) | Set-Content -Path $CachedPolicyPath -Encoding UTF8
    }
    catch { Write-Log "Failed to cache effective policy: $_" "WARN" }
}

function Get-CachedPolicy {
    try {
        if (Test-Path $CachedPolicyPath) { return (Get-Content -Path $CachedPolicyPath -Raw | ConvertFrom-Json) }
    }
    catch { Write-Log "Failed to read cached policy: $_" "WARN" }
    return $null
}

function Remove-StaleKeys {
    param([string]$BasePath, [string[]]$PreviousKeys, [string[]]$CurrentKeys)
    $removed = 0
    $staleKeys = $PreviousKeys | Where-Object { $_ -notin $CurrentKeys }
    foreach ($key in $staleKeys) {
        try {
            $itemPath = Join-Path $BasePath $key
            if (Test-Path $itemPath) { Remove-Item -Path $itemPath -Recurse -Force; $removed++ }
            elseif (Test-Path $BasePath) {
                $existing = Get-ItemProperty -Path $BasePath -Name $key -ErrorAction SilentlyContinue
                if ($null -ne $existing.$key) { Remove-ItemProperty -Path $BasePath -Name $key -Force; $removed++ }
            }
            Write-Log "Removed stale policy: $key"
        }
        catch { Write-Log "Failed to remove stale key '$key': $_" "WARN" }
    }
    return $removed
}

function Send-ComplianceReport {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCert,
        [string]$DeviceId, [string]$DeviceName, [string]$PolicyHash,
        [string]$Status, [string]$Errors, [int]$KeysWritten, [int]$KeysRemoved
    )
    try {
        $di = Get-DeviceInfo
        $report = @{
            deviceId = $DeviceId; deviceName = $DeviceName; userPrincipalName = $null
            appliedPolicyHash = $PolicyHash; status = $Status; errors = $Errors
            chromeVersion = $di.ChromeVersion; osVersion = $di.OsVersion
            osBuild = $di.OsBuild; manufacturer = $di.Manufacturer; model = $di.Model
            scriptVersion = $ScriptVersion
            policyKeysWritten = $KeysWritten; policyKeysRemoved = $KeysRemoved
        } | ConvertTo-Json
        Invoke-RestMethod -Uri "$ApiBaseUrl/api/devices/$DeviceId/report" -Method POST -Body $report `
            -ContentType "application/json" -Certificate $ClientCert | Out-Null
        Write-Log "Compliance report sent successfully"
    }
    catch { Write-Log "Failed to send compliance report: $_" "WARN" }
}

function Invoke-InlineRemediation {
    param(
        [object]$EffectivePolicy,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCert,
        [string]$DeviceId
    )
    Write-Log "=== Inline remediation started ==="
    $serverHash = $EffectivePolicy.hash
    $deviceName = $env:COMPUTERNAME
    $previousManaged = Get-ManagedKeys
    $previousMandatoryKeys = @($previousManaged.mandatory)
    $previousRecommendedKeys = @($previousManaged.recommended)
    $keysWritten = 0; $keysRemoved = 0; $errors = @()
    $currentMandatoryKeys = @(); $currentRecommendedKeys = @()

    # Apply mandatory policies
    if ($EffectivePolicy.mandatoryPolicies -and $EffectivePolicy.mandatoryPolicies -is [PSCustomObject]) {
        Write-Log "Applying mandatory policies..."
        $EffectivePolicy.mandatoryPolicies.PSObject.Properties | ForEach-Object {
            try {
                Write-RegistryPolicy -BasePath $ChromePolicyPath -PolicyName $_.Name -Value $_.Value
                $currentMandatoryKeys += $_.Name; $keysWritten++
                Write-Log "  Applied: $($_.Name)"
            }
            catch { $errors += "Failed mandatory '$($_.Name)': $_"; Write-Log "  FAILED: $($_.Name) - $_" "ERROR" }
        }
    }

    # Apply recommended policies
    if ($EffectivePolicy.recommendedPolicies -and $EffectivePolicy.recommendedPolicies -is [PSCustomObject]) {
        Write-Log "Applying recommended policies..."
        $EffectivePolicy.recommendedPolicies.PSObject.Properties | ForEach-Object {
            try {
                Write-RegistryPolicy -BasePath $ChromeRecommendedPath -PolicyName $_.Name -Value $_.Value
                $currentRecommendedKeys += $_.Name; $keysWritten++
                Write-Log "  Applied: $($_.Name) (Recommended)"
            }
            catch { $errors += "Failed recommended '$($_.Name)': $_"; Write-Log "  FAILED: $($_.Name) - $_" "ERROR" }
        }
    }

    # Remove stale keys
    $keysRemoved += (Remove-StaleKeys -BasePath $ChromePolicyPath -PreviousKeys $previousMandatoryKeys -CurrentKeys $currentMandatoryKeys)
    $keysRemoved += (Remove-StaleKeys -BasePath $ChromeRecommendedPath -PreviousKeys $previousRecommendedKeys -CurrentKeys $currentRecommendedKeys)

    # Update manifest
    Set-ManagedKeys -Keys @{ mandatory = $currentMandatoryKeys; recommended = $currentRecommendedKeys }
    if (-not (Test-Path $ManifestPath)) { New-Item -Path $ManifestPath -Force | Out-Null }
    Set-ItemProperty -Path $ManifestPath -Name $ManifestHashValue -Value $serverHash
    Set-ItemProperty -Path $ManifestPath -Name $ManifestTimestamp -Value (Get-Date -Format "o")

    # Verify the registry reflects the intended policy the way Chrome reads it.
    $verify = Test-AllPoliciesApplied -EffectivePolicy $EffectivePolicy
    if (-not $verify.Compliant) {
        foreach ($m in $verify.Mismatches) { Write-Log "  VERIFY MISMATCH: $m" "WARN" }
        $errors += "Post-apply verification failed for: $($verify.Mismatches -join ', ')"
    }
    Save-CachedPolicy -EffectivePolicy $EffectivePolicy

    $verifiedHash = Get-CurrentPolicyHash
    $success = $verify.Compliant -and ($verifiedHash -eq $serverHash) -and ($errors.Count -eq 0)

    $status = if ($verify.Compliant -and $errors.Count -eq 0) { "Compliant" } elseif ($keysWritten -gt 0) { "PartiallyApplied" } else { "Error" }
    $errorsJson = if ($errors.Count -gt 0) { $errors | ConvertTo-Json -Compress } else { $null }

    Send-ComplianceReport -ClientCert $ClientCert -DeviceId $DeviceId -DeviceName $deviceName `
        -PolicyHash $serverHash -Status $status -Errors $errorsJson `
        -KeysWritten $keysWritten -KeysRemoved $keysRemoved

    Write-Log "Inline remediation complete: $keysWritten written, $keysRemoved removed, Status: $status, Verified: $success"
    return @{ Success = $success; KeysWritten = $keysWritten; KeysRemoved = $keysRemoved; Status = $status; Hash = $serverHash }
}

function Invoke-CachedVerification {
    # Used on 304 Not Modified / cached paths. Verifies the live registry against
    # the cached effective policy (tamper/drift detection) and remediates inline
    # if drift is found. Returns @{ Output=<string>; ExitCode=<int> }.
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCert,
        [string]$DeviceId,
        [string]$LocalHash
    )
    $cached = Get-CachedPolicy
    if (-not $cached) {
        return @{ Output = "Compliant (Hash: $LocalHash, cached)"; ExitCode = 0 }
    }
    $verify = Test-AllPoliciesApplied -EffectivePolicy $cached
    if ($verify.Compliant) {
        return @{ Output = "Compliant (Hash: $LocalHash, verified)"; ExitCode = 0 }
    }
    Write-Log "Registry drift vs cached policy: $($verify.Mismatches -join ', ')" "WARN"
    if ($EnableInlineRemediation -and $ClientCert) {
        $result = Invoke-InlineRemediation -EffectivePolicy $cached -ClientCert $ClientCert -DeviceId $DeviceId
        if ($result.Success) {
            return @{ Output = "Remediated drift: $($result.KeysWritten) applied, $($result.KeysRemoved) removed"; ExitCode = 0 }
        }
        return @{ Output = "Drift remediation failed: Status=$($result.Status)"; ExitCode = 1 }
    }
    return @{ Output = "Non-compliant (registry drift: $($verify.Mismatches -join ', '))"; ExitCode = 1 }
}

# Main detection logic
$script:ExitCode = 1
$script:ClientCertForLog = $null
$script:DeviceIdForLog = $null

try {
    Write-Log "Detection script started"
    
    $deviceId = Get-DeviceId
    $script:DeviceIdForLog = $deviceId
    if (-not $deviceId) {
        Write-Log "Cannot determine device ID - device may not be Entra joined" "ERROR"
        Write-Output "Cannot determine device ID"
        $script:ExitCode = 1; return
    }
    Write-Log "Device ID: $deviceId"
    
    # Get client certificate for mTLS authentication
    $clientCert = Get-ClientCertificate
    $script:ClientCertForLog = $clientCert
    if (-not $clientCert) {
        Write-Log "Cannot find client certificate - device may not have the CPM cert profile applied" "WARN"
        # If we can't authenticate, check if we have any policy applied locally
        $localHash = Get-CurrentPolicyHash
        if ($localHash) {
            Write-Log "Local policy hash exists: $localHash - assuming compliant"
            Write-Output "Compliant (offline - using cached state)"
            $script:ExitCode = 0; return
        }
        else {
            Write-Log "No local policy hash - non-compliant"
            Write-Output "Non-compliant (no policies applied and cannot authenticate)"
            $script:ExitCode = 1; return
        }
    }
    
    # Call API to get effective policy (with ETag for bandwidth optimization)
    $headers = @{
        "Content-Type" = "application/json"
    }
    
    # If we have a local hash, send it as ETag — API returns 304 if nothing changed
    $localHash = Get-CurrentPolicyHash
    if ($localHash) {
        $headers["If-None-Match"] = "`"$localHash`""
    }
    
    # Add initial jitter to avoid thundering herd (randomize check-in window)
    $jitter = Get-Random -Minimum 0 -Maximum $BaseJitterSeconds
    Start-Sleep -Seconds $jitter
    
    $retryCount = 0
    $response = $null
    $effectivePolicy = $null
    
    while ($retryCount -le $MaxRetries) {
        try {
            $response = Invoke-WebRequest -Uri "$ApiBaseUrl/api/devices/$deviceId/effective-policy" -Headers $headers -Method GET -UseBasicParsing -Certificate $clientCert
            
            if ($response.StatusCode -eq 304) {
                Write-Log "304 Not Modified (Hash: $localHash) - verifying registry against cached policy"
                $r = Invoke-CachedVerification -ClientCert $clientCert -DeviceId $deviceId -LocalHash $localHash
                Write-Output $r.Output; $script:ExitCode = $r.ExitCode; return
            }
            
            $effectivePolicy = $response.Content | ConvertFrom-Json
            Write-Log "Effective policy received from API"
            break
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            
            if ($statusCode -eq 304) {
                Write-Log "304 Not Modified (Hash: $localHash) - verifying registry against cached policy"
                $r = Invoke-CachedVerification -ClientCert $clientCert -DeviceId $deviceId -LocalHash $localHash
                Write-Output $r.Output; $script:ExitCode = $r.ExitCode; return
            }
            elseif ($statusCode -eq 429) {
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                if (-not $retryAfter) { $retryAfter = 60 }
                $backoff = [int]$retryAfter + (Get-Random -Minimum 1 -Maximum 10)
                Write-Log "Rate limited (429). Retry $($retryCount + 1)/$MaxRetries after ${backoff}s" "WARN"
                $retryCount++
                if ($retryCount -gt $MaxRetries) {
                    Write-Log "Max retries exceeded after 429 responses" "ERROR"
                    if ($localHash) {
                        Write-Output "Compliant (offline - rate limited, using cached state)"
                        $script:ExitCode = 0; return
                    }
                    $script:ExitCode = 1; return
                }
                Start-Sleep -Seconds $backoff
            }
            else {
                throw
            }
        }
    }
    
    if (-not $effectivePolicy -or (-not $effectivePolicy.mandatoryPolicies -and -not $effectivePolicy.recommendedPolicies)) {
        Write-Log "No policies assigned to this device"
        Write-Output "No policies assigned"
        $script:ExitCode = 0; return
    }
    
    # Compare server hash with local hash
    $serverHash = $effectivePolicy.hash
    
    if ($serverHash -eq $localHash) {
        # Hash matches, but verify the registry actually reflects the policy the
        # way Chrome reads it (catches external tampering / drift).
        $verify = Test-AllPoliciesApplied -EffectivePolicy $effectivePolicy
        if ($verify.Compliant) {
            Write-Log "Policy hash matches and registry verified - device is compliant (Hash: $serverHash)"
            Save-CachedPolicy -EffectivePolicy $effectivePolicy
            Write-Output "Compliant (Hash: $serverHash, verified)"
            $script:ExitCode = 0; return
        }
        Write-Log "Hash matches but registry drift detected: $($verify.Mismatches -join ', ')" "WARN"
        if ($EnableInlineRemediation) {
            $result = Invoke-InlineRemediation -EffectivePolicy $effectivePolicy -ClientCert $clientCert -DeviceId $deviceId
            if ($result.Success) {
                Write-Output "Remediated drift inline: $($result.KeysWritten) applied, $($result.KeysRemoved) removed. Hash: $($result.Hash)"
                $script:ExitCode = 0; return
            }
            Write-Output "Drift remediation failed: Status=$($result.Status)"
            $script:ExitCode = 1; return
        }
        Write-Output "Non-compliant (registry drift: $($verify.Mismatches -join ', '))"
        $script:ExitCode = 1; return
    }
    else {
        Write-Log "Policy hash mismatch - Server: $serverHash, Local: $localHash" "WARN"
        
        if ($EnableInlineRemediation) {
            # Apply policies inline since Intune's remediation trigger is unreliable
            $result = Invoke-InlineRemediation -EffectivePolicy $effectivePolicy -ClientCert $clientCert -DeviceId $deviceId
            if ($result.Success) {
                Write-Output "Remediated inline: $($result.KeysWritten) applied, $($result.KeysRemoved) removed. Hash: $($result.Hash)"
                $script:ExitCode = 0; return
            }
            else {
                Write-Output "Inline remediation failed: Status=$($result.Status), Hash=$($result.Hash)"
                $script:ExitCode = 1; return
            }
        }
        else {
            Write-Output "Non-compliant (Server: $serverHash, Local: $localHash)"
            $script:ExitCode = 1; return
        }
    }
}
catch {
    Write-Log "Detection script error: $_" "ERROR"
    Write-Output "Error during detection: $_"
    $script:ExitCode = 1
}
finally {
    # Always send logs to server (best-effort)
    if ($script:ClientCertForLog -and $script:DeviceIdForLog) {
        Send-LogBatch -ClientCert $script:ClientCertForLog -DeviceId $script:DeviceIdForLog
    }
    Write-Log "Detection script finished (exit: $($script:ExitCode))"
}
exit $script:ExitCode
