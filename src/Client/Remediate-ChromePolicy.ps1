<#
.SYNOPSIS
    Chrome Policy Manager - Remediation Script
    Applies Chrome policies from the central API to the local registry.

.DESCRIPTION
    This script is deployed via Intune Proactive Remediation (Remediation).
    It contacts the Chrome Policy Manager API, retrieves the effective policy for this device,
    writes the policies to the Chrome policy registry path, manages stale policy removal,
    and reports compliance status back to the API.

    Registry paths managed:
    - HKLM:\SOFTWARE\Policies\Google\Chrome (mandatory)
    - HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended (recommended)
    
    Local manifest stored at:
    - HKLM:\SOFTWARE\ChromePolicyManager

.NOTES
    Requires: 64-bit PowerShell, Administrator privileges
    Chrome will pick up changes within 15 minutes (periodic refresh) or immediately via chrome://policy reload
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# Configuration
# API base URL is provisioned as a machine-scope environment variable (CPM_API_URL)
# by the companion 'Set CPM API endpoint' Intune remediation. There is NO hardcoded
# fallback: if the variable is missing the script aborts.
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

# Retry/jitter settings
$MaxRetries = 3
$BaseJitterSeconds = 5

# Registry paths
$ChromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$ChromeRecommendedPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended"
$ManifestPath = "HKLM:\SOFTWARE\ChromePolicyManager"
$ManifestKeysValue = "ManagedKeys"       # JSON list of keys we own
$ManifestHashValue = "PolicyHash"        # Hash of applied policy
$ManifestVersionValue = "PolicyVersion"  # Version string
$ManifestTimestamp = "LastApplied"       # Last application timestamp
$LogPath = "$env:ProgramData\ChromePolicyManager\remediation.log"
$MaxLogSizeMB = 5
# Cached copy of the last effective policy — used for offline registry verification.
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
        ChromeVersion = (Get-ChromeVersion)
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property BuildNumber -ErrorAction SilentlyContinue
        if ($os) { $info.OsBuild = $os.BuildNumber }
    } catch { }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -Property Manufacturer, Model -ErrorAction SilentlyContinue
        if ($cs) { $info.Manufacturer = $cs.Manufacturer; $info.Model = $cs.Model }
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
            scriptType = "Remediation"
            chromeVersion = $di.ChromeVersion
            osVersion = $di.OsVersion
            osBuild = $di.OsBuild
            manufacturer = $di.Manufacturer
            model = $di.Model
            entries    = @($script:LogBuffer)
        } | ConvertTo-Json -Depth 3 -Compress

        Invoke-RestMethod -Uri "$ApiBaseUrl/api/devices/$DeviceId/logs" `
            -Method POST -Body $body -ContentType "application/json" `
            -Certificate $ClientCert -TimeoutSec 10 -ErrorAction Stop | Out-Null
    }
    catch {
        Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARN] Log batch upload failed: $_" -ErrorAction SilentlyContinue
    }
}

function Get-DeviceId {
    try {
        $dsregOutput = dsregcmd /status 2>&1
        $deviceIdLine = $dsregOutput | Select-String "DeviceId\s*:\s*(.+)"
        if ($deviceIdLine) {
            return $deviceIdLine.Matches[0].Groups[1].Value.Trim()
        }
    }
    catch {
        Write-Log "Failed to get device ID: $_" "ERROR"
    }
    return $null
}

function Get-DeviceName {
    return $env:COMPUTERNAME
}

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

function Get-ClientCertificate {
    # Find the client certificate issued by the CPM Root CA (deployed via Intune PKCS/SCEP)
    try {
        $cert = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Issuer -match $CertIssuerMatch -and $_.NotAfter -gt (Get-Date) } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

        if ($cert) {
            Write-Log "Found client certificate: Subject=$($cert.Subject), Thumbprint=$($cert.Thumbprint)"
            return $cert
        }
        Write-Log "No valid client certificate found (issuer: $CertIssuerMatch)" "WARN"
    }
    catch {
        Write-Log "Error searching for client certificate: $_" "ERROR"
    }
    return $null
}

function Get-ManagedKeys {
    # Read the list of registry keys we previously wrote
    try {
        if (Test-Path $ManifestPath) {
            $json = (Get-ItemProperty -Path $ManifestPath -Name $ManifestKeysValue -ErrorAction SilentlyContinue).$ManifestKeysValue
            if ($json) {
                return ($json | ConvertFrom-Json)
            }
        }
    }
    catch { }
    return @{ mandatory = @(); recommended = @() }
}

function Set-ManagedKeys {
    param([hashtable]$Keys)
    if (-not (Test-Path $ManifestPath)) {
        New-Item -Path $ManifestPath -Force | Out-Null
    }
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
    # Persist the full effective policy for offline registry verification.
    param([object]$EffectivePolicy)
    try {
        $dir = Split-Path $CachedPolicyPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        ($EffectivePolicy | ConvertTo-Json -Depth 20 -Compress) | Set-Content -Path $CachedPolicyPath -Encoding UTF8
    }
    catch { Write-Log "Failed to cache effective policy: $_" "WARN" }
}

function Remove-StaleKeys {
    param(
        [string]$BasePath,
        [string[]]$PreviousKeys,
        [string[]]$CurrentKeys
    )
    
    $removed = 0
    $staleKeys = $PreviousKeys | Where-Object { $_ -notin $CurrentKeys }
    
    foreach ($key in $staleKeys) {
        try {
            $itemPath = Join-Path $BasePath $key
            # Check if it's a subkey (list policy) or a value
            if (Test-Path $itemPath) {
                Remove-Item -Path $itemPath -Recurse -Force
                $removed++
            }
            elseif (Test-Path $BasePath) {
                $existing = Get-ItemProperty -Path $BasePath -Name $key -ErrorAction SilentlyContinue
                if ($null -ne $existing.$key) {
                    Remove-ItemProperty -Path $BasePath -Name $key -Force
                    $removed++
                }
            }
            Write-Log "Removed stale policy: $key"
        }
        catch {
            Write-Log "Failed to remove stale key '$key': $_" "WARN"
        }
    }
    
    return $removed
}

function Send-ComplianceReport {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCert,
        [string]$DeviceId,
        [string]$DeviceName,
        [string]$PolicyHash,
        [string]$Status,
        [string]$Errors,
        [int]$KeysWritten,
        [int]$KeysRemoved
    )
    
    try {
        $headers = @{
            "Content-Type" = "application/json"
        }
        
        $di = Get-DeviceInfo
        $report = @{
            deviceId = $DeviceId
            deviceName = $DeviceName
            userPrincipalName = $null
            appliedPolicyHash = $PolicyHash
            status = $Status
            errors = $Errors
            chromeVersion = $di.ChromeVersion
            osVersion = $di.OsVersion
            osBuild = $di.OsBuild
            manufacturer = $di.Manufacturer
            model = $di.Model
            policyKeysWritten = $KeysWritten
            policyKeysRemoved = $KeysRemoved
        } | ConvertTo-Json
        
        Invoke-RestMethod -Uri "$ApiBaseUrl/api/devices/$DeviceId/report" -Headers $headers -Method POST -Body $report -Certificate $ClientCert | Out-Null
        Write-Log "Compliance report sent successfully"
    }
    catch {
        Write-Log "Failed to send compliance report: $_" "WARN"
    }
}

# ============ Main Remediation Logic ============
$script:ExitCode = 1
$script:ClientCertForLog = $null
$script:DeviceIdForLog = $null

try {
    Write-Log "=== Remediation script started ==="
    
    $deviceId = Get-DeviceId
    $script:DeviceIdForLog = $deviceId
    if (-not $deviceId) {
        Write-Log "Cannot determine device ID" "ERROR"
        Write-Output "FAILED: Cannot determine device ID"
        $script:ExitCode = 1; return
    }
    $deviceName = Get-DeviceName
    Write-Log "Device: $deviceName ($deviceId)"
    
    # Authenticate with client certificate
    $clientCert = Get-ClientCertificate
    $script:ClientCertForLog = $clientCert
    if (-not $clientCert) {
        Write-Log "Cannot find client certificate" "ERROR"
        Write-Output "FAILED: Cannot find client certificate (CPM cert profile not applied)"
        $script:ExitCode = 1; return
    }
    Write-Log "Client certificate found: $($clientCert.Thumbprint)"
    
    # Get effective policy from API
    $headers = @{
        "Content-Type" = "application/json"
    }
    
    $effectivePolicy = Invoke-RestMethod -Uri "$ApiBaseUrl/api/devices/$deviceId/effective-policy" -Headers $headers -Method GET -Certificate $clientCert
    
    if (-not $effectivePolicy) {
        Write-Log "No effective policy returned from API" "WARN"
        Write-Output "No policies assigned"
        $script:ExitCode = 0; return
    }
    
    $serverHash = $effectivePolicy.hash
    Write-Log "Effective policy hash: $serverHash"
    
    # Get previously managed keys (for stale removal)
    $previousManaged = Get-ManagedKeys
    $previousMandatoryKeys = @($previousManaged.mandatory)
    $previousRecommendedKeys = @($previousManaged.recommended)
    
    $keysWritten = 0
    $keysRemoved = 0
    $errors = @()
    $currentMandatoryKeys = @()
    $currentRecommendedKeys = @()
    
    # Apply mandatory policies
    if ($effectivePolicy.mandatoryPolicies) {
        Write-Log "Applying mandatory policies..."
        $mandatoryPolicies = $effectivePolicy.mandatoryPolicies
        
        # Handle PSCustomObject from JSON
        if ($mandatoryPolicies -is [PSCustomObject]) {
            $mandatoryPolicies.PSObject.Properties | ForEach-Object {
                $policyName = $_.Name
                $policyValue = $_.Value
                try {
                    Write-RegistryPolicy -BasePath $ChromePolicyPath -PolicyName $policyName -Value $policyValue
                    $currentMandatoryKeys += $policyName
                    $keysWritten++
                    Write-Log "  Applied: $policyName"
                }
                catch {
                    $errors += "Failed to write mandatory policy '$policyName': $_"
                    Write-Log "  FAILED: $policyName - $_" "ERROR"
                }
            }
        }
    }
    
    # Apply recommended policies
    if ($effectivePolicy.recommendedPolicies) {
        Write-Log "Applying recommended policies..."
        $recommendedPolicies = $effectivePolicy.recommendedPolicies
        
        if ($recommendedPolicies -is [PSCustomObject]) {
            $recommendedPolicies.PSObject.Properties | ForEach-Object {
                $policyName = $_.Name
                $policyValue = $_.Value
                try {
                    Write-RegistryPolicy -BasePath $ChromeRecommendedPath -PolicyName $policyName -Value $policyValue
                    $currentRecommendedKeys += $policyName
                    $keysWritten++
                    Write-Log "  Applied: $policyName (Recommended)"
                }
                catch {
                    $errors += "Failed to write recommended policy '$policyName': $_"
                    Write-Log "  FAILED: $policyName - $_" "ERROR"
                }
            }
        }
    }
    
    # Remove stale policies (owned by us but no longer in effective policy)
    $keysRemoved += (Remove-StaleKeys -BasePath $ChromePolicyPath -PreviousKeys $previousMandatoryKeys -CurrentKeys $currentMandatoryKeys)
    $keysRemoved += (Remove-StaleKeys -BasePath $ChromeRecommendedPath -PreviousKeys $previousRecommendedKeys -CurrentKeys $currentRecommendedKeys)
    
    # Update local manifest
    Set-ManagedKeys -Keys @{
        mandatory = $currentMandatoryKeys
        recommended = $currentRecommendedKeys
    }
    
    # Update manifest metadata
    if (-not (Test-Path $ManifestPath)) { New-Item -Path $ManifestPath -Force | Out-Null }
    Set-ItemProperty -Path $ManifestPath -Name $ManifestHashValue -Value $serverHash
    Set-ItemProperty -Path $ManifestPath -Name $ManifestTimestamp -Value (Get-Date -Format "o")

    # Verify the registry reflects the intended policy the way Chrome reads it.
    $verify = Test-AllPoliciesApplied -EffectivePolicy $effectivePolicy
    if (-not $verify.Compliant) {
        foreach ($m in $verify.Mismatches) { Write-Log "  VERIFY MISMATCH: $m" "WARN" }
        $errors += "Post-apply verification failed for: $($verify.Mismatches -join ', ')"
    }
    Save-CachedPolicy -EffectivePolicy $effectivePolicy
    
    # Determine compliance status
    $status = if ($errors.Count -eq 0) { "Compliant" } 
              elseif ($keysWritten -gt 0) { "PartiallyApplied" }
              else { "Error" }
    
    # Report back to API
    $errorsJson = if ($errors.Count -gt 0) { $errors | ConvertTo-Json -Compress } else { $null }
    Send-ComplianceReport -ClientCert $clientCert -DeviceId $deviceId -DeviceName $deviceName `
        -PolicyHash $serverHash -Status $status -Errors $errorsJson `
        -KeysWritten $keysWritten -KeysRemoved $keysRemoved
    
    Write-Log "Remediation complete: $keysWritten written, $keysRemoved removed, Status: $status"
    Write-Output "SUCCESS: $keysWritten policies applied, $keysRemoved stale removed. Hash: $serverHash"
    $script:ExitCode = 0
}
catch {
    Write-Log "Remediation script error: $_" "ERROR"
    Write-Output "FAILED: $_"
    $script:ExitCode = 1
}
finally {
    # Always send logs to server (best-effort)
    if ($script:ClientCertForLog -and $script:DeviceIdForLog) {
        Send-LogBatch -ClientCert $script:ClientCertForLog -DeviceId $script:DeviceIdForLog
    }
    Write-Log "Remediation script finished (exit: $($script:ExitCode))"
}
exit $script:ExitCode
