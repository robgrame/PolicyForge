<#
.SYNOPSIS
    Remediation: set the Chrome Policy Manager API endpoint machine env vars.

.DESCRIPTION
    Writes the machine-scope environment variables consumed by the Chrome Policy
    Manager detect/remediate scripts:

        CPM_API_URL            = $ExpectedApiUrl
        CPM_CERT_ISSUER_LIKE   = $ExpectedCertIssuerLike   ('' deletes the var)

    Keep these constants in lockstep with Detect-CpmEndpoint.ps1.

.NOTES
    Context: SYSTEM (Proactive Remediation), 64-bit.
    Exit 0 -> remediation succeeded. Non-zero -> failed.
#>

[CmdletBinding()]
param()

# === EDIT BEFORE UPLOADING TO INTUNE =========================================
$ExpectedApiUrl         = 'https://cpm-dev-api.azurewebsites.net'
$ExpectedCertIssuerLike = 'CN=MSLABS-SUBCA01'   # '' to remove the var
# =============================================================================

$UrlVar        = 'CPM_API_URL'
$CertIssuerVar = 'CPM_CERT_ISSUER_LIKE'
$LogDir        = Join-Path $env:ProgramData 'ChromePolicyManager'
$LogFile       = Join-Path $LogDir 'endpoint-remediation.log'

function Write-Log {
    param([string]$Message)
    if (-not $Message) { return }
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $line = "[{0}] {1}" -f (Get-Date -Format o), ($Message -replace "[\r\n]+", ' ')
    $line | Out-File -FilePath $LogFile -Append -Encoding utf8
    Write-Host $line
}

try {
    Write-Log ("Remediation started. Setting {0}='{1}'." -f $UrlVar, $ExpectedApiUrl)
    [Environment]::SetEnvironmentVariable($UrlVar, $ExpectedApiUrl, 'Machine')

    if ($ExpectedCertIssuerLike) {
        [Environment]::SetEnvironmentVariable($CertIssuerVar, $ExpectedCertIssuerLike, 'Machine')
        Write-Log ("Set {0}='{1}'." -f $CertIssuerVar, $ExpectedCertIssuerLike)
    } else {
        [Environment]::SetEnvironmentVariable($CertIssuerVar, $null, 'Machine')
        Write-Log ("Removed {0} (empty expected value)." -f $CertIssuerVar)
    }

    # Verify read-back.
    $writtenUrl    = [Environment]::GetEnvironmentVariable($UrlVar, 'Machine')
    $writtenIssuer = [Environment]::GetEnvironmentVariable($CertIssuerVar, 'Machine')
    Write-Log ("Read-back: {0}='{1}', {2}='{3}'." -f $UrlVar, $writtenUrl, $CertIssuerVar, $writtenIssuer)

    if ($writtenUrl.TrimEnd('/') -ne $ExpectedApiUrl.TrimEnd('/')) {
        Write-Log ("FAIL: {0} read-back '{1}' does not match expected." -f $UrlVar, $writtenUrl)
        exit 1
    }

    Write-Log "OK: endpoint env vars written to Machine scope."
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
