<#
.SYNOPSIS
    Detection: verify the Chrome Policy Manager API endpoint machine env vars.

.DESCRIPTION
    Deployed as an Intune Proactive Remediation (Detection). Confirms that the
    machine-scope environment variables consumed by the Chrome Policy Manager
    detect/remediate scripts are present and match the expected values:

        CPM_API_URL            = $ExpectedApiUrl
        CPM_CERT_ISSUER_LIKE   = $ExpectedCertIssuerLike   (optional, '' = opt out)

    Exit 0 -> values already correct (compliant).
    Exit 1 -> missing or mismatched (triggers Remediate-CpmEndpoint.ps1).

.NOTES
    Context: SYSTEM (Proactive Remediation), 64-bit.
    Keep these constants in lockstep with Remediate-CpmEndpoint.ps1.
#>

[CmdletBinding()]
param()

# === EDIT BEFORE UPLOADING TO INTUNE =========================================
$ExpectedApiUrl         = 'https://cpm-dev-api.azurewebsites.net'
$ExpectedCertIssuerLike = 'CN=MSLABS-SUBCA01'   # '' to opt out of pinning via env
# =============================================================================

$UrlVar        = 'CPM_API_URL'
$CertIssuerVar = 'CPM_CERT_ISSUER_LIKE'
$LogDir        = Join-Path $env:ProgramData 'ChromePolicyManager'
$LogFile       = Join-Path $LogDir 'endpoint-detection.log'

function Write-Log {
    param([string]$Message)
    if (-not $Message) { return }
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $line = "[{0}] {1}" -f (Get-Date -Format o), ($Message -replace "[\r\n]+", ' ')
    $line | Out-File -FilePath $LogFile -Append -Encoding utf8
    Write-Host $line
}

try {
    $currentUrl    = [Environment]::GetEnvironmentVariable($UrlVar, 'Machine')
    $currentIssuer = [Environment]::GetEnvironmentVariable($CertIssuerVar, 'Machine')
    Write-Log ("Snapshot: {0}='{1}', {2}='{3}' (expected URL='{4}', Issuer='{5}')" -f `
        $UrlVar, $currentUrl, $CertIssuerVar, $currentIssuer, $ExpectedApiUrl, $ExpectedCertIssuerLike)

    if (-not $currentUrl -or $currentUrl.Trim().TrimEnd('/') -ne $ExpectedApiUrl.TrimEnd('/')) {
        Write-Log ("REMEDIATE: {0} missing or mismatched." -f $UrlVar)
        exit 1
    }

    if ($ExpectedCertIssuerLike) {
        if (-not $currentIssuer -or $currentIssuer.Trim() -ne $ExpectedCertIssuerLike) {
            Write-Log ("REMEDIATE: {0} missing or mismatched." -f $CertIssuerVar)
            exit 1
        }
    }

    Write-Log "OK: endpoint env vars compliant."
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
