namespace ChromePolicyManager.Api.Models;

/// <summary>
/// A trusted CA certificate (root or intermediate) used to validate device client certificates.
/// </summary>
public record CaCertificateInfo
{
    public string Subject { get; init; } = "";
    public string Issuer { get; init; } = "";
    public string Thumbprint { get; init; } = "";
    /// <summary>Base64-encoded DER of the certificate.</summary>
    public string Base64 { get; init; } = "";
    /// <summary>True when Subject == Issuer (self-signed root).</summary>
    public bool IsRoot { get; init; }
    public DateTime NotAfter { get; init; }
}

/// <summary>
/// Client-certificate trust configuration for device endpoints. Persisted to Azure App Configuration
/// under the ClientCert:* key namespace and consumed by <c>ClientCertificateMiddleware</c>.
/// </summary>
public class ClientCertConfig
{
    /// <summary>Master switch: when true, device endpoints require a trusted client certificate.</summary>
    public bool Enabled { get; set; }

    /// <summary>Whether to perform CRL/OCSP revocation checking during chain validation.</summary>
    public bool CheckRevocation { get; set; }

    /// <summary>Revocation mode: Online | Offline | NoCheck.</summary>
    public string RevocationMode { get; set; } = "Online";

    /// <summary>Trusted root + intermediate CA certificates.</summary>
    public List<CaCertificateInfo> Certificates { get; set; } = new();
}
