using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Data.AppConfiguration;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Reads and writes the client-certificate trust configuration.
/// </summary>
public interface IClientCertConfigStore
{
    Task<ClientCertConfig> GetAsync(CancellationToken ct = default);
    Task SaveAsync(ClientCertConfig config, CancellationToken ct = default);
    bool IsBackingStoreAvailable { get; }
}

/// <summary>
/// Persists client-certificate trust configuration to Azure App Configuration under the
/// ClientCert:* key namespace (mirrors the intune-wipe-portal layout). When App Configuration
/// is not wired (local dev), returns a disabled configuration and rejects writes.
/// </summary>
public class AppConfigClientCertConfigStore : IClientCertConfigStore
{
    private const string KeyEnabled = "ClientCert:Enabled";
    private const string KeyCheckRevocation = "ClientCert:CheckRevocation";
    private const string KeyRevocationMode = "ClientCert:RevocationMode";
    private const string KeyRoots = "ClientCert:TrustedRootCertificates";          // comma-joined base64 DER
    private const string KeyIntermediates = "ClientCert:TrustedIntermediateCertificates"; // comma-joined base64 DER
    private const string KeyThumbprints = "ClientCert:TrustedCaThumbprints";       // comma-joined
    private const string KeySubjects = "ClientCert:TrustedCaSubjects";             // pipe-joined

    private readonly ConfigurationClient? _client;
    private readonly ILogger<AppConfigClientCertConfigStore> _logger;

    public AppConfigClientCertConfigStore(ILogger<AppConfigClientCertConfigStore> logger, ConfigurationClient? client = null)
    {
        _logger = logger;
        _client = client;
    }

    public bool IsBackingStoreAvailable => _client is not null;

    public async Task<ClientCertConfig> GetAsync(CancellationToken ct = default)
    {
        var config = new ClientCertConfig();
        if (_client is null)
        {
            return config; // disabled by default in local dev
        }

        config.Enabled = await GetBoolAsync(KeyEnabled, false, ct);
        config.CheckRevocation = await GetBoolAsync(KeyCheckRevocation, false, ct);
        config.RevocationMode = await GetStringAsync(KeyRevocationMode, "Online", ct);

        var roots = SplitCsv(await GetStringAsync(KeyRoots, "", ct));
        var intermediates = SplitCsv(await GetStringAsync(KeyIntermediates, "", ct));

        config.Certificates = new List<CaCertificateInfo>();
        config.Certificates.AddRange(ParseCerts(roots, isRoot: true));
        config.Certificates.AddRange(ParseCerts(intermediates, isRoot: false));
        return config;
    }

    public async Task SaveAsync(ClientCertConfig config, CancellationToken ct = default)
    {
        if (_client is null)
        {
            throw new InvalidOperationException("Azure App Configuration is not configured (AppConfig:Endpoint missing).");
        }

        var roots = config.Certificates.Where(c => c.IsRoot).Select(c => c.Base64).Where(b => !string.IsNullOrWhiteSpace(b));
        var intermediates = config.Certificates.Where(c => !c.IsRoot).Select(c => c.Base64).Where(b => !string.IsNullOrWhiteSpace(b));
        var thumbprints = config.Certificates.Select(c => c.Thumbprint).Where(t => !string.IsNullOrWhiteSpace(t));
        var subjects = config.Certificates.Select(c => c.Subject).Where(s => !string.IsNullOrWhiteSpace(s));

        await SetAsync(KeyEnabled, config.Enabled ? "true" : "false", ct);
        await SetAsync(KeyCheckRevocation, config.CheckRevocation ? "true" : "false", ct);
        await SetAsync(KeyRevocationMode, config.RevocationMode ?? "Online", ct);
        await SetAsync(KeyRoots, string.Join(",", roots), ct);
        await SetAsync(KeyIntermediates, string.Join(",", intermediates), ct);
        await SetAsync(KeyThumbprints, string.Join(",", thumbprints), ct);
        await SetAsync(KeySubjects, string.Join("|", subjects), ct);
    }

    private IEnumerable<CaCertificateInfo> ParseCerts(IEnumerable<string> base64List, bool isRoot)
    {
        foreach (var b64 in base64List)
        {
            CaCertificateInfo? info = null;
            try
            {
                var bytes = Convert.FromBase64String(b64);
                using var cert = X509CertificateLoader.LoadCertificate(bytes);
                info = new CaCertificateInfo
                {
                    Subject = cert.Subject,
                    Issuer = cert.Issuer,
                    Thumbprint = cert.Thumbprint,
                    Base64 = b64,
                    IsRoot = cert.Subject == cert.Issuer,
                    NotAfter = cert.NotAfter
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse stored CA certificate ({Kind}).", isRoot ? "root" : "intermediate");
            }
            if (info is not null) yield return info;
        }
    }

    private async Task<string> GetStringAsync(string key, string fallback, CancellationToken ct)
    {
        try
        {
            var resp = await _client!.GetConfigurationSettingAsync(key, cancellationToken: ct);
            return resp.Value?.Value ?? fallback;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return fallback;
        }
    }

    private async Task<bool> GetBoolAsync(string key, bool fallback, CancellationToken ct)
    {
        var raw = await GetStringAsync(key, fallback ? "true" : "false", ct);
        return bool.TryParse(raw, out var b) ? b : fallback;
    }

    private async Task SetAsync(string key, string value, CancellationToken ct)
    {
        await _client!.SetConfigurationSettingAsync(new ConfigurationSetting(key, value), onlyIfUnchanged: false, ct);
    }

    private static IEnumerable<string> SplitCsv(string value) =>
        string.IsNullOrWhiteSpace(value)
            ? Array.Empty<string>()
            : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
