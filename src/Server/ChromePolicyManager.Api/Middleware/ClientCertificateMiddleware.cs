using System.Security.Cryptography.X509Certificates;
using ChromePolicyManager.Api.Models;
using ChromePolicyManager.Api.Services;
using Microsoft.Extensions.Caching.Memory;

namespace ChromePolicyManager.Api.Middleware;

/// <summary>
/// Validates the device client certificate against the operator-configured trusted CA bundle
/// (managed from the Admin portal, persisted in Azure App Configuration).
///
/// This enforces the same trust decision APIM makes (issuer/chain), but inside the backend so it
/// also works when APIM is not deployed (e.g. the dev environment, which talks to the API directly).
/// When APIM IS configured (ApimGateway:ClientId set) the client cert never reaches the backend —
/// APIM terminates mTLS — so this middleware stands down and lets ApimGatewayMiddleware enforce the
/// APIM managed-identity check instead.
///
/// The certificate is read from the App Service forwarded header X-ARR-ClientCert (base64 DER), with
/// a fallback to the negotiated TLS connection certificate. On success the certificate CN (the Entra
/// device id) is forwarded downstream via X-Forwarded-Device-Id.
/// </summary>
public class ClientCertificateMiddleware
{
    private const string ForwardedCertHeader = "X-ARR-ClientCert";
    private const string ForwardedDeviceHeader = "X-Forwarded-Device-Id";
    private const string CacheKey = "ClientCertConfig";

    private static readonly string[] ProtectedDevicePaths = ["/api/devices"];
    private static readonly string[] ExemptPaths = ["/health", "/api/webhooks"];

    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ClientCertificateMiddleware> _logger;

    public ClientCertificateMiddleware(RequestDelegate next, IConfiguration configuration, ILogger<ClientCertificateMiddleware> logger)
    {
        _next = next;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, IClientCertConfigStore store, IMemoryCache cache)
    {
        var path = context.Request.Path.Value ?? "";

        if (!IsProtected(path) || IsExempt(path))
        {
            await _next(context);
            return;
        }

        // If APIM is in front, it owns mTLS termination and trust — stand down.
        if (!string.IsNullOrEmpty(_configuration["ApimGateway:ClientId"]))
        {
            await _next(context);
            return;
        }

        var config = await cache.GetOrCreateAsync(CacheKey, async entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(60);
            return await store.GetAsync(context.RequestAborted);
        }) ?? new ClientCertConfig();

        if (!config.Enabled)
        {
            // Enforcement disabled — preserve the existing direct-access behaviour.
            await _next(context);
            return;
        }

        var clientCert = ExtractCertificate(context);
        if (clientCert is null)
        {
            await Deny(context, "Client certificate required.");
            return;
        }

        using (clientCert)
        {
            if (!ValidateChain(clientCert, config, out var reason))
            {
                _logger.LogWarning("Client certificate rejected for {Path}: {Reason} (Subject={Subject}, Issuer={Issuer})",
                    path, reason, clientCert.Subject, clientCert.Issuer);
                await Deny(context, reason);
                return;
            }

            var deviceId = ExtractCommonName(clientCert.Subject);
            if (!string.IsNullOrEmpty(deviceId))
            {
                context.Request.Headers[ForwardedDeviceHeader] = deviceId;
                context.Items["TrustedDeviceId"] = deviceId;
            }

            _logger.LogDebug("Client certificate validated for {Path} (deviceId={DeviceId})", path, deviceId);
        }

        await _next(context);
    }

    private bool ValidateChain(X509Certificate2 cert, ClientCertConfig config, out string reason)
    {
        reason = "";

        if (cert.NotAfter < DateTime.UtcNow || cert.NotBefore > DateTime.UtcNow)
        {
            reason = "Client certificate is outside its validity period.";
            return false;
        }

        var roots = LoadCerts(config.Certificates.Where(c => c.IsRoot));
        var intermediates = LoadCerts(config.Certificates.Where(c => !c.IsRoot));

        if (roots.Count == 0)
        {
            reason = "No trusted root CA certificates are configured.";
            return false;
        }

        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.RevocationMode = ResolveRevocationMode(config);
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            foreach (var root in roots) chain.ChainPolicy.CustomTrustStore.Add(root);
            foreach (var inter in intermediates) chain.ChainPolicy.ExtraStore.Add(inter);

            var built = chain.Build(cert);
            if (!built)
            {
                var statuses = chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Where(s => s.Length > 0);
                reason = "Certificate chain validation failed: " + string.Join("; ", statuses);
                return false;
            }

            return true;
        }
        finally
        {
            foreach (var c in roots) c.Dispose();
            foreach (var c in intermediates) c.Dispose();
        }
    }

    private X509RevocationMode ResolveRevocationMode(ClientCertConfig config)
    {
        if (!config.CheckRevocation) return X509RevocationMode.NoCheck;
        return config.RevocationMode?.Trim().ToLowerInvariant() switch
        {
            "offline" => X509RevocationMode.Offline,
            "nocheck" => X509RevocationMode.NoCheck,
            _ => X509RevocationMode.Online
        };
    }

    private List<X509Certificate2> LoadCerts(IEnumerable<CaCertificateInfo> source)
    {
        var list = new List<X509Certificate2>();
        foreach (var info in source)
        {
            try
            {
                list.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(info.Base64)));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load configured CA certificate {Thumbprint}.", info.Thumbprint);
            }
        }
        return list;
    }

    private X509Certificate2? ExtractCertificate(HttpContext context)
    {
        // Azure App Service forwards the negotiated client cert as base64 DER in X-ARR-ClientCert.
        var header = context.Request.Headers[ForwardedCertHeader].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(header))
        {
            try
            {
                return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(header));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to decode {Header}.", ForwardedCertHeader);
            }
        }

        // Fallback: certificate negotiated directly on the TLS connection (local/dev).
        return context.Connection.ClientCertificate;
    }

    private static string ExtractCommonName(string subject)
    {
        // Subject like "CN=<deviceId>, OU=..., O=..."
        foreach (var part in subject.Split(',', StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return part.Substring(3).Trim();
        }
        return "";
    }

    private static async Task Deny(HttpContext context, string message)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new { Error = "Unauthorized", Message = message });
    }

    private static bool IsProtected(string path) =>
        ProtectedDevicePaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    private static bool IsExempt(string path) =>
        ExemptPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
}

public static class ClientCertificateMiddlewareExtensions
{
    public static IApplicationBuilder UseClientCertificateValidation(this IApplicationBuilder app)
        => app.UseMiddleware<ClientCertificateMiddleware>();
}
