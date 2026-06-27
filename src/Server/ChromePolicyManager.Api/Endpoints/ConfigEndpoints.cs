using ChromePolicyManager.Api.Models;
using ChromePolicyManager.Api.Services;

namespace ChromePolicyManager.Api.Endpoints;

public static class ConfigEndpoints
{
    public static void MapConfigEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/config").WithTags("Configuration");

        // GET /api/config/clientcert - current client-certificate trust configuration
        group.MapGet("/clientcert", async (IClientCertConfigStore store, CancellationToken ct) =>
        {
            var config = await store.GetAsync(ct);
            return Results.Ok(new
            {
                config.Enabled,
                config.CheckRevocation,
                config.RevocationMode,
                BackingStoreAvailable = store.IsBackingStoreAvailable,
                Certificates = config.Certificates
            });
        })
        .WithName("GetClientCertConfig");

        // PUT /api/config/clientcert - replace the client-certificate trust configuration
        group.MapPut("/clientcert", async (ClientCertConfig config, IClientCertConfigStore store, CancellationToken ct) =>
        {
            if (!store.IsBackingStoreAvailable)
            {
                return Results.Problem(
                    detail: "Azure App Configuration is not configured for this API (AppConfig:Endpoint missing).",
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            try
            {
                await store.SaveAsync(config, ct);
                return Results.NoContent();
            }
            catch (Exception ex)
            {
                return Results.Problem(detail: ex.Message, statusCode: StatusCodes.Status500InternalServerError);
            }
        })
        .WithName("SaveClientCertConfig");
    }
}
