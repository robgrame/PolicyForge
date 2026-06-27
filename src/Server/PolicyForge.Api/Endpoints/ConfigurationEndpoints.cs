using PolicyForge.Api.Providers;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Endpoints;

public static class ConfigurationEndpoints
{
    public static void MapConfigurationEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/configuration").WithTags("Configuration Engine");

        // GET /api/configuration/providers - provider types supported by this server.
        group.MapGet("/providers", (ConfigurationProviderRegistry registry) =>
            Results.Ok(registry.SupportedTypes.OrderBy(t => t).Select(t => t.ToString())))
            .WithName("GetSupportedProviders");

        // POST /api/configuration/compile - validate and compile a set of authored items into the
        // flat, client-ready instruction set (no persistence). Useful for authoring previews and tests.
        group.MapPost("/compile", (CompileRequest request, ConfigurationCompiler compiler) =>
        {
            var items = request.Items ?? new List<ConfigurationItem>();

            var errors = compiler.Validate(items);
            if (errors.Count > 0)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["items"] = errors.ToArray() });

            var resolved = compiler.BuildResolved(request.DeviceId ?? string.Empty, items);
            return Results.Ok(resolved);
        })
        .WithName("CompileConfiguration");
    }

    public sealed record CompileRequest
    {
        public string? DeviceId { get; init; }
        public List<ConfigurationItem>? Items { get; init; }
    }
}
