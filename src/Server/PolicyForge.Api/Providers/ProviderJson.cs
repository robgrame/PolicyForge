using System.Text.Json;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>Helpers for building <see cref="ResolvedInstruction"/> payloads.</summary>
internal static class ProviderJson
{
    public static JsonElement ToElement(object value) =>
        JsonSerializer.SerializeToElement(value, ConfigurationJson.Options);
}
