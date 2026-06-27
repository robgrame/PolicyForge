using System.Text.Json;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>
/// Provider for arbitrary registry values (GPP-style). Each item compiles to exactly one
/// instruction; the payload is already client-ready so compilation is a pass-through.
/// </summary>
public sealed class RegistryValueProvider : IConfigurationProvider
{
    public ProviderType Type => ProviderType.RegistryValue;

    public ProviderValidationResult Validate(string payloadJson)
    {
        RegistryValuePayload payload;
        try
        {
            payload = JsonSerializer.Deserialize<RegistryValuePayload>(payloadJson, ConfigurationJson.Options)
                      ?? new RegistryValuePayload();
        }
        catch (JsonException ex)
        {
            return ProviderValidationResult.Fail($"Invalid RegistryValue payload: {ex.Message}");
        }

        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(payload.Key))
            errors.Add("RegistryValue.Key is required.");
        if (payload.Ensure == EnsureState.Present && payload.Data is null)
            errors.Add("RegistryValue.Data is required when Ensure is Present.");

        return errors.Count == 0 ? ProviderValidationResult.Ok : ProviderValidationResult.Fail(errors.ToArray());
    }

    public IReadOnlyList<ResolvedInstruction> Compile(ConfigurationItem item)
    {
        var payload = item.DeserializePayload<RegistryValuePayload>();
        var action = payload.Ensure == EnsureState.Absent ? "Remove" : "Set";

        return new[]
        {
            new ResolvedInstruction
            {
                Provider = ProviderType.RegistryValue,
                Action = action,
                Data = ProviderJson.ToElement(payload),
                SourceItemId = item.Id,
                Name = item.Name,
            }
        };
    }
}
