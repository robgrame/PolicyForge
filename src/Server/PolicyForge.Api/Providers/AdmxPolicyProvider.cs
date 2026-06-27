using System.Text.Json;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>
/// Provider for ADMX-backed policies. Realises the core design insight: an ADMX policy is just a
/// (set of) registry value(s). The registry mapping is captured into the payload at authoring time,
/// so this provider compiles a policy down to one or more <see cref="ProviderType.RegistryValue"/>
/// instructions — the client only ever needs a registry handler to apply ADMX policies.
/// </summary>
public sealed class AdmxPolicyProvider : IConfigurationProvider
{
    public ProviderType Type => ProviderType.AdmxPolicy;

    public ProviderValidationResult Validate(string payloadJson)
    {
        AdmxPolicyPayload payload;
        try
        {
            payload = JsonSerializer.Deserialize<AdmxPolicyPayload>(payloadJson, ConfigurationJson.Options)
                      ?? new AdmxPolicyPayload();
        }
        catch (JsonException ex)
        {
            return ProviderValidationResult.Fail($"Invalid AdmxPolicy payload: {ex.Message}");
        }

        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(payload.Namespace))
            errors.Add("AdmxPolicy.Namespace is required.");
        if (string.IsNullOrWhiteSpace(payload.PolicyId))
            errors.Add("AdmxPolicy.PolicyId is required.");
        if (string.IsNullOrWhiteSpace(payload.RegistryKey))
            errors.Add("AdmxPolicy.RegistryKey is required.");
        if (string.IsNullOrWhiteSpace(payload.ValueName))
            errors.Add("AdmxPolicy.ValueName is required.");
        if (payload.Ensure == EnsureState.Present && payload.Value is null)
            errors.Add("AdmxPolicy.Value is required when Ensure is Present.");
        if (payload.IsList && payload.Ensure == EnsureState.Present
            && payload.Value is { ValueKind: not JsonValueKind.Array })
            errors.Add("AdmxPolicy.Value must be an array when IsList is true.");

        return errors.Count == 0 ? ProviderValidationResult.Ok : ProviderValidationResult.Fail(errors.ToArray());
    }

    public IReadOnlyList<ResolvedInstruction> Compile(ConfigurationItem item)
    {
        var payload = item.DeserializePayload<AdmxPolicyPayload>();

        // Removal: drop the scalar value, or the whole list subkey.
        if (payload.Ensure == EnsureState.Absent)
        {
            if (payload.IsList)
            {
                return new[]
                {
                    RegistryInstruction(item, "Remove", new RegistryValuePayload
                    {
                        Hive = payload.Hive,
                        Key = ListSubkey(payload),
                        Ensure = EnsureState.Absent,
                    })
                };
            }

            return new[]
            {
                RegistryInstruction(item, "Remove", new RegistryValuePayload
                {
                    Hive = payload.Hive,
                    Key = payload.RegistryKey,
                    Name = payload.ValueName,
                    Ensure = EnsureState.Absent,
                })
            };
        }

        // List policy: expand into the canonical ADMX list form (subkey with numbered values).
        if (payload.IsList && payload.Value is { ValueKind: JsonValueKind.Array } array)
        {
            var subkey = ListSubkey(payload);
            var instructions = new List<ResolvedInstruction>();
            var index = 1;
            foreach (var element in array.EnumerateArray())
            {
                instructions.Add(RegistryInstruction(item, "Set", new RegistryValuePayload
                {
                    Hive = payload.Hive,
                    Key = subkey,
                    Name = index.ToString(),
                    Type = payload.ValueType,
                    Data = element,
                }));
                index++;
            }
            return instructions;
        }

        // Scalar policy: a single registry value.
        return new[]
        {
            RegistryInstruction(item, "Set", new RegistryValuePayload
            {
                Hive = payload.Hive,
                Key = payload.RegistryKey,
                Name = payload.ValueName,
                Type = payload.ValueType,
                Data = payload.Value,
            })
        };
    }

    private static string ListSubkey(AdmxPolicyPayload payload) =>
        $"{payload.RegistryKey.TrimEnd('\\')}\\{payload.ValueName}";

    private static ResolvedInstruction RegistryInstruction(ConfigurationItem item, string action, RegistryValuePayload registry) => new()
    {
        Provider = ProviderType.RegistryValue,
        Action = action,
        Data = ProviderJson.ToElement(registry),
        SourceItemId = item.Id,
        Name = item.Name,
    };
}
