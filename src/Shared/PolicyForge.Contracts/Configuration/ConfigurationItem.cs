using System.Text.Json;
using System.Text.Json.Serialization;

namespace PolicyForge.Contracts.Configuration;

/// <summary>
/// A single authored unit of configuration inside a profile version. Provider-agnostic:
/// the <see cref="Provider"/> selects the handler and <see cref="PayloadJson"/> carries the
/// provider-specific, typed payload (one of the *Payload records in this namespace).
/// </summary>
public sealed record ConfigurationItem
{
    /// <summary>Stable identifier of the item within its profile version.</summary>
    public string Id { get; init; } = Guid.NewGuid().ToString("n");

    /// <summary>Optional human label shown in the authoring UI and reports.</summary>
    public string? Name { get; init; }

    /// <summary>The provider that owns this item.</summary>
    public ProviderType Provider { get; init; }

    /// <summary>Provider-specific payload, serialized as JSON.</summary>
    public string PayloadJson { get; init; } = "{}";

    public T DeserializePayload<T>() =>
        JsonSerializer.Deserialize<T>(PayloadJson, ConfigurationJson.Options)
        ?? throw new InvalidOperationException($"Payload of item '{Id}' could not be deserialized as {typeof(T).Name}.");

    public static ConfigurationItem Create<T>(ProviderType provider, T payload, string? name = null) => new()
    {
        Provider = provider,
        Name = name,
        PayloadJson = JsonSerializer.Serialize(payload, ConfigurationJson.Options),
    };
}

/// <summary>Shared JSON options for configuration payloads (camelCase, enums as strings).</summary>
public static class ConfigurationJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

/// <summary>Payload for <see cref="ProviderType.RegistryValue"/>.</summary>
public sealed record RegistryValuePayload
{
    public RegistryHive Hive { get; init; } = RegistryHive.Hklm;

    /// <summary>Key path without the hive prefix, e.g. <c>SOFTWARE\Policies\Google\Chrome</c>.</summary>
    public string Key { get; init; } = string.Empty;

    /// <summary>Value name. Null or empty targets the key's default value.</summary>
    public string? Name { get; init; }

    public RegistryValueKind Type { get; init; } = RegistryValueKind.String;

    /// <summary>The desired value. Ignored when <see cref="Ensure"/> is <see cref="EnsureState.Absent"/>.</summary>
    public JsonElement? Data { get; init; }

    public EnsureState Ensure { get; init; } = EnsureState.Present;
}

/// <summary>
/// Payload for <see cref="ProviderType.AdmxPolicy"/>. The registry mapping (key/value/type) is
/// captured at authoring time from the ADMX catalog so the item is self-contained and compilation
/// is a pure function (no DB lookup). Compiles to one or more RegistryValue instructions.
/// </summary>
public sealed record AdmxPolicyPayload
{
    /// <summary>ADMX namespace / product, e.g. <c>chrome</c>, <c>edge</c>, <c>office16</c>.</summary>
    public string Namespace { get; init; } = string.Empty;

    /// <summary>Policy id/name as declared in the ADMX, e.g. <c>SafeBrowsingProtectionLevel</c>.</summary>
    public string PolicyId { get; init; } = string.Empty;

    public RegistryHive Hive { get; init; } = RegistryHive.Hklm;

    /// <summary>Target registry key (e.g. <c>SOFTWARE\Policies\Google\Chrome</c>).</summary>
    public string RegistryKey { get; init; } = string.Empty;

    /// <summary>Registry value name (usually equals the policy id).</summary>
    public string ValueName { get; init; } = string.Empty;

    public RegistryValueKind ValueType { get; init; } = RegistryValueKind.String;

    /// <summary>The configured value.</summary>
    public JsonElement? Value { get; init; }

    /// <summary>
    /// When true the value is a list policy, expanded into the canonical ADMX list form: a subkey
    /// named <see cref="ValueName"/> with numbered values (1, 2, 3...).
    /// </summary>
    public bool IsList { get; init; }

    public EnsureState Ensure { get; init; } = EnsureState.Present;

    /// <summary>Version of the ADMX/product this mapping was captured from (drift tracking).</summary>
    public string? AdmxVersion { get; init; }
}
