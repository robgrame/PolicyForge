using System.Text.Json;

namespace PolicyForge.Contracts.Configuration;

/// <summary>
/// A compiled, client-ready instruction. Providers turn authored <see cref="ConfigurationItem"/>s
/// into a flat list of these. The client's provider dispatcher executes each instruction without
/// needing product-specific knowledge (e.g. an AdmxPolicy is already compiled to RegistryValue
/// instructions with explicit hive/key/name/type/data).
/// </summary>
public sealed record ResolvedInstruction
{
    /// <summary>The provider that the client handler must use to apply this instruction.</summary>
    public ProviderType Provider { get; init; }

    /// <summary>Desired action: <c>Set</c> (ensure present) or <c>Remove</c> (ensure absent).</summary>
    public string Action { get; init; } = "Set";

    /// <summary>Provider-specific, fully-resolved payload (e.g. a <see cref="RegistryValuePayload"/>).</summary>
    public JsonElement Data { get; init; }

    /// <summary>Id of the authored <see cref="ConfigurationItem"/> this came from (for reporting).</summary>
    public string? SourceItemId { get; init; }

    /// <summary>Optional human label, propagated from the source item.</summary>
    public string? Name { get; init; }
}

/// <summary>
/// The full set of instructions a given device must converge to, plus a content hash the client
/// can use to short-circuit when nothing changed.
/// </summary>
public sealed record ResolvedConfiguration
{
    public string DeviceId { get; init; } = string.Empty;

    public IReadOnlyList<ResolvedInstruction> Instructions { get; init; } = Array.Empty<ResolvedInstruction>();

    /// <summary>SHA-256 (lowercase hex) of the canonical serialized instruction set.</summary>
    public string Hash { get; init; } = string.Empty;

    /// <summary>Non-blocking advisories (e.g. two items converging on the same target).</summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
