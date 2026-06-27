using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>
/// Turns a set of authored <see cref="ConfigurationItem"/>s into a flat, client-ready
/// <see cref="ResolvedConfiguration"/> by dispatching each item to its provider. This is the
/// generic equivalent of the legacy Chrome-only effective-policy resolution.
/// </summary>
public sealed class ConfigurationCompiler
{
    private readonly ConfigurationProviderRegistry _registry;
    private readonly ConfigurationGuardrails _guardrails;

    public ConfigurationCompiler(ConfigurationProviderRegistry registry, ConfigurationGuardrails guardrails)
    {
        _registry = registry;
        _guardrails = guardrails;
    }

    /// <summary>
    /// Validate every item against its provider, then run safety guardrails over the compiled
    /// instructions. Returns all errors found (both syntactic and guardrail violations).
    /// </summary>
    public IReadOnlyList<string> Validate(IEnumerable<ConfigurationItem> items)
    {
        var errors = new List<string>();
        var compilable = new List<ConfigurationItem>();

        foreach (var item in items)
        {
            if (!_registry.TryGet(item.Provider, out var provider))
            {
                errors.Add($"Item '{item.Id}': unsupported provider '{item.Provider}'.");
                continue;
            }

            var result = provider.Validate(item.PayloadJson);
            if (!result.IsValid)
                errors.AddRange(result.Errors.Select(e => $"Item '{item.Id}' ({item.Provider}): {e}"));
            else
                compilable.Add(item);
        }

        // Guardrails run on the lowered instructions so ADMX (compiled to registry) is covered too.
        if (compilable.Count > 0)
        {
            try
            {
                errors.AddRange(_guardrails.Evaluate(Compile(compilable)));
            }
            catch
            {
                // A compile failure here means an item is malformed in a way Validate didn't catch;
                // the syntactic errors above (or version creation) will surface it. Don't mask them.
            }
        }

        return errors;
    }

    /// <summary>Compile items into a flat instruction list (order preserved).</summary>
    public IReadOnlyList<ResolvedInstruction> Compile(IEnumerable<ConfigurationItem> items)
    {
        var instructions = new List<ResolvedInstruction>();
        foreach (var item in items)
            instructions.AddRange(_registry.Get(item.Provider).Compile(item));
        return instructions;
    }

    /// <summary>Compile items and wrap them with the device id, a content hash and conflict warnings.</summary>
    public ResolvedConfiguration BuildResolved(string deviceId, IEnumerable<ConfigurationItem> items)
    {
        var instructions = Compile(items);
        return new ResolvedConfiguration
        {
            DeviceId = deviceId,
            Instructions = instructions,
            Hash = ComputeHash(instructions),
            Warnings = ConflictWarnings(instructions),
        };
    }

    /// <summary>Wrap an already-compiled (e.g. de-duplicated) instruction set with id and hash.</summary>
    public ResolvedConfiguration BuildResolvedFromInstructions(string deviceId, IReadOnlyList<ResolvedInstruction> instructions)
        => new()
        {
            DeviceId = deviceId,
            Instructions = instructions,
            Hash = ComputeHash(instructions),
            Warnings = ConflictWarnings(instructions),
        };

    /// <summary>
    /// Detect instructions that converge on the same target (hive+key+name for registry, full
    /// payload otherwise). De-duplication keeps the first writer; this surfaces the collision so
    /// authors know a later item is being shadowed.
    /// </summary>
    public static IReadOnlyList<string> ConflictWarnings(IReadOnlyList<ResolvedInstruction> instructions)
    {
        var warnings = new List<string>();
        var seen = new Dictionary<string, ResolvedInstruction>(StringComparer.OrdinalIgnoreCase);
        foreach (var i in instructions)
        {
            var key = TargetKey(i);
            if (seen.TryGetValue(key, out var first))
                warnings.Add($"Conflict on the same target: '{Label(i)}' is shadowed by '{Label(first)}' (first/highest-priority writer wins).");
            else
                seen[key] = i;
        }
        return warnings;
    }

    private static string Label(ResolvedInstruction i)
        => string.IsNullOrWhiteSpace(i.Name) ? i.SourceItemId ?? "(item)" : i.Name!;

    private static string TargetKey(ResolvedInstruction i)
    {
        if (TryGet(i.Data, "hive", out var hive) && TryGet(i.Data, "key", out var key))
        {
            TryGet(i.Data, "name", out var name);
            return $"{i.Provider}|{hive}|{key}|{name}".ToLowerInvariant();
        }
        return $"{i.Provider}|{i.Data.GetRawText()}";
    }

    private static bool TryGet(JsonElement element, string property, out string value)
    {
        value = string.Empty;
        if (element.ValueKind != JsonValueKind.Object) return false;
        foreach (var p in element.EnumerateObject())
        {
            if (string.Equals(p.Name, property, StringComparison.OrdinalIgnoreCase))
            {
                value = p.Value.ValueKind == JsonValueKind.String ? (p.Value.GetString() ?? "") : p.Value.GetRawText();
                return true;
            }
        }
        return false;
    }

    private static string ComputeHash(IReadOnlyList<ResolvedInstruction> instructions)
    {
        var canonical = JsonSerializer.Serialize(instructions, ConfigurationJson.Options);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
