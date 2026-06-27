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

    public ConfigurationCompiler(ConfigurationProviderRegistry registry) => _registry = registry;

    /// <summary>Validate every item against its provider, returning all errors found.</summary>
    public IReadOnlyList<string> Validate(IEnumerable<ConfigurationItem> items)
    {
        var errors = new List<string>();
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

    /// <summary>Compile items and wrap them with the device id and a content hash.</summary>
    public ResolvedConfiguration BuildResolved(string deviceId, IEnumerable<ConfigurationItem> items)
    {
        var instructions = Compile(items);
        return new ResolvedConfiguration
        {
            DeviceId = deviceId,
            Instructions = instructions,
            Hash = ComputeHash(instructions),
        };
    }

    private static string ComputeHash(IReadOnlyList<ResolvedInstruction> instructions)
    {
        var canonical = JsonSerializer.Serialize(instructions, ConfigurationJson.Options);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
