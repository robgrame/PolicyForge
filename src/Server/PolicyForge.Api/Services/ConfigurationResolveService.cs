using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PolicyForge.Api.Data;
using PolicyForge.Api.Providers;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Services;

/// <summary>
/// Generic, provider-agnostic device resolution — the evolution of <see cref="EffectivePolicyService"/>.
/// Resolves a device's Entra group memberships, gathers the configuration items from every active
/// assignment (priority-ordered), compiles them through the provider engine and de-duplicates the
/// resulting instructions (first/highest-priority writer wins per instruction key).
/// </summary>
public sealed class ConfigurationResolveService
{
    private readonly AppDbContext _db;
    private readonly IGraphService _graph;
    private readonly ConfigurationCompiler _compiler;

    public ConfigurationResolveService(AppDbContext db, IGraphService graph, ConfigurationCompiler compiler)
    {
        _db = db;
        _graph = graph;
        _compiler = compiler;
    }

    public async Task<ResolvedConfiguration> ResolveAsync(string deviceId)
    {
        // 1. Trusted, server-side group membership lookup.
        var groupIds = await _graph.GetDeviceGroupMembershipsAsync(deviceId);

        // 2. Active assignments targeting those groups, highest priority first.
        var assignments = await _db.ConfigurationAssignments
            .Include(a => a.ProfileVersion)
            .Where(a => a.Enabled && groupIds.Contains(a.EntraGroupId))
            .Where(a => a.ProfileVersion.Status == Models.PolicyVersionStatus.Active)
            .OrderBy(a => a.Priority)
            .ToListAsync();

        // 3. Gather authored items in priority order.
        var items = new List<ConfigurationItem>();
        foreach (var a in assignments)
        {
            var parsed = JsonSerializer.Deserialize<List<ConfigurationItem>>(
                a.ProfileVersion.ItemsJson, ConfigurationJson.Options);
            if (parsed is not null)
                items.AddRange(parsed);
        }

        // 4. Compile then de-duplicate instructions (first writer wins per target key).
        var resolved = _compiler.BuildResolved(deviceId, items);
        var deduped = DedupeByTarget(resolved.Instructions);

        if (deduped.Count == resolved.Instructions.Count)
            return resolved;

        // Re-wrap with the de-duplicated set so the hash stays in sync with what the client applies.
        return _compiler.BuildResolvedFromInstructions(deviceId, deduped);
    }

    /// <summary>
    /// Keeps the first occurrence of each instruction target so a higher-priority assignment wins
    /// over a lower-priority one that touches the same target. The target identity deliberately
    /// excludes the desired value: for registry instructions it is hive+key+name; for other
    /// providers we fall back to the provider plus the full payload (best effort).
    /// </summary>
    private static List<ResolvedInstruction> DedupeByTarget(IReadOnlyList<ResolvedInstruction> instructions)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<ResolvedInstruction>();
        foreach (var i in instructions)
        {
            if (seen.Add(TargetKey(i)))
                result.Add(i);
        }
        return result;
    }

    private static string TargetKey(ResolvedInstruction i)
    {
        // Registry instructions (incl. all compiled ADMX) identify a target by hive+key+name.
        if (TryGet(i.Data, "hive", out var hive) &&
            TryGet(i.Data, "key", out var key))
        {
            TryGet(i.Data, "name", out var name);
            return $"{i.Provider}|{hive}|{key}|{name}".ToLowerInvariant();
        }
        // Fallback: provider + full payload (cannot infer a value-independent target generically).
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
}
