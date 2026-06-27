using System.Text.Json;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>
/// Anti-footgun safety checks that run over compiled <see cref="ResolvedInstruction"/>s (so ADMX
/// policies, already lowered to registry writes, are covered too). Blocks edits to destructive
/// areas of the OS by default. The rule set can be tightened via configuration
/// (<c>PolicyForge:Guardrails:*</c>) and disabled globally for advanced operators.
/// </summary>
public sealed class ConfigurationGuardrails
{
    private readonly bool _enabled;
    private readonly IReadOnlyList<string> _deniedRegistryPrefixes;
    private readonly IReadOnlySet<string> _criticalServices;

    // Registry sub-trees whose modification can break boot, security or service config.
    private static readonly string[] DefaultDeniedRegistryPrefixes =
    [
        @"SAM\",
        @"SECURITY\",
        @"SYSTEM\CurrentControlSet\Control\Lsa",
        @"SYSTEM\CurrentControlSet\Services",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ];

    // Services whose disabling/stopping commonly bricks Windows or its management plane.
    private static readonly string[] DefaultCriticalServices =
    [
        "RpcSs", "DcomLaunch", "LSM", "Power", "PlugPlay", "BrokerInfrastructure",
        "Winmgmt", "ProfSvc", "SamSs", "EventLog", "Schedule", "gpsvc",
        "Dnscache", "nsi", "mpssvc", "RpcEptMapper", "CoreMessagingRegistrar",
    ];

    public ConfigurationGuardrails(IConfiguration? configuration = null)
    {
        var section = configuration?.GetSection("PolicyForge:Guardrails");
        _enabled = section?.GetValue("Enabled", true) ?? true;

        var extraReg = section?.GetSection("DeniedRegistryPrefixes").Get<string[]>() ?? [];
        _deniedRegistryPrefixes = DefaultDeniedRegistryPrefixes
            .Concat(extraReg)
            .Select(p => p.TrimStart('\\'))
            .ToList();

        var extraSvc = section?.GetSection("CriticalServices").Get<string[]>() ?? [];
        _criticalServices = DefaultCriticalServices
            .Concat(extraSvc)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public bool Enabled => _enabled;

    /// <summary>Evaluate every instruction, returning a human-readable violation per blocked target.</summary>
    public IReadOnlyList<string> Evaluate(IEnumerable<ResolvedInstruction> instructions)
    {
        var violations = new List<string>();
        if (!_enabled) return violations;

        foreach (var i in instructions)
        {
            var v = Evaluate(i);
            if (v is not null) violations.Add(v);
        }
        return violations;
    }

    private string? Evaluate(ResolvedInstruction i)
    {
        var label = string.IsNullOrWhiteSpace(i.Name) ? i.SourceItemId ?? "(item)" : i.Name;
        return i.Provider switch
        {
            ProviderType.RegistryValue or ProviderType.AdmxPolicy => CheckRegistry(i.Data, label),
            ProviderType.WindowsService => CheckService(i.Data, label),
            ProviderType.FileResource => CheckFile(i.Data, label),
            ProviderType.ScheduledTask => CheckScheduledTask(i.Data, label),
            ProviderType.LocalGroupMembership => CheckLocalGroup(i.Data, label),
            _ => null,
        };
    }

    private string? CheckRegistry(JsonElement data, string label)
    {
        var key = GetString(data, "key");
        if (string.IsNullOrEmpty(key)) return null;
        var normalized = key.TrimStart('\\');
        foreach (var prefix in _deniedRegistryPrefixes)
        {
            if (normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return $"'{label}': writing to protected registry path '{key}' is blocked by guardrails (matches '{prefix}').";
        }
        return null;
    }

    private string? CheckService(JsonElement data, string label)
    {
        var name = GetString(data, "name");
        if (string.IsNullOrEmpty(name) || !_criticalServices.Contains(name)) return null;

        var startup = GetString(data, "startupType");
        var state = GetString(data, "state");
        if (string.Equals(startup, "Disabled", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(state, "Stopped", StringComparison.OrdinalIgnoreCase))
            return $"'{label}': disabling/stopping the critical service '{name}' is blocked by guardrails.";
        return null;
    }

    private static string? CheckFile(JsonElement data, string label)
    {
        var path = GetString(data, "targetPath");
        if (string.IsNullOrEmpty(path)) return null;
        var ensure = GetString(data, "ensure");
        if (string.Equals(ensure, "Absent", StringComparison.OrdinalIgnoreCase) && IsUnderWindows(path))
            return $"'{label}': deleting files under the Windows directory ('{path}') is blocked by guardrails.";
        return null;
    }

    private static string? CheckScheduledTask(JsonElement data, string label)
    {
        var ensure = GetString(data, "ensure");
        var taskPath = GetString(data, "path");
        if (string.Equals(ensure, "Absent", StringComparison.OrdinalIgnoreCase) &&
            taskPath.Replace('/', '\\').TrimStart('\\').StartsWith(@"Microsoft\Windows", StringComparison.OrdinalIgnoreCase))
            return $"'{label}': deleting built-in OS scheduled tasks under '\\Microsoft\\Windows' is blocked by guardrails.";
        return null;
    }

    private static string? CheckLocalGroup(JsonElement data, string label)
    {
        var group = GetString(data, "group");
        var action = GetString(data, "action");
        if (string.Equals(action, "Replace", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(group, "Administrators", StringComparison.OrdinalIgnoreCase))
            return $"'{label}': replacing the entire membership of the local Administrators group is blocked by guardrails (use Add/Remove).";
        return null;
    }

    private static bool IsUnderWindows(string path)
    {
        var p = path.Replace('/', '\\').Trim();
        return p.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase)
            || p.StartsWith("%SystemRoot%", StringComparison.OrdinalIgnoreCase)
            || p.StartsWith("%windir%", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetString(JsonElement element, string property)
    {
        if (element.ValueKind != JsonValueKind.Object) return string.Empty;
        foreach (var p in element.EnumerateObject())
        {
            if (string.Equals(p.Name, property, StringComparison.OrdinalIgnoreCase))
                return p.Value.ValueKind == JsonValueKind.String ? (p.Value.GetString() ?? "") : p.Value.GetRawText();
        }
        return string.Empty;
    }
}
