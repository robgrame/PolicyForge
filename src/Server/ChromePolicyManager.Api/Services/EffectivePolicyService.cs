using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Resolves the effective Chrome policy for a device based on its Entra group memberships and assignment priorities.
/// </summary>
public class EffectivePolicyService
{
    private readonly AppDbContext _db;
    private readonly IGraphService _graphService;

    public EffectivePolicyService(AppDbContext db, IGraphService graphService)
    {
        _db = db;
        _graphService = graphService;
    }

    /// <summary>
    /// Get the effective policy for a device by resolving group memberships and merging policies by priority.
    /// </summary>
    public async Task<EffectivePolicyResult> GetEffectivePolicyAsync(string deviceId)
    {
        // 1. Resolve device group memberships from Microsoft Graph (server-side, trusted)
        var groupIds = await _graphService.GetDeviceGroupMembershipsAsync(deviceId);

        // 2. Find all active assignments targeting those groups
        var assignments = await _db.PolicyAssignments
            .Include(a => a.PolicySetVersion)
            .Where(a => a.Enabled && groupIds.Contains(a.EntraGroupId))
            .Where(a => a.PolicySetVersion.Status == PolicyVersionStatus.Active)
            .OrderBy(a => a.Priority)
            .ToListAsync();

        if (!assignments.Any())
        {
            return new EffectivePolicyResult
            {
                DeviceId = deviceId,
                MandatoryPolicies = new Dictionary<string, object>(),
                RecommendedPolicies = new Dictionary<string, object>(),
                Hash = ComputeHash("{}{}"),
                AppliedAssignments = new List<AppliedAssignmentInfo>()
            };
        }

        // 3. Merge policies by priority (lower number wins per key)
        var mandatoryPolicies = new Dictionary<string, object>();
        var recommendedPolicies = new Dictionary<string, object>();
        var appliedAssignments = new List<AppliedAssignmentInfo>();

        foreach (var assignment in assignments)
        {
            var settings = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(assignment.PolicySetVersion.SettingsJson)
                ?? new Dictionary<string, JsonElement>();

            var targetDict = assignment.Scope == PolicyScope.Mandatory ? mandatoryPolicies : recommendedPolicies;

            bool hadNewKeys = false;
            foreach (var kvp in settings)
            {
                // First writer wins (lowest priority number)
                if (!targetDict.ContainsKey(kvp.Key))
                {
                    targetDict[kvp.Key] = ConvertJsonElement(kvp.Value);
                    hadNewKeys = true;
                }
            }

            if (hadNewKeys || !settings.Any())
            {
                appliedAssignments.Add(new AppliedAssignmentInfo
                {
                    AssignmentId = assignment.Id,
                    PolicySetName = assignment.PolicySetVersion.PolicySet?.Name ?? "Unknown",
                    Version = assignment.PolicySetVersion.Version,
                    Priority = assignment.Priority,
                    Scope = assignment.Scope,
                    GroupName = assignment.GroupName
                });
            }
        }

        var hashInput = JsonSerializer.Serialize(mandatoryPolicies) + JsonSerializer.Serialize(recommendedPolicies);

        return new EffectivePolicyResult
        {
            DeviceId = deviceId,
            MandatoryPolicies = mandatoryPolicies,
            RecommendedPolicies = recommendedPolicies,
            Hash = ComputeHash(hashInput),
            AppliedAssignments = appliedAssignments
        };
    }

    private static object ConvertJsonElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString()!,
            JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Array => element.EnumerateArray().Select(ConvertJsonElement).ToList(),
            JsonValueKind.Object => element.EnumerateObject().ToDictionary(p => p.Name, p => ConvertJsonElement(p.Value)),
            _ => element.GetRawText()
        };
    }

    private static string ComputeHash(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexStringLower(bytes);
    }
}

public class EffectivePolicyResult
{
    public string DeviceId { get; set; } = string.Empty;
    public Dictionary<string, object> MandatoryPolicies { get; set; } = new();
    public Dictionary<string, object> RecommendedPolicies { get; set; } = new();
    public string Hash { get; set; } = string.Empty;
    public List<AppliedAssignmentInfo> AppliedAssignments { get; set; } = new();
}

public class AppliedAssignmentInfo
{
    public Guid AssignmentId { get; set; }
    public string PolicySetName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public int Priority { get; set; }
    public PolicyScope Scope { get; set; }
    public string GroupName { get; set; } = string.Empty;
}
