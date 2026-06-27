using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

public class PolicyService
{
    private readonly AppDbContext _db;
    private readonly AuditService _audit;
    private readonly PushRemediationService _pushRemediation;

    public PolicyService(AppDbContext db, AuditService audit, PushRemediationService pushRemediation)
    {
        _db = db;
        _audit = audit;
        _pushRemediation = pushRemediation;
    }

    public async Task<PolicySet> CreatePolicySetAsync(string name, string description, string? actor = null)
    {
        var policySet = new PolicySet { Name = name, Description = description };
        _db.PolicySets.Add(policySet);
        await _db.SaveChangesAsync();
        await _audit.LogAsync("PolicySet.Created", actor, "PolicySet", policySet.Id.ToString(), $"Name: {name}");
        return policySet;
    }

    public async Task<List<PolicySet>> GetAllPolicySetsAsync()
    {
        return await _db.PolicySets
            .Include(p => p.Versions)
            .OrderBy(p => p.Name)
            .ToListAsync();
    }

    public async Task<PolicySet?> GetPolicySetAsync(Guid id)
    {
        return await _db.PolicySets
            .Include(p => p.Versions.OrderByDescending(v => v.CreatedAt))
            .FirstOrDefaultAsync(p => p.Id == id);
    }

    public async Task<PolicySetVersion> CreateVersionAsync(Guid policySetId, string version, string settingsJson, string? actor = null)
    {
        var hash = ComputeHash(settingsJson);
        var policyVersion = new PolicySetVersion
        {
            PolicySetId = policySetId,
            Version = version,
            SettingsJson = settingsJson,
            Hash = hash,
            AdmxVersion = await GetCatalogTemplateVersionAsync(),
            Status = PolicyVersionStatus.Draft,
            CreatedBy = actor
        };
        _db.PolicySetVersions.Add(policyVersion);
        await _db.SaveChangesAsync();
        await _audit.LogAsync("PolicyVersion.Created", actor, "PolicySetVersion", policyVersion.Id.ToString(),
            $"Version: {version}, AdmxVersion: {policyVersion.AdmxVersion ?? "none"}, Hash: {hash}");
        return policyVersion;
    }

    /// <summary>
    /// Returns the Chrome ADMX template version currently loaded in the catalog, used to stamp
    /// new policy versions so we can trace which Chrome version they were authored against.
    /// </summary>
    private async Task<string?> GetCatalogTemplateVersionAsync()
    {
        var version = await _db.PolicyCatalog
            .Select(e => e.TemplateVersion)
            .FirstOrDefaultAsync();
        return string.IsNullOrWhiteSpace(version) ? null : version;
    }

    public async Task<PolicySetVersion?> PromoteVersionAsync(Guid versionId, string? actor = null)
    {
        var version = await _db.PolicySetVersions.FindAsync(versionId);
        if (version == null) return null;

        // Archive any currently active version for this policy set
        var currentActive = await _db.PolicySetVersions
            .Where(v => v.PolicySetId == version.PolicySetId && v.Status == PolicyVersionStatus.Active)
            .ToListAsync();

        foreach (var active in currentActive)
        {
            active.Status = PolicyVersionStatus.Archived;
        }

        version.Status = PolicyVersionStatus.Active;
        await _db.SaveChangesAsync();
        await _audit.LogAsync("PolicyVersion.Promoted", actor, "PolicySetVersion", versionId.ToString(),
            $"Version {version.Version} promoted to Active");

        await TriggerPushRemediationForVersionAsync(version.Id, $"Version {version.Version} promoted", actor);
        return version;
    }

    public async Task<PolicySetVersion?> RollbackVersionAsync(Guid policySetId, Guid targetVersionId, string? actor = null)
    {
        var target = await _db.PolicySetVersions.FindAsync(targetVersionId);
        if (target == null || target.PolicySetId != policySetId) return null;

        // Archive current active
        var currentActive = await _db.PolicySetVersions
            .Where(v => v.PolicySetId == policySetId && v.Status == PolicyVersionStatus.Active)
            .ToListAsync();
        foreach (var active in currentActive) active.Status = PolicyVersionStatus.Archived;

        target.Status = PolicyVersionStatus.Active;
        await _db.SaveChangesAsync();
        await _audit.LogAsync("PolicyVersion.Rollback", actor, "PolicySetVersion", targetVersionId.ToString(),
            $"Rolled back to version {target.Version}");

        await TriggerPushRemediationForVersionAsync(target.Id, $"Rolled back to version {target.Version}", actor);
        return target;
    }

    public async Task<object?> AddSettingToDraftAsync(Guid policySetId, string policyName, object value, string? actor = null)
    {
        var policySet = await _db.PolicySets
            .Include(p => p.Versions)
            .FirstOrDefaultAsync(p => p.Id == policySetId);
        if (policySet == null) return null;

        // Find existing draft or create one
        var draft = policySet.Versions
            .Where(v => v.Status == PolicyVersionStatus.Draft)
            .OrderByDescending(v => v.CreatedAt)
            .FirstOrDefault();

        Dictionary<string, JsonElement> settings;

        if (draft != null)
        {
            // Parse existing settings and add/update
            settings = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(draft.SettingsJson)
                ?? new Dictionary<string, JsonElement>();
        }
        else
        {
            settings = new Dictionary<string, JsonElement>();
            // Determine next version number
            var latest = policySet.Versions.OrderByDescending(v => v.CreatedAt).FirstOrDefault();
            var nextVersion = "1.0.0";
            if (latest != null)
            {
                var parts = latest.Version.Split('.');
                if (parts.Length == 3 && int.TryParse(parts[2], out var patch))
                    nextVersion = $"{parts[0]}.{parts[1]}.{patch + 1}";
            }

            draft = new PolicySetVersion
            {
                PolicySetId = policySetId,
                Version = nextVersion,
                SettingsJson = "{}",
                Hash = "",
                AdmxVersion = await GetCatalogTemplateVersionAsync(),
                Status = PolicyVersionStatus.Draft
            };
            _db.PolicySetVersions.Add(draft);
        }

        // Add/update the policy value
        var jsonValue = JsonSerializer.SerializeToElement(value);
        settings[policyName] = jsonValue;

        draft.SettingsJson = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
        draft.Hash = ComputeHash(draft.SettingsJson);
        await _db.SaveChangesAsync();

        await _audit.LogAsync("PolicySetting.Added", actor, "PolicySet", policySetId.ToString(),
            $"Added {policyName} to draft {draft.Version}");

        return new { draft.Id, draft.Version, PolicyName = policyName, Value = value, TotalSettings = settings.Count };
    }

    public async Task<object> GetDraftSettingsAsync(Guid policySetId)
    {
        var draft = await _db.PolicySetVersions
            .Where(v => v.PolicySetId == policySetId && v.Status == PolicyVersionStatus.Draft)
            .OrderByDescending(v => v.CreatedAt)
            .FirstOrDefaultAsync();

        if (draft == null)
            return new { HasDraft = false, Version = (string?)null, Settings = "{}", Count = 0 };

        var settings = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(draft.SettingsJson)
            ?? new Dictionary<string, JsonElement>();

        return new { HasDraft = true, Version = draft.Version, Settings = draft.SettingsJson, Count = settings.Count };
    }

    public async Task<bool> DeletePolicySetAsync(Guid policySetId, bool force = false, string? actor = null)
    {
        var policySet = await _db.PolicySets
            .Include(p => p.Versions)
            .FirstOrDefaultAsync(p => p.Id == policySetId);
        if (policySet == null) return false;

        // Check if any version has active assignments
        var versionIds = policySet.Versions.Select(v => v.Id).ToList();
        var orphanedAssignments = await _db.PolicyAssignments
            .Where(a => versionIds.Contains(a.PolicySetVersionId))
            .ToListAsync();

        if (orphanedAssignments.Count > 0)
        {
            if (!force)
                throw new InvalidOperationException(
                    $"Cannot delete: {orphanedAssignments.Count} assignment(s) reference this policy set. Use force delete to remove them.");

            _db.PolicyAssignments.RemoveRange(orphanedAssignments);
            await _audit.LogAsync("PolicySet.ForceDeleteAssignments", actor, "PolicySet", policySetId.ToString(),
                $"Cascade-removed {orphanedAssignments.Count} assignment(s)");
        }

        _db.PolicySetVersions.RemoveRange(policySet.Versions);
        _db.PolicySets.Remove(policySet);
        await _db.SaveChangesAsync();
        await _audit.LogAsync("PolicySet.Deleted", actor, "PolicySet", policySetId.ToString(), $"Name: {policySet.Name}");
        return true;
    }

    private static string ComputeHash(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexStringLower(bytes);
    }

    private async Task TriggerPushRemediationForVersionAsync(Guid policySetVersionId, string reason, string? actor)
    {
        var assignments = await _db.PolicyAssignments
            .Where(a => a.PolicySetVersionId == policySetVersionId && a.Enabled && a.PushRemediationEnabled)
            .ToListAsync();

        foreach (var assignment in assignments)
        {
            await _pushRemediation.DispatchToAssignmentAsync(assignment, reason, actor);
        }
    }
}
