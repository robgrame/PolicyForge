namespace ChromePolicyManager.Api.Models;

public class PolicySet
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<PolicySetVersion> Versions { get; set; } = new List<PolicySetVersion>();
}

public class PolicySetVersion
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid PolicySetId { get; set; }
    public string Version { get; set; } = "1.0.0"; // Semantic version
    public string SettingsJson { get; set; } = "{}"; // Chrome policy key-value pairs
    public string Hash { get; set; } = string.Empty; // SHA256 of SettingsJson

    /// <summary>
    /// Chrome ADMX template version (e.g. "120.0.6099.x") that was loaded in the catalog when
    /// this policy version was authored. Captured so that, after importing a newer ADMX, we can
    /// still tell which Chrome version a given policy version was based on.
    /// </summary>
    public string? AdmxVersion { get; set; }

    public PolicyVersionStatus Status { get; set; } = PolicyVersionStatus.Draft;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }

    public PolicySet PolicySet { get; set; } = null!;
    public ICollection<PolicyAssignment> Assignments { get; set; } = new List<PolicyAssignment>();
}

public enum PolicyVersionStatus
{
    Draft,
    Active,
    Archived
}
