namespace PolicyForge.Api.Models;

/// <summary>
/// Generic, provider-agnostic configuration aggregate — the evolution of <see cref="PolicySet"/>.
/// A profile is a named, versioned collection of configuration items spanning any provider
/// (ADMX policy, registry value, Windows service, scheduled task, file, local group, env var...).
/// </summary>
public class ConfigurationProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    /// <summary>Optional target OS filter (e.g. "Windows11", "Windows10"); null = any.</summary>
    public string? TargetOs { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<ConfigurationProfileVersion> Versions { get; set; } = new List<ConfigurationProfileVersion>();
}

/// <summary>
/// An immutable-once-published version of a <see cref="ConfigurationProfile"/>. The items are
/// stored as a JSON array of <c>PolicyForge.Contracts.Configuration.ConfigurationItem</c>.
/// </summary>
public class ConfigurationProfileVersion
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProfileId { get; set; }
    public string Version { get; set; } = "1.0.0";

    /// <summary>JSON array of authored configuration items (provider + typed payload).</summary>
    public string ItemsJson { get; set; } = "[]";

    /// <summary>SHA-256 of <see cref="ItemsJson"/>.</summary>
    public string Hash { get; set; } = string.Empty;

    /// <summary>ADMX/product version captured when authoring (applies to AdmxPolicy items).</summary>
    public string? AdmxVersion { get; set; }

    public PolicyVersionStatus Status { get; set; } = PolicyVersionStatus.Draft;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }

    public ConfigurationProfile Profile { get; set; } = null!;
}
