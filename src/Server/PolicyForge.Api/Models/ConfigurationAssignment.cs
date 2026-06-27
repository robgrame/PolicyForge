namespace PolicyForge.Api.Models;

/// <summary>
/// Targets a published <see cref="ConfigurationProfileVersion"/> at an Entra group. The generic
/// equivalent of <see cref="PolicyAssignment"/>: it drives device-side resolution by mapping group
/// memberships to the profile versions a device must converge to. Lower <see cref="Priority"/> wins
/// when two assignments resolve conflicting instructions.
/// </summary>
public class ConfigurationAssignment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ProfileVersionId { get; set; }
    public string EntraGroupId { get; set; } = string.Empty;
    public string GroupName { get; set; } = string.Empty;

    /// <summary>Lower number = higher priority (first writer wins per resolved instruction key).</summary>
    public int Priority { get; set; } = 100;

    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }

    public ConfigurationProfileVersion ProfileVersion { get; set; } = null!;
}
