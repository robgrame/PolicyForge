namespace PolicyForge.Api.Models;

/// <summary>
/// Represents a single policy definition parsed from ADMX/ADML templates.
/// This is the "catalog" of all available policies (any product) that admins can pick from.
/// </summary>
public class PolicyCatalogEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>ADMX target prefix / namespace (e.g. "chrome", "microsoft_edge", "windows").
    /// Used to disambiguate identically-named policies across different products.</summary>
    public string Namespace { get; set; } = string.Empty;

    /// <summary>Friendly product name this policy belongs to (e.g. "Google Chrome", "Microsoft Edge").</summary>
    public string ProductName { get; set; } = string.Empty;

    /// <summary>Policy name as defined in ADMX (e.g. "SafeBrowsingProtectionLevel")</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Human-readable display name from ADML</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>Full explanation text from ADML</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Category hierarchy (e.g. "SafeBrowsing", "ContentSettings")</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>Data type: Boolean, Integer, String, List, Enum</summary>
    public string DataType { get; set; } = string.Empty;

    /// <summary>Registry key path (e.g. "Software\Policies\Google\Chrome")</summary>
    public string RegistryKey { get; set; } = string.Empty;

    /// <summary>Registry value name</summary>
    public string RegistryValueName { get; set; } = string.Empty;

    /// <summary>Whether it's a "Recommended" policy variant</summary>
    public bool IsRecommended { get; set; }

    /// <summary>Supported platform/version info</summary>
    public string SupportedOn { get; set; } = string.Empty;

    /// <summary>For Enum types: JSON array of {value, displayName} options</summary>
    public string? EnumOptions { get; set; }

    /// <summary>Policy class: Machine, User, or Both</summary>
    public string PolicyClass { get; set; } = "Both";

    /// <summary>Chrome ADMX template version this was imported from</summary>
    public string TemplateVersion { get; set; } = string.Empty;

    public DateTime ImportedAt { get; set; } = DateTime.UtcNow;
}
