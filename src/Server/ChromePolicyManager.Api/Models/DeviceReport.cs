namespace ChromePolicyManager.Api.Models;

public class DeviceReport
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string DeviceId { get; set; } = string.Empty; // Entra device ID
    public string DeviceName { get; set; } = string.Empty;
    public string? UserPrincipalName { get; set; }
    public string AppliedPolicyHash { get; set; } = string.Empty;
    public string? AppliedVersion { get; set; }
    public DeviceComplianceStatus Status { get; set; }
    public string? Errors { get; set; } // JSON array of error messages
    public string? ChromeVersion { get; set; }
    public string? OsVersion { get; set; }
    public string? OsBuild { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? ScriptVersion { get; set; }
    public int? PolicyKeysWritten { get; set; }
    public int? PolicyKeysRemoved { get; set; }
    public DateTime ReportedAt { get; set; } = DateTime.UtcNow;
}

public enum DeviceComplianceStatus
{
    Compliant,
    NonCompliant,
    Error,
    Pending,
    PartiallyApplied,
    Unknown
}

public class DeviceState
{
    public string DeviceId { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public string? UserPrincipalName { get; set; }
    public string? LastAppliedPolicyHash { get; set; }
    public string? LastAppliedVersion { get; set; }
    public DeviceComplianceStatus LastStatus { get; set; }
    public DateTime? LastCheckIn { get; set; }
    public string? LastError { get; set; }
    public string? ChromeVersion { get; set; }
    public string? OsVersion { get; set; }
    public string? OsBuild { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? ScriptVersion { get; set; }
    public bool IsOffline => LastCheckIn.HasValue && DateTime.UtcNow - LastCheckIn.Value > TimeSpan.FromHours(24);
}
