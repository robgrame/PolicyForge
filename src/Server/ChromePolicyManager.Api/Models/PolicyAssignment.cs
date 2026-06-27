namespace ChromePolicyManager.Api.Models;

public class PolicyAssignment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid PolicySetVersionId { get; set; }
    public string EntraGroupId { get; set; } = string.Empty;
    public string GroupName { get; set; } = string.Empty;
    public int Priority { get; set; } = 100; // Lower number = higher priority
    public PolicyScope Scope { get; set; } = PolicyScope.Mandatory;
    public bool Enabled { get; set; } = true;
    public bool PushRemediationEnabled { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }

    public PolicySetVersion PolicySetVersion { get; set; } = null!;
}

public enum PolicyScope
{
    Mandatory,   // HKLM\SOFTWARE\Policies\Google\Chrome
    Recommended  // HKLM\SOFTWARE\Policies\Google\Chrome\Recommended
}
