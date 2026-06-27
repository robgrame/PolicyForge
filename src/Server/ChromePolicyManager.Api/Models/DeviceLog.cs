namespace ChromePolicyManager.Api.Models;

public class DeviceLog
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string DeviceId { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public string ScriptType { get; set; } = string.Empty; // "Detection" or "Remediation"
    public string Level { get; set; } = "INFO"; // INFO, WARN, ERROR
    public string Message { get; set; } = string.Empty;
    public DateTime ClientTimestamp { get; set; }
    public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
}
