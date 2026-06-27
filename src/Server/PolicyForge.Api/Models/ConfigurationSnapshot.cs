namespace PolicyForge.Api.Models;

/// <summary>
/// A rollback snapshot uploaded by a device after an Enforce run. It stores the set of inverse
/// instructions that restore the device's prior state, so the portal can audit what changed and,
/// if needed, surface an undo. Stored as the raw instruction JSON the client captured.
/// </summary>
public class ConfigurationSnapshot
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Entra device registration id the snapshot belongs to.</summary>
    public string DeviceId { get; set; } = string.Empty;

    /// <summary>Hash of the forward (applied) configuration this snapshot can roll back.</summary>
    public string ForwardHash { get; set; } = string.Empty;

    /// <summary>When the client captured the snapshot (device clock, ISO-8601).</summary>
    public DateTime CapturedAt { get; set; }

    /// <summary>Number of inverse instructions captured.</summary>
    public int ItemCount { get; set; }

    /// <summary>JSON array of inverse <c>ResolvedInstruction</c>s that restore the prior state.</summary>
    public string InstructionsJson { get; set; } = "[]";

    public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
}
