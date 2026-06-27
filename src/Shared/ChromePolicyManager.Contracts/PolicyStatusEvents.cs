namespace ChromePolicyManager.Contracts;

/// <summary>
/// Event-type names published to the Event Grid custom topic that feeds the portal with
/// policy-application status. See docs/adr-001 (Event Grid status pipeline).
/// </summary>
public static class PolicyEventTypes
{
    public const string DevicePolicyStatusChanged = "ChromePolicyManager.DevicePolicyStatusChanged";

    /// <summary>Data version stamped on every event (allows schema evolution).</summary>
    public const string DataVersion = "1.0";
}

/// <summary>
/// Payload of a <see cref="PolicyEventTypes.DevicePolicyStatusChanged"/> Event Grid event:
/// emitted whenever a device reports the outcome of applying its assigned Chrome policies.
/// The API webhook subscriber rebroadcasts this to the portal over SignalR.
/// </summary>
public sealed record DevicePolicyStatusChangedData
{
    public required string DeviceId { get; init; }
    public required string DeviceName { get; init; }
    public string? UserPrincipalName { get; init; }

    /// <summary>Compliance status as string (e.g. Compliant, Error, PartiallyApplied).</summary>
    public required string Status { get; init; }

    public string? AppliedVersion { get; init; }
    public string? ScriptVersion { get; init; }
    public int? PolicyKeysWritten { get; init; }
    public int? PolicyKeysRemoved { get; init; }

    /// <summary>JSON array of error messages, when Status indicates a failure.</summary>
    public string? Errors { get; init; }

    public DateTimeOffset ReportedUtc { get; init; } = DateTimeOffset.UtcNow;
}
