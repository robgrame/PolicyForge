using System.Text.Json;
using System.Text.Json.Serialization;

namespace ChromePolicyManager.Contracts;

/// <summary>
/// Types of privileged commands handled by the Worker. Each maps to a strongly-typed payload.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PrivilegedCommandType
{
    /// <summary>Dispatch proactive remediation to every device of an assignment's Entra group.</summary>
    PushRemediationDispatch = 0,

    /// <summary>Dispatch proactive remediation to a single Entra device.</summary>
    PushRemediationDevice = 1,

    /// <summary>Reconcile Graph change-notification subscriptions for the active Entra groups.</summary>
    WebhookSubscriptionSync = 2,
}

/// <summary>
/// Envelope that carries a privileged command from the API to the Worker over Service Bus.
/// The concrete payload is serialized in <see cref="PayloadJson"/> and deserialized by the
/// handler using <see cref="Type"/>. The API enriches the payload with everything the Worker
/// needs so the Worker never has to read SQL.
/// </summary>
public sealed record PrivilegedCommandEnvelope
{
    public required Guid CommandId { get; init; }
    public required PrivilegedCommandType Type { get; init; }
    public DateTimeOffset CreatedUtc { get; init; } = DateTimeOffset.UtcNow;
    public string? Actor { get; init; }
    public string? Reason { get; init; }
    public required string PayloadJson { get; init; }

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    public string Serialize() => JsonSerializer.Serialize(this, Options);

    public static PrivilegedCommandEnvelope? Deserialize(string json) =>
        JsonSerializer.Deserialize<PrivilegedCommandEnvelope>(json, Options);

    public static PrivilegedCommandEnvelope Create<TPayload>(
        PrivilegedCommandType type, TPayload payload, string? actor = null, string? reason = null) =>
        new()
        {
            CommandId = Guid.NewGuid(),
            Type = type,
            Actor = actor,
            Reason = reason,
            PayloadJson = JsonSerializer.Serialize(payload, Options)
        };

    public TPayload? GetPayload<TPayload>() =>
        JsonSerializer.Deserialize<TPayload>(PayloadJson, Options);
}

/// <summary>Payload for <see cref="PrivilegedCommandType.PushRemediationDispatch"/>.</summary>
public sealed record PushRemediationDispatchPayload
{
    public required Guid AssignmentId { get; init; }
    public required string EntraGroupId { get; init; }
    public string? GroupName { get; init; }
}

/// <summary>Payload for <see cref="PrivilegedCommandType.PushRemediationDevice"/>.</summary>
public sealed record PushRemediationDevicePayload
{
    public required string EntraDeviceId { get; init; }
}

/// <summary>Payload for <see cref="PrivilegedCommandType.WebhookSubscriptionSync"/>.</summary>
public sealed record WebhookSubscriptionSyncPayload
{
    /// <summary>Entra group IDs that currently have at least one active assignment.</summary>
    public required IReadOnlyList<string> ActiveGroupIds { get; init; }
}
