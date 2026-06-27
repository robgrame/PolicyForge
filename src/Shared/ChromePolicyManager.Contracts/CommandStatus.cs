using System.Text.Json;
using System.Text.Json.Serialization;

namespace ChromePolicyManager.Contracts;

/// <summary>
/// Lifecycle status of a privileged command, mirrored in the API's PrivilegedCommands table.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CommandStatus
{
    Pending = 0,
    Dispatched = 1,
    InProgress = 2,
    Succeeded = 3,
    Failed = 4,
    DeadLettered = 5,
    Skipped = 6,
}

/// <summary>
/// Status update emitted by the Worker on the <c>cpm-command-status</c> queue and consumed by
/// the API's status relay, which persists it and broadcasts it to the portal over SignalR.
/// </summary>
public sealed record CommandStatusUpdate
{
    public required Guid CommandId { get; init; }
    public required CommandStatus Status { get; init; }
    public string? Message { get; init; }
    public string? ResultJson { get; init; }
    public string? Error { get; init; }
    public DateTimeOffset UpdatedUtc { get; init; } = DateTimeOffset.UtcNow;

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    public string Serialize() => JsonSerializer.Serialize(this, Options);

    public static CommandStatusUpdate? Deserialize(string json) =>
        JsonSerializer.Deserialize<CommandStatusUpdate>(json, Options);
}
