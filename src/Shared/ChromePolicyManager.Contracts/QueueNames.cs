namespace ChromePolicyManager.Contracts;

/// <summary>
/// Names of the Service Bus queues used by the decoupled privileged-action pipeline.
/// See docs/adr-001-decoupling-azioni-privilegiate.md.
/// </summary>
public static class QueueNames
{
    /// <summary>Commands enqueued by the API and consumed by the privileged Worker.</summary>
    public const string Commands = "cpm-commands";

    /// <summary>Status updates emitted by the Worker and consumed by the API status relay.</summary>
    public const string CommandStatus = "cpm-command-status";

    /// <summary>Existing device-report queue (migrated to the Worker in a later phase).</summary>
    public const string DeviceReports = "device-reports";
}

/// <summary>
/// Application-property and content-type constants shared by sender/receiver.
/// </summary>
public static class MessageProperties
{
    public const string CommandType = "CommandType";
    public const string CommandId = "CommandId";
    public const string Actor = "Actor";
    public const string ContentTypeJson = "application/json";
}
