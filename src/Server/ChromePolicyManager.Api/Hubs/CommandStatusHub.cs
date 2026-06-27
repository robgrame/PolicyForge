using Microsoft.AspNetCore.SignalR;

namespace ChromePolicyManager.Api.Hubs;

/// <summary>
/// SignalR hub used to push privileged-command status updates to the Admin portal in real time.
/// The portal subscribes to the "CommandStatusUpdated" event.
/// </summary>
public sealed class CommandStatusHub : Hub
{
    public const string Path = "/hubs/command-status";
    public const string EventName = "CommandStatusUpdated";
}
