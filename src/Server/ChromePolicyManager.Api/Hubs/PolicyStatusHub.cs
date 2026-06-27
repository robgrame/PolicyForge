using Microsoft.AspNetCore.SignalR;

namespace ChromePolicyManager.Api.Hubs;

/// <summary>
/// SignalR hub that pushes device policy-application status to the portal in real time.
/// Fed by the Event Grid webhook subscriber (EventGridEndpoints).
/// </summary>
public sealed class PolicyStatusHub : Hub
{
    public const string Path = "/hubs/policy-status";
    public const string EventName = "DevicePolicyStatusChanged";
}
