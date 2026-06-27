using Azure.Messaging.EventGrid;
using Azure.Messaging.EventGrid.SystemEvents;
using ChromePolicyManager.Api.Hubs;
using ChromePolicyManager.Contracts;
using Microsoft.AspNetCore.SignalR;

namespace ChromePolicyManager.Api.Endpoints;

/// <summary>
/// Event Grid webhook subscriber. Event Grid delivers policy-status events here; the handler
/// performs the subscription-validation handshake and rebroadcasts data events to the portal
/// over SignalR (PolicyStatusHub). This is the bridge Event Grid -> browser, since Event Grid
/// cannot push to web clients directly.
/// </summary>
public static class EventGridEndpoints
{
    public static void MapEventGridEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/eventgrid").WithTags("EventGrid");

        group.MapPost("/policy-status", async (
            HttpRequest request,
            IHubContext<PolicyStatusHub> hub,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("EventGridWebhook");
            var payload = await BinaryData.FromStreamAsync(request.Body, ct);

            EventGridEvent[] events;
            try
            {
                events = EventGridEvent.ParseMany(payload);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to parse Event Grid payload");
                return Results.BadRequest();
            }

            foreach (var e in events)
            {
                // Subscription validation handshake (sent when the event subscription is created).
                if (e.TryGetSystemEventData(out var systemData)
                    && systemData is SubscriptionValidationEventData validation)
                {
                    logger.LogInformation("Event Grid subscription validation handshake received");
                    return Results.Ok(new SubscriptionValidationResponse
                    {
                        ValidationResponse = validation.ValidationCode
                    });
                }

                if (e.EventType == PolicyEventTypes.DevicePolicyStatusChanged)
                {
                    var data = e.Data.ToObjectFromJson<DevicePolicyStatusChangedData>();
                    if (data is not null)
                    {
                        await hub.Clients.All.SendAsync(PolicyStatusHub.EventName, data, ct);
                        logger.LogDebug("Broadcast policy status for {DeviceId} ({Status})", data.DeviceId, data.Status);
                    }
                }
            }

            return Results.Ok();
        }).WithName("EventGridPolicyStatusWebhook").AllowAnonymous();
    }
}
