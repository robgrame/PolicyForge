using Azure;
using Azure.Identity;
using Azure.Messaging.EventGrid;
using ChromePolicyManager.Contracts;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Publishes domain events to an Event Grid custom topic. Used to fan out policy-application
/// status to the portal (via the API webhook subscriber + SignalR) and to any future subscribers.
/// </summary>
public interface IEventPublisher
{
    bool Enabled { get; }
    Task PublishDevicePolicyStatusAsync(DevicePolicyStatusChangedData data, CancellationToken ct = default);
}

/// <summary>
/// Event Grid implementation using Managed Identity (no SAS keys — topic has disableLocalAuth=true).
/// No-op when <c>EventGrid:TopicEndpoint</c> is not configured, so behavior is unchanged in
/// environments without Event Grid.
/// </summary>
public sealed class EventGridEventPublisher : IEventPublisher
{
    private readonly EventGridPublisherClient? _client;
    private readonly ILogger<EventGridEventPublisher> _logger;

    public bool Enabled => _client is not null;

    public EventGridEventPublisher(IConfiguration configuration, ILogger<EventGridEventPublisher> logger)
    {
        _logger = logger;
        var endpoint = configuration["EventGrid:TopicEndpoint"];
        if (!string.IsNullOrWhiteSpace(endpoint))
        {
            _client = new EventGridPublisherClient(new Uri(endpoint), new DefaultAzureCredential());
            _logger.LogInformation("Event Grid publisher initialized ({Endpoint})", endpoint);
        }
        else
        {
            _logger.LogWarning("Event Grid not configured - policy status events will not be published");
        }
    }

    public async Task PublishDevicePolicyStatusAsync(DevicePolicyStatusChangedData data, CancellationToken ct = default)
    {
        if (_client is null) return;

        try
        {
            var evt = new EventGridEvent(
                subject: $"devices/{data.DeviceId}",
                eventType: PolicyEventTypes.DevicePolicyStatusChanged,
                dataVersion: PolicyEventTypes.DataVersion,
                data: BinaryData.FromObjectAsJson(data));
            await _client.SendEventAsync(evt, ct);
        }
        catch (Exception ex)
        {
            // Status fan-out is best-effort: never fail report processing because of it.
            _logger.LogError(ex, "Failed to publish DevicePolicyStatusChanged for {DeviceId}", data.DeviceId);
        }
    }
}
