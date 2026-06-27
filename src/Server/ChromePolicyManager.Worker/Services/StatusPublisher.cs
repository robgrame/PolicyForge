using Azure.Identity;
using Azure.Messaging.ServiceBus;
using ChromePolicyManager.Contracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace ChromePolicyManager.Worker.Services;

/// <summary>
/// Publishes <see cref="CommandStatusUpdate"/> messages back to the API on the
/// <c>cpm-command-status</c> queue. The API's status relay persists them and pushes
/// them to the portal over SignalR. The Worker therefore never touches SQL.
/// </summary>
public sealed class StatusPublisher : IAsyncDisposable
{
    private readonly ServiceBusClient? _client;
    private readonly ServiceBusSender? _sender;
    private readonly ILogger<StatusPublisher> _logger;

    public StatusPublisher(IConfiguration configuration, ILogger<StatusPublisher> logger)
    {
        _logger = logger;
        var fqns = configuration["ServiceBus:fullyQualifiedNamespace"]
                   ?? configuration["ServiceBus__fullyQualifiedNamespace"];
        var connectionString = configuration["ServiceBus:ConnectionString"];
        var queue = configuration["ServiceBus:CommandStatusQueue"] ?? QueueNames.CommandStatus;

        if (!string.IsNullOrEmpty(fqns))
        {
            _client = new ServiceBusClient(fqns, new DefaultAzureCredential());
            _sender = _client.CreateSender(queue);
        }
        else if (!string.IsNullOrEmpty(connectionString))
        {
            _client = new ServiceBusClient(connectionString);
            _sender = _client.CreateSender(queue);
        }
        else
        {
            _logger.LogWarning("Service Bus not configured - status updates will not be published");
        }
    }

    public async Task PublishAsync(CommandStatusUpdate update, CancellationToken ct = default)
    {
        if (_sender is null)
        {
            _logger.LogWarning("StatusPublisher disabled - dropping status for {CommandId}", update.CommandId);
            return;
        }

        var message = new ServiceBusMessage(update.Serialize())
        {
            ContentType = MessageProperties.ContentTypeJson,
            Subject = update.Status.ToString(),
            MessageId = $"{update.CommandId}:{update.Status}:{Guid.NewGuid():N}"
        };
        await _sender.SendMessageAsync(message, ct);
    }

    public async ValueTask DisposeAsync()
    {
        if (_sender is not null) await _sender.DisposeAsync();
        if (_client is not null) await _client.DisposeAsync();
    }
}
