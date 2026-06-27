using Azure.Identity;
using Azure.Messaging.ServiceBus;
using ChromePolicyManager.Contracts;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Singleton holder for the Service Bus sender that publishes privileged commands to the
/// <c>cpm-commands</c> queue. Mirrors <see cref="DeviceReportQueue"/>: Managed Identity first,
/// connection string fallback, disabled (no-op) if neither is configured.
/// </summary>
public sealed class CommandQueueClient : IAsyncDisposable
{
    private readonly ServiceBusClient? _client;
    private readonly ServiceBusSender? _sender;
    private readonly ILogger<CommandQueueClient> _logger;

    public bool Enabled { get; }

    public CommandQueueClient(IConfiguration configuration, ILogger<CommandQueueClient> logger)
    {
        _logger = logger;
        var fullyQualifiedNamespace = configuration["ServiceBus:FullyQualifiedNamespace"];
        var connectionString = configuration["ServiceBus:ConnectionString"];
        var queueName = configuration["ServiceBus:CommandQueue"] ?? QueueNames.Commands;

        if (!string.IsNullOrEmpty(fullyQualifiedNamespace))
        {
            _client = new ServiceBusClient(fullyQualifiedNamespace, new DefaultAzureCredential());
            _sender = _client.CreateSender(queueName);
            Enabled = true;
            _logger.LogInformation("Command queue '{Queue}' initialized with Managed Identity ({Namespace})", queueName, fullyQualifiedNamespace);
        }
        else if (!string.IsNullOrEmpty(connectionString))
        {
            _client = new ServiceBusClient(connectionString);
            _sender = _client.CreateSender(queueName);
            Enabled = true;
            _logger.LogInformation("Command queue '{Queue}' initialized with connection string", queueName);
        }
        else
        {
            Enabled = false;
            _logger.LogWarning("Service Bus not configured - privileged commands cannot be queued");
        }
    }

    public async Task SendAsync(PrivilegedCommandEnvelope envelope, CancellationToken ct = default)
    {
        if (!Enabled || _sender is null)
            throw new InvalidOperationException("Command queue is not configured.");

        var message = new ServiceBusMessage(envelope.Serialize())
        {
            ContentType = MessageProperties.ContentTypeJson,
            Subject = envelope.Type.ToString(),
            MessageId = envelope.CommandId.ToString(),
            ApplicationProperties =
            {
                [MessageProperties.CommandType] = envelope.Type.ToString(),
                [MessageProperties.CommandId] = envelope.CommandId.ToString(),
                [MessageProperties.Actor] = envelope.Actor ?? string.Empty
            }
        };
        await _sender.SendMessageAsync(message, ct);
    }

    public async ValueTask DisposeAsync()
    {
        if (_sender is not null) await _sender.DisposeAsync();
        if (_client is not null) await _client.DisposeAsync();
    }
}
