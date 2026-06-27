using System.Text.Json;
using Azure.Identity;
using Azure.Messaging.ServiceBus;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Sends device reports to Azure Service Bus for async processing.
/// The APIM Device API receives the report, enqueues it, and returns 202 immediately.
/// A background processor (DeviceReportProcessor) picks up messages and processes them.
/// Supports both Managed Identity (FullyQualifiedNamespace) and connection string auth.
/// </summary>
public class DeviceReportQueue
{
    private readonly ServiceBusSender _sender;
    private readonly ILogger<DeviceReportQueue> _logger;
    private readonly bool _enabled;

    public DeviceReportQueue(IConfiguration configuration, ILogger<DeviceReportQueue> logger)
    {
        _logger = logger;
        var fullyQualifiedNamespace = configuration["ServiceBus:FullyQualifiedNamespace"];
        var connectionString = configuration["ServiceBus:ConnectionString"];
        var queueName = configuration["ServiceBus:DeviceReportQueue"] ?? "device-reports";

        if (!string.IsNullOrEmpty(fullyQualifiedNamespace))
        {
            var client = new ServiceBusClient(fullyQualifiedNamespace, new DefaultAzureCredential());
            _sender = client.CreateSender(queueName);
            _enabled = true;
            _logger.LogInformation("Service Bus queue '{Queue}' initialized with Managed Identity ({Namespace})", queueName, fullyQualifiedNamespace);
        }
        else if (!string.IsNullOrEmpty(connectionString))
        {
            var client = new ServiceBusClient(connectionString);
            _sender = client.CreateSender(queueName);
            _enabled = true;
            _logger.LogInformation("Service Bus queue '{Queue}' initialized with connection string", queueName);
        }
        else
        {
            _sender = null!;
            _enabled = false;
            _logger.LogWarning("Service Bus not configured - device reports will be processed synchronously");
        }
    }

    /// <summary>
    /// Enqueue a device report for async processing. Returns true if enqueued, false if fallback to sync.
    /// </summary>
    public async Task<bool> EnqueueReportAsync(DeviceReportRequest request)
    {
        if (!_enabled) return false;

        try
        {
            var messageBody = JsonSerializer.Serialize(request);
            var message = new ServiceBusMessage(messageBody)
            {
                ContentType = "application/json",
                Subject = "DeviceReport",
                MessageId = Guid.NewGuid().ToString(),
                ApplicationProperties =
                {
                    ["DeviceId"] = request.DeviceId,
                    ["DeviceName"] = request.DeviceName,
                    ["Timestamp"] = DateTime.UtcNow.ToString("O")
                }
            };

            await _sender.SendMessageAsync(message);
            _logger.LogInformation("Device report enqueued for {DeviceId}", request.DeviceId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to enqueue device report for {DeviceId} - falling back to sync", request.DeviceId);
            return false;
        }
    }
}
