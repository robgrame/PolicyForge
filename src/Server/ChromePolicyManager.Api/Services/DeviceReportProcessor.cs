using System.Text.Json;
using Azure.Identity;
using Azure.Messaging.ServiceBus;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Background processor that reads device reports from Azure Service Bus and processes them.
/// Handles: DeviceState upsert, compliance evaluation, offline detection alerts.
/// 
/// Flow: Device → APIM → Service Bus Queue → [this processor] → Database
/// 
/// Supports both Managed Identity (FullyQualifiedNamespace) and connection string auth.
/// </summary>
public class DeviceReportProcessor : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<DeviceReportProcessor> _logger;
    private readonly string? _fullyQualifiedNamespace;
    private readonly string? _connectionString;
    private readonly string _queueName;

    public DeviceReportProcessor(IConfiguration configuration, IServiceProvider serviceProvider, ILogger<DeviceReportProcessor> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _fullyQualifiedNamespace = configuration["ServiceBus:FullyQualifiedNamespace"];
        _connectionString = configuration["ServiceBus:ConnectionString"];
        _queueName = configuration["ServiceBus:DeviceReportQueue"] ?? "device-reports";
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrEmpty(_fullyQualifiedNamespace) && string.IsNullOrEmpty(_connectionString))
        {
            _logger.LogWarning("Service Bus not configured - DeviceReportProcessor disabled");
            return;
        }

        _logger.LogInformation("DeviceReportProcessor starting, listening on queue '{Queue}'", _queueName);

        ServiceBusClient client;
        if (!string.IsNullOrEmpty(_fullyQualifiedNamespace))
        {
            client = new ServiceBusClient(_fullyQualifiedNamespace, new DefaultAzureCredential());
            _logger.LogInformation("Service Bus processor using Managed Identity ({Namespace})", _fullyQualifiedNamespace);
        }
        else
        {
            client = new ServiceBusClient(_connectionString);
        }

        var processor = client.CreateProcessor(_queueName, new ServiceBusProcessorOptions
        {
            AutoCompleteMessages = false,
            MaxConcurrentCalls = 10,
            MaxAutoLockRenewalDuration = TimeSpan.FromMinutes(5)
        });

        processor.ProcessMessageAsync += ProcessMessageAsync;
        processor.ProcessErrorAsync += ProcessErrorAsync;

        await processor.StartProcessingAsync(stoppingToken);

        // Keep running until cancellation
        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException) { }

        await processor.StopProcessingAsync();
        await processor.DisposeAsync();
        await client.DisposeAsync();

        _logger.LogInformation("DeviceReportProcessor stopped");
    }

    private async Task ProcessMessageAsync(ProcessMessageEventArgs args)
    {
        var body = args.Message.Body.ToString();
        _logger.LogDebug("Processing device report message: {MessageId}", args.Message.MessageId);

        try
        {
            var request = JsonSerializer.Deserialize<DeviceReportRequest>(body);
            if (request == null)
            {
                _logger.LogWarning("Failed to deserialize device report message {MessageId}", args.Message.MessageId);
                await args.DeadLetterMessageAsync(args.Message, "DeserializationFailed", "Could not deserialize message body");
                return;
            }

            // Process the report using a scoped service
            using var scope = _serviceProvider.CreateScope();
            var reportingService = scope.ServiceProvider.GetRequiredService<DeviceReportingService>();
            await reportingService.SubmitReportAsync(request);

            // Fan out policy-application status (Event Grid -> API webhook -> SignalR -> portal).
            var eventPublisher = scope.ServiceProvider.GetRequiredService<IEventPublisher>();
            await eventPublisher.PublishDevicePolicyStatusAsync(new Contracts.DevicePolicyStatusChangedData
            {
                DeviceId = request.DeviceId,
                DeviceName = request.DeviceName,
                UserPrincipalName = request.UserPrincipalName,
                Status = request.Status.ToString(),
                AppliedVersion = request.AppliedVersion,
                ScriptVersion = request.ScriptVersion,
                PolicyKeysWritten = request.PolicyKeysWritten,
                PolicyKeysRemoved = request.PolicyKeysRemoved,
                Errors = request.Errors
            });

            // Check for alert conditions
            await EvaluateAlertsAsync(scope.ServiceProvider, request);

            await args.CompleteMessageAsync(args.Message);
            _logger.LogInformation("Device report processed for {DeviceId} ({DeviceName})", request.DeviceId, request.DeviceName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing device report message {MessageId}", args.Message.MessageId);

            if (args.Message.DeliveryCount >= 3)
            {
                await args.DeadLetterMessageAsync(args.Message, "ProcessingFailed", ex.Message);
            }
            else
            {
                await args.AbandonMessageAsync(args.Message);
            }
        }
    }

    private async Task EvaluateAlertsAsync(IServiceProvider services, DeviceReportRequest request)
    {
        // Alert on error status
        if (request.Status == DeviceComplianceStatus.Error)
        {
            _logger.LogWarning("⚠️ Device {DeviceName} ({DeviceId}) reported ERROR status: {Errors}",
                request.DeviceName, request.DeviceId, request.Errors);
            // TODO: Send alert (email, Teams webhook, Azure Monitor)
        }

        // Alert on partial application
        if (request.Status == DeviceComplianceStatus.PartiallyApplied)
        {
            _logger.LogWarning("⚠️ Device {DeviceName} ({DeviceId}) partially applied policies",
                request.DeviceName, request.DeviceId);
        }
    }

    private Task ProcessErrorAsync(ProcessErrorEventArgs args)
    {
        _logger.LogError(args.Exception, "Service Bus processor error. Source: {Source}, Entity: {Entity}",
            args.ErrorSource, args.EntityPath);
        return Task.CompletedTask;
    }
}
