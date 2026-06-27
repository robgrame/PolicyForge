using Azure.Identity;
using Azure.Messaging.ServiceBus;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Hubs;
using ChromePolicyManager.Contracts;
using Microsoft.AspNetCore.SignalR;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Background relay that consumes <c>cpm-command-status</c> messages emitted by the Worker,
/// persists the status onto the matching PrivilegedCommands row and broadcasts it to the
/// Admin portal over SignalR. Keeps SQL ownership in the API while the Worker stays SQL-free.
/// </summary>
public sealed class CommandStatusRelay : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IHubContext<CommandStatusHub> _hub;
    private readonly ILogger<CommandStatusRelay> _logger;
    private readonly string? _fullyQualifiedNamespace;
    private readonly string? _connectionString;
    private readonly string _queueName;

    public CommandStatusRelay(
        IConfiguration configuration,
        IServiceProvider serviceProvider,
        IHubContext<CommandStatusHub> hub,
        ILogger<CommandStatusRelay> logger)
    {
        _serviceProvider = serviceProvider;
        _hub = hub;
        _logger = logger;
        _fullyQualifiedNamespace = configuration["ServiceBus:FullyQualifiedNamespace"];
        _connectionString = configuration["ServiceBus:ConnectionString"];
        _queueName = configuration["ServiceBus:CommandStatusQueue"] ?? QueueNames.CommandStatus;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrEmpty(_fullyQualifiedNamespace) && string.IsNullOrEmpty(_connectionString))
        {
            _logger.LogWarning("Service Bus not configured - CommandStatusRelay disabled");
            return;
        }

        _logger.LogInformation("CommandStatusRelay starting, listening on queue '{Queue}'", _queueName);

        var client = !string.IsNullOrEmpty(_fullyQualifiedNamespace)
            ? new ServiceBusClient(_fullyQualifiedNamespace, new DefaultAzureCredential())
            : new ServiceBusClient(_connectionString);

        var processor = client.CreateProcessor(_queueName, new ServiceBusProcessorOptions
        {
            AutoCompleteMessages = false,
            MaxConcurrentCalls = 5
        });

        processor.ProcessMessageAsync += ProcessMessageAsync;
        processor.ProcessErrorAsync += args =>
        {
            _logger.LogError(args.Exception, "CommandStatusRelay processor error on {Entity}", args.EntityPath);
            return Task.CompletedTask;
        };

        await processor.StartProcessingAsync(stoppingToken);

        try { await Task.Delay(Timeout.Infinite, stoppingToken); }
        catch (OperationCanceledException) { }

        await processor.StopProcessingAsync();
        await processor.DisposeAsync();
        await client.DisposeAsync();
        _logger.LogInformation("CommandStatusRelay stopped");
    }

    private async Task ProcessMessageAsync(ProcessMessageEventArgs args)
    {
        try
        {
            var update = CommandStatusUpdate.Deserialize(args.Message.Body.ToString());
            if (update is null)
            {
                await args.DeadLetterMessageAsync(args.Message, "DeserializationFailed", "Could not parse status update");
                return;
            }

            using var scope = _serviceProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var record = await db.PrivilegedCommands.FindAsync(new object?[] { update.CommandId }, args.CancellationToken);
            if (record is not null)
            {
                record.Status = update.Status;
                record.Message = Truncate(update.Message, 1024);
                record.ResultJson = update.ResultJson;
                record.Error = Truncate(update.Error, 2000);
                record.Attempts++;
                record.UpdatedUtc = DateTime.UtcNow;
                await db.SaveChangesAsync(args.CancellationToken);
            }

            await _hub.Clients.All.SendAsync(CommandStatusHub.EventName, update, args.CancellationToken);
            await args.CompleteMessageAsync(args.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing status update {MessageId}", args.Message.MessageId);
            if (args.Message.DeliveryCount >= 3)
                await args.DeadLetterMessageAsync(args.Message, "ProcessingFailed", ex.Message);
            else
                await args.AbandonMessageAsync(args.Message);
        }
    }

    private static string? Truncate(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
