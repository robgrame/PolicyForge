using System.Text.Json;
using ChromePolicyManager.Contracts;
using ChromePolicyManager.Worker.Services;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace ChromePolicyManager.Worker.Functions;

/// <summary>
/// Service Bus–triggered entry point for the decoupled privileged-action pipeline (ADR-001).
/// Consumes <c>cpm-commands</c>, dispatches by command type, and reports progress/outcome back
/// to the API on <c>cpm-command-status</c>. Throwing lets Service Bus retry up to MaxDeliveryCount
/// and then dead-letter, so idempotency is handled by the API tracking row.
/// </summary>
public sealed class CommandHandlerFunction
{
    private readonly PrivilegedGraphActions _graphActions;
    private readonly StatusPublisher _status;
    private readonly ILogger<CommandHandlerFunction> _logger;

    public CommandHandlerFunction(
        PrivilegedGraphActions graphActions, StatusPublisher status, ILogger<CommandHandlerFunction> logger)
    {
        _graphActions = graphActions;
        _status = status;
        _logger = logger;
    }

    [Function(nameof(CommandHandlerFunction))]
    public async Task RunAsync(
        [ServiceBusTrigger("%ServiceBus:CommandQueue%", Connection = "ServiceBus")] string body,
        CancellationToken ct)
    {
        var envelope = PrivilegedCommandEnvelope.Deserialize(body);
        if (envelope is null)
        {
            _logger.LogError("Could not deserialize command envelope; dropping message");
            return; // malformed message: complete to avoid poison loop
        }

        _logger.LogInformation("Handling command {CommandId} ({Type})", envelope.CommandId, envelope.Type);
        await _status.PublishAsync(new CommandStatusUpdate
        {
            CommandId = envelope.CommandId,
            Status = CommandStatus.InProgress,
            Message = $"Worker processing {envelope.Type}"
        }, ct);

        try
        {
            var (status, message, result) = await DispatchAsync(envelope, ct);
            await _status.PublishAsync(new CommandStatusUpdate
            {
                CommandId = envelope.CommandId,
                Status = status,
                Message = message,
                ResultJson = result
            }, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Command {CommandId} ({Type}) failed", envelope.CommandId, envelope.Type);
            await _status.PublishAsync(new CommandStatusUpdate
            {
                CommandId = envelope.CommandId,
                Status = CommandStatus.Failed,
                Error = ex.Message
            }, ct);
            throw; // let Service Bus retry / dead-letter
        }
    }

    private async Task<(CommandStatus Status, string Message, string? ResultJson)> DispatchAsync(
        PrivilegedCommandEnvelope envelope, CancellationToken ct)
    {
        switch (envelope.Type)
        {
            case PrivilegedCommandType.PushRemediationDispatch:
            {
                var payload = envelope.GetPayload<PushRemediationDispatchPayload>()
                    ?? throw new InvalidOperationException("Missing PushRemediationDispatch payload");
                var result = await _graphActions.DispatchToAssignmentAsync(payload, ct);
                return ToStatus(result);
            }
            case PrivilegedCommandType.PushRemediationDevice:
            {
                var payload = envelope.GetPayload<PushRemediationDevicePayload>()
                    ?? throw new InvalidOperationException("Missing PushRemediationDevice payload");
                var result = await _graphActions.DispatchToDeviceAsync(payload, ct);
                return ToStatus(result);
            }
            case PrivilegedCommandType.WebhookSubscriptionSync:
                // TODO (ADR-001 phase 2): reconcile Graph change-notification subscriptions
                // for payload.ActiveGroupIds. Stubbed until the subscription logic is migrated.
                _logger.LogInformation("WebhookSubscriptionSync not yet implemented in Worker");
                return (CommandStatus.Skipped, "WebhookSubscriptionSync not yet implemented", null);

            default:
                return (CommandStatus.Failed, $"Unknown command type {envelope.Type}", null);
        }
    }

    private static (CommandStatus, string, string?) ToStatus(PushRemediationDispatchResult result)
    {
        var status = result.Skipped
            ? CommandStatus.Skipped
            : result.CommandsFailed > 0 && result.CommandsSent == 0
                ? CommandStatus.Failed
                : CommandStatus.Succeeded;
        return (status, result.Message, JsonSerializer.Serialize(result));
    }
}
