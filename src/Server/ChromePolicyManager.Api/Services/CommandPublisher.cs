using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;
using ChromePolicyManager.Contracts;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Publishes privileged commands to the Worker: persists a tracking row in PrivilegedCommands
/// (status Pending) then enqueues the envelope on the command queue (status Dispatched).
/// The Worker reports progress back via the status relay (cpm-command-status queue).
/// </summary>
public interface ICommandPublisher
{
    bool Enabled { get; }

    Task<Guid> PublishAsync<TPayload>(
        PrivilegedCommandType type, TPayload payload,
        string? actor = null, string? reason = null, CancellationToken ct = default);
}

public sealed class CommandPublisher : ICommandPublisher
{
    private readonly AppDbContext _db;
    private readonly CommandQueueClient _queue;
    private readonly ILogger<CommandPublisher> _logger;

    public CommandPublisher(AppDbContext db, CommandQueueClient queue, ILogger<CommandPublisher> logger)
    {
        _db = db;
        _queue = queue;
        _logger = logger;
    }

    public bool Enabled => _queue.Enabled;

    public async Task<Guid> PublishAsync<TPayload>(
        PrivilegedCommandType type, TPayload payload,
        string? actor = null, string? reason = null, CancellationToken ct = default)
    {
        var envelope = PrivilegedCommandEnvelope.Create(type, payload, actor, reason);

        var record = new PrivilegedCommand
        {
            Id = envelope.CommandId,
            Type = type,
            Status = CommandStatus.Pending,
            PayloadJson = envelope.PayloadJson.Length <= 2000 ? envelope.PayloadJson : envelope.PayloadJson[..2000],
            Actor = actor,
            Reason = reason,
            CreatedUtc = DateTime.UtcNow
        };
        _db.PrivilegedCommands.Add(record);
        await _db.SaveChangesAsync(ct);

        try
        {
            await _queue.SendAsync(envelope, ct);
            record.Status = CommandStatus.Dispatched;
            record.UpdatedUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync(ct);
            _logger.LogInformation("Privileged command {CommandId} ({Type}) dispatched", envelope.CommandId, type);
        }
        catch (Exception ex)
        {
            record.Status = CommandStatus.Failed;
            record.Error = ex.Message.Length <= 2000 ? ex.Message : ex.Message[..2000];
            record.UpdatedUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync(ct);
            _logger.LogError(ex, "Failed to dispatch privileged command {CommandId} ({Type})", envelope.CommandId, type);
            throw;
        }

        return envelope.CommandId;
    }
}
