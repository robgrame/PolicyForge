using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

public class AuditService
{
    private readonly AppDbContext _db;

    public AuditService(AppDbContext db)
    {
        _db = db;
    }

    public async Task LogAsync(string action, string? actor, string entityType, string? entityId, string? details = null)
    {
        _db.AuditLogs.Add(new AuditLog
        {
            Action = action,
            Actor = actor,
            EntityType = entityType,
            EntityId = entityId,
            Details = details
        });
        await _db.SaveChangesAsync();
    }
}
