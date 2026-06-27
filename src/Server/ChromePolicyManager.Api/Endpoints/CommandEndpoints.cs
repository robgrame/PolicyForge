using ChromePolicyManager.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace ChromePolicyManager.Api.Endpoints;

/// <summary>
/// Read-only endpoints to inspect privileged-command status (the worker pipeline).
/// The portal subscribes to live updates over SignalR (CommandStatusHub) and uses these
/// endpoints for the initial load / history.
/// </summary>
public static class CommandEndpoints
{
    public static void MapCommandEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/commands").WithTags("Commands");

        group.MapGet("/", async (AppDbContext db, int? take) =>
        {
            var n = Math.Clamp(take ?? 50, 1, 200);
            var items = await db.PrivilegedCommands
                .OrderByDescending(c => c.CreatedUtc)
                .Take(n)
                .ToListAsync();
            return Results.Ok(items);
        }).WithName("GetCommands");

        group.MapGet("/{id:guid}", async (Guid id, AppDbContext db) =>
        {
            var item = await db.PrivilegedCommands.FindAsync(id);
            return item is null ? Results.NotFound() : Results.Ok(item);
        }).WithName("GetCommand");
    }
}
