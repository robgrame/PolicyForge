using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PolicyForge.Api.Data;
using PolicyForge.Api.Models;
using PolicyForge.Api.Providers;
using PolicyForge.Api.Services;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Endpoints;

public static class ConfigurationEndpoints
{
    public static void MapConfigurationEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/configuration").WithTags("Configuration Engine");

        // GET /api/configuration/providers - provider types supported by this server.
        group.MapGet("/providers", (ConfigurationProviderRegistry registry) =>
            Results.Ok(registry.SupportedTypes.OrderBy(t => t).Select(t => t.ToString())))
            .WithName("GetSupportedProviders");

        // POST /api/configuration/compile - validate and compile a set of authored items into the
        // flat, client-ready instruction set (no persistence). Useful for authoring previews and tests.
        group.MapPost("/compile", (CompileRequest request, ConfigurationCompiler compiler) =>
        {
            var items = request.Items ?? new List<ConfigurationItem>();

            var errors = compiler.Validate(items);
            if (errors.Count > 0)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["items"] = errors.ToArray() });

            var resolved = compiler.BuildResolved(request.DeviceId ?? string.Empty, items);
            return Results.Ok(resolved);
        })
        .WithName("CompileConfiguration");

        // GET /api/configuration/resolve/{deviceId} - the device-facing endpoint the client
        // dispatcher fetches: resolves group memberships + active assignments server-side and
        // returns the flat, de-duplicated instruction set the device must converge to.
        group.MapGet("/resolve/{deviceId}", async (string deviceId, ConfigurationResolveService resolver) =>
        {
            var resolved = await resolver.ResolveAsync(deviceId);
            return Results.Ok(resolved);
        })
        .WithName("ResolveConfiguration");

        // POST /api/configuration/snapshots - device uploads a rollback snapshot after Enforce.
        group.MapPost("/snapshots", async (SnapshotUploadRequest request, AppDbContext db) =>
        {
            if (string.IsNullOrWhiteSpace(request.DeviceId))
                return Results.BadRequest("deviceId is required");

            var instructionsJson = request.Instructions.ValueKind == JsonValueKind.Array
                ? request.Instructions.GetRawText()
                : "[]";
            var count = request.Instructions.ValueKind == JsonValueKind.Array
                ? request.Instructions.GetArrayLength()
                : 0;

            var snapshot = new ConfigurationSnapshot
            {
                DeviceId = request.DeviceId,
                ForwardHash = request.ForwardHash ?? string.Empty,
                CapturedAt = request.CapturedAt ?? DateTime.UtcNow,
                ItemCount = count,
                InstructionsJson = instructionsJson,
                ReceivedAt = DateTime.UtcNow
            };
            db.ConfigurationSnapshots.Add(snapshot);
            await db.SaveChangesAsync();
            return Results.Ok(new { snapshot.Id, snapshot.ItemCount });
        })
        .WithName("UploadSnapshot")
        .DisableAntiforgery();

        // GET /api/configuration/snapshots?deviceId=&take= - list recent snapshots (metadata only).
        group.MapGet("/snapshots", async (AppDbContext db, string? deviceId, int? take) =>
        {
            var q = db.ConfigurationSnapshots.AsQueryable();
            if (!string.IsNullOrWhiteSpace(deviceId))
                q = q.Where(s => s.DeviceId == deviceId);
            var items = await q
                .OrderByDescending(s => s.ReceivedAt)
                .Take(Math.Clamp(take ?? 50, 1, 200))
                .Select(s => new { s.Id, s.DeviceId, s.ForwardHash, s.CapturedAt, s.ItemCount, s.ReceivedAt })
                .ToListAsync();
            return Results.Ok(items);
        })
        .WithName("ListSnapshots");

        // GET /api/configuration/snapshots/{id} - full snapshot incl. inverse instructions.
        group.MapGet("/snapshots/{id:guid}", async (AppDbContext db, Guid id) =>
        {
            var s = await db.ConfigurationSnapshots.FindAsync(id);
            if (s is null) return Results.NotFound();
            return Results.Ok(new
            {
                s.Id, s.DeviceId, s.ForwardHash, s.CapturedAt, s.ItemCount, s.ReceivedAt,
                Instructions = JsonSerializer.Deserialize<JsonElement>(s.InstructionsJson)
            });
        })
        .WithName("GetSnapshot");
    }

    public sealed record CompileRequest
    {
        public string? DeviceId { get; init; }
        public List<ConfigurationItem>? Items { get; init; }
    }

    public sealed record SnapshotUploadRequest
    {
        public string DeviceId { get; init; } = string.Empty;
        public string? ForwardHash { get; init; }
        public DateTime? CapturedAt { get; init; }
        public JsonElement Instructions { get; init; }
    }
}
