using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Services;

namespace ChromePolicyManager.Api.Endpoints;

public static class DeviceEndpoints
{
    public static void MapDeviceEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/devices").WithTags("Devices");

        // Get effective policy for a device (server-side resolution)
        // Supports ETag/If-None-Match for bandwidth optimization at scale
        group.MapGet("/{deviceId}/effective-policy", async (string deviceId, HttpContext httpContext, EffectivePolicyService service) =>
        {
            var result = await service.GetEffectivePolicyAsync(deviceId);
            var etag = $"\"{result.Hash}\"";

            // Check If-None-Match header — if hash matches, policy hasn't changed
            var ifNoneMatch = httpContext.Request.Headers.IfNoneMatch.FirstOrDefault();
            if (!string.IsNullOrEmpty(ifNoneMatch) && ifNoneMatch == etag)
            {
                httpContext.Response.Headers.ETag = etag;
                return Results.StatusCode(304);
            }

            httpContext.Response.Headers.ETag = etag;
            httpContext.Response.Headers.CacheControl = "no-cache"; // must revalidate
            return Results.Ok(result);
        }).WithName("GetEffectivePolicy");

        // Device reports compliance status - async via Service Bus when available
        group.MapPost("/{deviceId}/report", async (string deviceId, [FromBody] DeviceReportRequest request,
            DeviceReportQueue queue, DeviceReportingService service, IEventPublisher events) =>
        {
            if (request.DeviceId != deviceId)
                return Results.BadRequest("DeviceId in URL must match body");

            // Try async processing via Service Bus
            var enqueued = await queue.EnqueueReportAsync(request);
            if (enqueued)
            {
                return Results.Accepted(value: new { Status = "Accepted", Message = "Report queued for processing" });
            }

            // Fallback: process synchronously if Service Bus not configured
            var report = await service.SubmitReportAsync(request);
            await events.PublishDevicePolicyStatusAsync(new ChromePolicyManager.Contracts.DevicePolicyStatusChangedData
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
            return Results.Ok(new { ReportId = report.Id, Received = report.ReportedAt });
        }).WithName("SubmitDeviceReport");

        // Get device compliance history
        group.MapGet("/{deviceId}/history", async (string deviceId, DeviceReportingService service, int? count) =>
        {
            var history = await service.GetDeviceHistoryAsync(deviceId, count ?? 20);
            return Results.Ok(history);
        }).WithName("GetDeviceHistory");

        // Batch ingest device logs
        group.MapPost("/{deviceId}/logs", async (string deviceId, [FromBody] DeviceLogBatchRequest request,
            AppDbContext db) =>
        {
            if (request.Entries == null || request.Entries.Count == 0)
                return Results.BadRequest("No log entries");

            if (request.Entries.Count > 500)
                return Results.BadRequest("Max 500 entries per batch");

            var now = DateTime.UtcNow;
            var logs = request.Entries.Select(e => new Models.DeviceLog
            {
                DeviceId = deviceId,
                DeviceName = request.DeviceName ?? "",
                ScriptType = request.ScriptType ?? "Unknown",
                Level = e.Level ?? "INFO",
                Message = e.Message ?? "",
                ClientTimestamp = e.Timestamp,
                ReceivedAt = now
            }).ToList();

            db.DeviceLogs.AddRange(logs);

            // Upsert DeviceState so device appears in dashboard on first check-in
            var deviceState = await db.DeviceStates.FindAsync(deviceId);
            if (deviceState == null)
            {
                deviceState = new Models.DeviceState
                {
                    DeviceId = deviceId,
                    DeviceName = request.DeviceName ?? "",
                    LastCheckIn = now,
                    LastStatus = Models.DeviceComplianceStatus.Unknown,
                    ChromeVersion = request.ChromeVersion,
                    OsVersion = request.OsVersion,
                    OsBuild = request.OsBuild,
                    Manufacturer = request.Manufacturer,
                    Model = request.Model,
                    ScriptVersion = request.ScriptVersion
                };
                db.DeviceStates.Add(deviceState);
            }
            else
            {
                deviceState.LastCheckIn = now;
                if (!string.IsNullOrEmpty(request.DeviceName))
                    deviceState.DeviceName = request.DeviceName;
                if (!string.IsNullOrEmpty(request.ChromeVersion))
                    deviceState.ChromeVersion = request.ChromeVersion;
                if (!string.IsNullOrEmpty(request.OsVersion))
                    deviceState.OsVersion = request.OsVersion;
                if (!string.IsNullOrEmpty(request.OsBuild))
                    deviceState.OsBuild = request.OsBuild;
                if (!string.IsNullOrEmpty(request.Manufacturer))
                    deviceState.Manufacturer = request.Manufacturer;
                if (!string.IsNullOrEmpty(request.Model))
                    deviceState.Model = request.Model;
                if (!string.IsNullOrEmpty(request.ScriptVersion))
                    deviceState.ScriptVersion = request.ScriptVersion;
            }

            await db.SaveChangesAsync();

            return Results.Ok(new { Accepted = logs.Count });
        }).WithName("IngestDeviceLogs");

        // Query device logs (for admin UI)
        group.MapGet("/{deviceId}/logs", async (string deviceId, AppDbContext db, int? count, string? level) =>
        {
            var query = db.DeviceLogs
                .Where(l => l.DeviceId == deviceId)
                .OrderByDescending(l => l.ClientTimestamp)
                .AsQueryable();

            if (!string.IsNullOrEmpty(level))
                query = query.Where(l => l.Level == level.ToUpper());

            var logs = await query.Take(count ?? 100).ToListAsync();
            return Results.Ok(logs);
        }).WithName("GetDeviceLogs");
    }
}

public record DeviceLogBatchRequest
{
    public string? DeviceName { get; init; }
    public string? ScriptType { get; init; }
    public string? ChromeVersion { get; init; }
    public string? OsVersion { get; init; }
    public string? OsBuild { get; init; }
    public string? Manufacturer { get; init; }
    public string? Model { get; init; }
    public string? ScriptVersion { get; init; }
    public List<DeviceLogEntry> Entries { get; init; } = [];
}

public record DeviceLogEntry
{
    public DateTime Timestamp { get; init; }
    public string? Level { get; init; }
    public string? Message { get; init; }
}
