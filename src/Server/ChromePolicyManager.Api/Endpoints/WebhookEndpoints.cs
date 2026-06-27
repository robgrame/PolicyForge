using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Data;

namespace ChromePolicyManager.Api.Endpoints;

/// <summary>
/// Receives Microsoft Graph change notifications when group memberships change.
/// This eliminates the need to call Graph for every device check-in — 
/// we only recalculate effective policies for affected devices.
/// </summary>
public static class WebhookEndpoints
{
    // In-memory set of group IDs that changed recently (devices check this on next poll)
    private static readonly HashSet<string> _changedGroups = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object _lock = new();
    private static DateTime _lastCleared = DateTime.UtcNow;

    public static void MapWebhookEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/webhooks").WithTags("Webhooks");

        // Graph subscription validation + change notification receiver
        group.MapPost("/group-change", async (HttpContext context, IConfiguration config, AppDbContext db) =>
        {
            // Step 1: Handle subscription validation (Graph sends validationToken on creation)
            if (context.Request.Query.ContainsKey("validationToken"))
            {
                var token = context.Request.Query["validationToken"].ToString();
                context.Response.ContentType = "text/plain";
                await context.Response.WriteAsync(token);
                return;
            }

            // Step 2: Verify client state
            var expectedState = config["GraphWebhooks:ClientState"] ?? "cpm-webhook-secret";

            // Step 3: Read notification payload
            using var reader = new StreamReader(context.Request.Body);
            var body = await reader.ReadToEndAsync();

            try
            {
                var notification = JsonDocument.Parse(body);
                var values = notification.RootElement.GetProperty("value");

                foreach (var item in values.EnumerateArray())
                {
                    // Verify clientState
                    if (item.TryGetProperty("clientState", out var state) &&
                        state.GetString() != expectedState)
                    {
                        continue; // Skip invalid notifications
                    }

                    // Extract group ID from resource path or query param
                    var resource = item.TryGetProperty("resource", out var res) ? res.GetString() : null;
                    var groupId = ExtractGroupId(resource);

                    if (!string.IsNullOrEmpty(groupId))
                    {
                        lock (_lock)
                        {
                            _changedGroups.Add(groupId);
                        }

                        // Log the change
                        var changeType = item.TryGetProperty("changeType", out var ct) ? ct.GetString() : "unknown";
                        app.Logger.LogInformation(
                            "Group membership changed: {GroupId}, change: {ChangeType}",
                            groupId, changeType);
                    }
                }
            }
            catch (Exception ex)
            {
                app.Logger.LogWarning(ex, "Failed to parse Graph notification");
            }

            // Graph expects 202 Accepted within 3 seconds
            context.Response.StatusCode = 202;
        }).WithName("GraphGroupChangeWebhook");

        // Endpoint for the effective-policy resolver to check if a group changed recently
        group.MapGet("/changed-groups", (HttpContext context) =>
        {
            // Auto-clear after 2 hours (safety net)
            lock (_lock)
            {
                if (DateTime.UtcNow - _lastCleared > TimeSpan.FromHours(2))
                {
                    _changedGroups.Clear();
                    _lastCleared = DateTime.UtcNow;
                }
                return Results.Ok(new
                {
                    ChangedGroups = _changedGroups.ToList(),
                    Count = _changedGroups.Count,
                    Since = _lastCleared
                });
            }
        }).WithName("GetChangedGroups");

        // Endpoint for devices to acknowledge they've processed the change
        group.MapPost("/acknowledge/{groupId}", (string groupId) =>
        {
            // This would be called after all devices in a group have been notified
            // For now, we clear on a timer basis
            return Results.Ok();
        }).WithName("AcknowledgeGroupChange");
    }

    /// <summary>
    /// Check if any of the given groups have changed membership recently.
    /// Used by EffectivePolicyService to determine if a full Graph call is needed.
    /// </summary>
    public static bool HasGroupChanged(IEnumerable<string> groupIds)
    {
        lock (_lock)
        {
            return groupIds.Any(g => _changedGroups.Contains(g));
        }
    }

    /// <summary>
    /// Mark a group as no longer changed (after all affected devices have been refreshed).
    /// </summary>
    public static void ClearGroupChange(string groupId)
    {
        lock (_lock)
        {
            _changedGroups.Remove(groupId);
        }
    }

    private static string? ExtractGroupId(string? resource)
    {
        if (string.IsNullOrEmpty(resource)) return null;

        // Resource format: "groups/{group-id}/members"
        var parts = resource.Split('/');
        var groupIdx = Array.IndexOf(parts, "groups");
        if (groupIdx >= 0 && groupIdx + 1 < parts.Length)
        {
            return parts[groupIdx + 1];
        }
        return null;
    }
}
