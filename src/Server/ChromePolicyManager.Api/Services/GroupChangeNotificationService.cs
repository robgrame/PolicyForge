using System.Text.Json;
using Microsoft.Graph;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Manages Microsoft Graph change notification subscriptions for group membership changes.
/// When a group's membership changes, we get notified instead of polling Graph for every device.
/// </summary>
public class GroupChangeNotificationService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<GroupChangeNotificationService> _logger;
    private readonly IConfiguration _configuration;
    private readonly Dictionary<string, (string SubscriptionId, DateTime Expiry)> _subscriptions = new();
    private static readonly TimeSpan RenewalBuffer = TimeSpan.FromHours(1);

    public GroupChangeNotificationService(
        IServiceProvider serviceProvider,
        ILogger<GroupChangeNotificationService> logger,
        IConfiguration configuration)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _configuration = configuration;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Wait for app startup
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await EnsureSubscriptionsAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error managing Graph subscriptions");
            }

            // Check every 30 minutes for subscription renewals
            await Task.Delay(TimeSpan.FromMinutes(30), stoppingToken);
        }
    }

    /// <summary>
    /// Ensures all groups used in policy assignments have active webhook subscriptions.
    /// </summary>
    private async Task EnsureSubscriptionsAsync(CancellationToken ct)
    {
        using var scope = _serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<Data.AppDbContext>();
        var graphClient = scope.ServiceProvider.GetRequiredService<GraphServiceClient>();

        var notificationUrl = _configuration["GraphWebhooks:NotificationUrl"];
        if (string.IsNullOrEmpty(notificationUrl))
        {
            _logger.LogWarning("GraphWebhooks:NotificationUrl not configured — skipping subscription management");
            return;
        }

        // Get all distinct group IDs from active assignments
        var activeGroupIds = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions
            .ToListAsync(
                db.PolicyAssignments
                    .Where(a => a.Enabled)
                    .Select(a => a.EntraGroupId)
                    .Distinct(),
                ct);

        foreach (var groupId in activeGroupIds)
        {
            await EnsureGroupSubscriptionAsync(graphClient, groupId, notificationUrl, ct);
        }

        // Remove subscriptions for groups no longer in use
        var staleGroups = _subscriptions.Keys.Except(activeGroupIds).ToList();
        foreach (var groupId in staleGroups)
        {
            await RemoveSubscriptionAsync(graphClient, groupId, ct);
        }
    }

    private async Task EnsureGroupSubscriptionAsync(
        GraphServiceClient graphClient, string groupId, string notificationUrl, CancellationToken ct)
    {
        // Check if we have an active subscription that doesn't need renewal
        if (_subscriptions.TryGetValue(groupId, out var existing) &&
            existing.Expiry > DateTime.UtcNow + RenewalBuffer)
        {
            return; // Still valid
        }

        try
        {
            // Max expiration for group resources: 4230 minutes (~2.9 days)
            var expiry = DateTime.UtcNow.AddMinutes(4200);

            if (existing.SubscriptionId != null)
            {
                // Renew existing subscription
                await graphClient.Subscriptions[existing.SubscriptionId]
                    .PatchAsync(new Microsoft.Graph.Models.Subscription
                    {
                        ExpirationDateTime = new DateTimeOffset(expiry)
                    }, cancellationToken: ct);

                _subscriptions[groupId] = (existing.SubscriptionId, expiry);
                _logger.LogInformation("Renewed subscription for group {GroupId}, expires {Expiry}", groupId, expiry);
            }
            else
            {
                // Create new subscription
                var subscription = await graphClient.Subscriptions.PostAsync(
                    new Microsoft.Graph.Models.Subscription
                    {
                        ChangeType = "updated",
                        NotificationUrl = $"{notificationUrl}?groupId={groupId}",
                        Resource = $"groups/{groupId}/members",
                        ExpirationDateTime = new DateTimeOffset(expiry),
                        ClientState = _configuration["GraphWebhooks:ClientState"] ?? "cpm-webhook-secret"
                    }, cancellationToken: ct);

                if (subscription?.Id != null)
                {
                    _subscriptions[groupId] = (subscription.Id, expiry);
                    _logger.LogInformation("Created subscription {SubId} for group {GroupId}", subscription.Id, groupId);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to manage subscription for group {GroupId}", groupId);
        }
    }

    private async Task RemoveSubscriptionAsync(GraphServiceClient graphClient, string groupId, CancellationToken ct)
    {
        if (_subscriptions.TryGetValue(groupId, out var sub) && sub.SubscriptionId != null)
        {
            try
            {
                await graphClient.Subscriptions[sub.SubscriptionId].DeleteAsync(cancellationToken: ct);
                _logger.LogInformation("Removed subscription for group {GroupId}", groupId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to remove subscription for group {GroupId}", groupId);
            }
        }
        _subscriptions.Remove(groupId);
    }
}
