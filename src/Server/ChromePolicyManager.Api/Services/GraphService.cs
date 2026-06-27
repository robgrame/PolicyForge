using Microsoft.Graph;
using Microsoft.Graph.Models;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Microsoft Graph implementation for resolving device group memberships.
/// </summary>
public class GraphService : IGraphService
{
    private readonly GraphServiceClient _graphClient;
    private readonly ILogger<GraphService> _logger;

    public GraphService(GraphServiceClient graphClient, ILogger<GraphService> logger)
    {
        _graphClient = graphClient;
        _logger = logger;
    }

    public async Task<List<string>> GetDeviceGroupMembershipsAsync(string deviceId)
    {
        try
        {
            // The deviceId from dsregcmd is the Entra device registration ID, NOT the object ID.
            // Graph API Devices[x].MemberOf requires the object ID, so we must resolve it first.
            string objectId = deviceId;

            // Try to resolve by deviceId filter (Entra registration ID → object ID)
            if (Guid.TryParse(deviceId, out _))
            {
                var devices = await _graphClient.Devices.GetAsync(config =>
                {
                    config.QueryParameters.Filter = $"deviceId eq '{deviceId}'";
                    config.QueryParameters.Select = ["id", "displayName", "deviceId"];
                    config.QueryParameters.Top = 1;
                });

                if (devices?.Value != null && devices.Value.Count > 0)
                {
                    objectId = devices.Value[0].Id!;
                    _logger.LogInformation("Resolved deviceId {DeviceId} to objectId {ObjectId} ({DisplayName})",
                        deviceId, objectId, devices.Value[0].DisplayName);
                }
                else
                {
                    _logger.LogWarning("Device {DeviceId} not found in Entra ID", deviceId);
                    return new List<string>();
                }
            }

            var memberOf = await _graphClient.Devices[objectId].MemberOf.GetAsync();
            var groupIds = new List<string>();

            if (memberOf?.Value != null)
            {
                foreach (var obj in memberOf.Value)
                {
                    if (obj is Group group && group.Id != null)
                    {
                        groupIds.Add(group.Id);
                    }
                }
            }

            // Handle pagination
            var pageIterator = PageIterator<DirectoryObject, DirectoryObjectCollectionResponse>
                .CreatePageIterator(_graphClient, memberOf!, (item) =>
                {
                    if (item is Group g && g.Id != null)
                        groupIds.Add(g.Id);
                    return true;
                });
            await pageIterator.IterateAsync();

            _logger.LogInformation("Device {DeviceId} (objectId={ObjectId}) is member of {Count} groups",
                deviceId, objectId, groupIds.Count);
            return groupIds.Distinct().ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve group memberships for device {DeviceId}", deviceId);
            return new List<string>();
        }
    }

    public async Task<List<EntraGroupInfo>> SearchGroupsAsync(string query, int top = 10)
    {
        try
        {
            var result = await _graphClient.Groups.GetAsync(config =>
            {
                config.QueryParameters.Filter = $"startsWith(displayName, '{query.Replace("'", "''")}')";
                config.QueryParameters.Top = top;
                config.QueryParameters.Select = ["id", "displayName", "description", "groupTypes", "securityEnabled"];
                config.QueryParameters.Orderby = ["displayName"];
                config.Headers.Add("ConsistencyLevel", "eventual");
                config.QueryParameters.Count = true;
            });

            var groups = new List<EntraGroupInfo>();
            if (result?.Value != null)
            {
                foreach (var g in result.Value)
                {
                    var groupType = g.SecurityEnabled == true ? "Security" : 
                        (g.GroupTypes?.Contains("Unified") == true ? "Microsoft 365" : "Distribution");
                    groups.Add(new EntraGroupInfo(g.Id!, g.DisplayName ?? "", g.Description, groupType));
                }
            }
            return groups;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to search groups with query '{Query}'", query);
            return [];
        }
    }
}
