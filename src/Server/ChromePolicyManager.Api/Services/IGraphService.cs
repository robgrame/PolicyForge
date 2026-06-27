namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Interface for Microsoft Graph operations. Allows mocking in tests.
/// </summary>
public interface IGraphService
{
    /// <summary>
    /// Get the Entra ID group memberships for a device (server-side, trusted).
    /// </summary>
    Task<List<string>> GetDeviceGroupMembershipsAsync(string deviceId);

    /// <summary>
    /// Search Entra ID groups by display name prefix/substring.
    /// </summary>
    Task<List<EntraGroupInfo>> SearchGroupsAsync(string query, int top = 10);
}

public record EntraGroupInfo(string Id, string DisplayName, string? Description, string? GroupType);
