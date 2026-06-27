using System.Text;
using System.Text.Json;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Abstractions;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

public sealed record PushRemediationDispatchResult(
    bool Skipped,
    string Message,
    int TotalDevices,
    int CommandsSent,
    int CommandsFailed,
    int BatchesProcessed);

public class PushRemediationService
{
    private readonly GraphServiceClient _graphClient;
    private readonly ILogger<PushRemediationService> _logger;
    private readonly IConfiguration _configuration;
    private readonly AuditService _audit;

    public PushRemediationService(
        GraphServiceClient graphClient,
        ILogger<PushRemediationService> logger,
        IConfiguration configuration,
        AuditService audit)
    {
        _graphClient = graphClient;
        _logger = logger;
        _configuration = configuration;
        _audit = audit;
    }

    /// <summary>
    /// Trigger on-demand proactive remediation for a single device by its Entra device ID.
    /// </summary>
    public async Task<PushRemediationDispatchResult> DispatchToDeviceAsync(
        string entraDeviceId, string reason, string? actor = null, CancellationToken ct = default)
    {
        var scriptPolicyId = _configuration["PushRemediation:ScriptPolicyId"];
        if (string.IsNullOrWhiteSpace(scriptPolicyId))
        {
            return new PushRemediationDispatchResult(true, "PushRemediation:ScriptPolicyId is not configured.", 0, 0, 0, 0);
        }

        var managedDeviceId = await ResolveManagedDeviceIdAsync(entraDeviceId, ct);
        if (string.IsNullOrWhiteSpace(managedDeviceId))
        {
            return new PushRemediationDispatchResult(false, $"Could not resolve managed device for {entraDeviceId}.", 1, 0, 1, 0);
        }

        var success = await SendRemediationCommandAsync(managedDeviceId, scriptPolicyId, ct);
        await _audit.LogAsync("PushRemediation.Device", actor, "Device", entraDeviceId,
            $"Reason={reason}; ManagedDeviceId={managedDeviceId}; Success={success}");

        return success
            ? new PushRemediationDispatchResult(false, "Remediation triggered successfully.", 1, 1, 0, 1)
            : new PushRemediationDispatchResult(false, "Failed to send remediation command.", 1, 0, 1, 1);
    }

    public async Task<PushRemediationDispatchResult> DispatchToAssignmentAsync(
        PolicyAssignment assignment, string reason, string? actor = null, CancellationToken ct = default)
    {
        if (!assignment.PushRemediationEnabled)
        {
            return new PushRemediationDispatchResult(
                true, "Push remediation is disabled for this assignment.", 0, 0, 0, 0);
        }

        var scriptPolicyId = _configuration["PushRemediation:ScriptPolicyId"];
        if (string.IsNullOrWhiteSpace(scriptPolicyId))
        {
            var message = "PushRemediation:ScriptPolicyId is not configured.";
            _logger.LogWarning(message);
            return new PushRemediationDispatchResult(true, message, 0, 0, 0, 0);
        }

        var batchSize = Math.Clamp(_configuration.GetValue<int?>("PushRemediation:BatchSize") ?? 100, 1, 500);
        var groupDeviceIds = await GetGroupDeviceIdsAsync(assignment.EntraGroupId, ct);

        if (groupDeviceIds.Count == 0)
        {
            var noDeviceMessage = $"No devices found in group '{assignment.GroupName}'.";
            await _audit.LogAsync("PushRemediation.NoDevices", actor, "PolicyAssignment", assignment.Id.ToString(), noDeviceMessage);
            return new PushRemediationDispatchResult(false, noDeviceMessage, 0, 0, 0, 0);
        }

        var sent = 0;
        var failed = 0;
        var batches = 0;

        foreach (var batch in groupDeviceIds.Chunk(batchSize))
        {
            ct.ThrowIfCancellationRequested();
            batches++;

            foreach (var entraDeviceId in batch)
            {
                var managedDeviceId = await ResolveManagedDeviceIdAsync(entraDeviceId, ct);
                if (string.IsNullOrWhiteSpace(managedDeviceId))
                {
                    failed++;
                    continue;
                }

                if (await SendRemediationCommandAsync(managedDeviceId, scriptPolicyId, ct))
                    sent++;
                else
                    failed++;
            }
        }

        var details = $"Reason={reason}; Devices={groupDeviceIds.Count}; Sent={sent}; Failed={failed}; Batches={batches}; Group={assignment.GroupName}";
        await _audit.LogAsync("PushRemediation.Dispatched", actor, "PolicyAssignment", assignment.Id.ToString(), details);

        return new PushRemediationDispatchResult(
            false,
            $"Push remediation dispatched for group '{assignment.GroupName}'.",
            groupDeviceIds.Count,
            sent,
            failed,
            batches);
    }

    private async Task<List<string>> GetGroupDeviceIdsAsync(string groupId, CancellationToken ct)
    {
        var deviceIds = new List<string>();
        var members = await _graphClient.Groups[groupId].Members.GetAsync(cancellationToken: ct);
        if (members != null)
        {
            var iterator = PageIterator<DirectoryObject, DirectoryObjectCollectionResponse>
                .CreatePageIterator(_graphClient, members, item =>
                {
                    if (item is Device d && !string.IsNullOrWhiteSpace(d.Id))
                        deviceIds.Add(d.Id);
                    return true;
                });
            await iterator.IterateAsync();
        }

        return deviceIds.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<string?> ResolveManagedDeviceIdAsync(string entraDeviceId, CancellationToken ct)
    {
        try
        {
            var result = await _graphClient.DeviceManagement.ManagedDevices.GetAsync(config =>
            {
                config.QueryParameters.Filter = $"azureADDeviceId eq '{entraDeviceId}'";
                config.QueryParameters.Select = ["id"];
                config.QueryParameters.Top = 1;
            }, cancellationToken: ct);
            return result?.Value?.FirstOrDefault()?.Id;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to resolve managed device for Entra device {DeviceId}", entraDeviceId);
            return null;
        }
    }

    private async Task<bool> SendRemediationCommandAsync(string managedDeviceId, string scriptPolicyId, CancellationToken ct)
    {
        try
        {
            var request = new RequestInformation
            {
                HttpMethod = Method.POST,
                URI = new Uri($"{_graphClient.RequestAdapter.BaseUrl}/beta/deviceManagement/managedDevices/{managedDeviceId}/initiateOnDemandProactiveRemediation")
            };
            var payload = JsonSerializer.Serialize(new { scriptPolicyId });
            request.SetStreamContent(new MemoryStream(Encoding.UTF8.GetBytes(payload)), "application/json");
            await _graphClient.RequestAdapter.SendNoContentAsync(request, cancellationToken: ct);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send remediation command to managed device {ManagedDeviceId}", managedDeviceId);
            return false;
        }
    }
}
