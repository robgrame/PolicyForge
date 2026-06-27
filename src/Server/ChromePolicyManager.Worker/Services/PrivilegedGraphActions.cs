using System.Text;
using System.Text.Json;
using ChromePolicyManager.Contracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Abstractions;

namespace ChromePolicyManager.Worker.Services;

/// <summary>
/// Privileged Graph/Intune actions executed by the Worker. Ported from the API's
/// PushRemediationService but stripped of SQL/Audit dependencies: all data needed comes
/// from the command payload, and outcomes are reported back via <see cref="StatusPublisher"/>.
/// </summary>
public sealed class PrivilegedGraphActions
{
    private readonly GraphServiceClient _graph;
    private readonly IConfiguration _configuration;
    private readonly ILogger<PrivilegedGraphActions> _logger;

    public PrivilegedGraphActions(
        GraphServiceClient graph, IConfiguration configuration, ILogger<PrivilegedGraphActions> logger)
    {
        _graph = graph;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<PushRemediationDispatchResult> DispatchToAssignmentAsync(
        PushRemediationDispatchPayload payload, CancellationToken ct = default)
    {
        var scriptPolicyId = _configuration["PushRemediation:ScriptPolicyId"];
        if (string.IsNullOrWhiteSpace(scriptPolicyId))
            return new(true, "PushRemediation:ScriptPolicyId is not configured.", 0, 0, 0, 0);

        var batchSize = Math.Clamp(_configuration.GetValue<int?>("PushRemediation:BatchSize") ?? 100, 1, 500);
        var groupDeviceIds = await GetGroupDeviceIdsAsync(payload.EntraGroupId, ct);

        if (groupDeviceIds.Count == 0)
            return new(false, $"No devices found in group '{payload.GroupName ?? payload.EntraGroupId}'.", 0, 0, 0, 0);

        int sent = 0, failed = 0, batches = 0;
        foreach (var batch in groupDeviceIds.Chunk(batchSize))
        {
            ct.ThrowIfCancellationRequested();
            batches++;
            foreach (var entraDeviceId in batch)
            {
                var managedDeviceId = await ResolveManagedDeviceIdAsync(entraDeviceId, ct);
                if (string.IsNullOrWhiteSpace(managedDeviceId)) { failed++; continue; }
                if (await SendRemediationCommandAsync(managedDeviceId, scriptPolicyId, ct)) sent++;
                else failed++;
            }
        }

        return new(false, $"Push remediation dispatched for group '{payload.GroupName ?? payload.EntraGroupId}'.",
            groupDeviceIds.Count, sent, failed, batches);
    }

    public async Task<PushRemediationDispatchResult> DispatchToDeviceAsync(
        PushRemediationDevicePayload payload, CancellationToken ct = default)
    {
        var scriptPolicyId = _configuration["PushRemediation:ScriptPolicyId"];
        if (string.IsNullOrWhiteSpace(scriptPolicyId))
            return new(true, "PushRemediation:ScriptPolicyId is not configured.", 0, 0, 0, 0);

        var managedDeviceId = await ResolveManagedDeviceIdAsync(payload.EntraDeviceId, ct);
        if (string.IsNullOrWhiteSpace(managedDeviceId))
            return new(false, $"Could not resolve managed device for {payload.EntraDeviceId}.", 1, 0, 1, 0);

        var success = await SendRemediationCommandAsync(managedDeviceId, scriptPolicyId, ct);
        return success
            ? new(false, "Remediation triggered successfully.", 1, 1, 0, 1)
            : new(false, "Failed to send remediation command.", 1, 0, 1, 1);
    }

    private async Task<List<string>> GetGroupDeviceIdsAsync(string groupId, CancellationToken ct)
    {
        var deviceIds = new List<string>();
        var members = await _graph.Groups[groupId].Members.GetAsync(cancellationToken: ct);
        if (members != null)
        {
            var iterator = PageIterator<DirectoryObject, DirectoryObjectCollectionResponse>
                .CreatePageIterator(_graph, members, item =>
                {
                    if (item is Device d && !string.IsNullOrWhiteSpace(d.Id))
                        deviceIds.Add(d.Id);
                    return true;
                });
            await iterator.IterateAsync(ct);
        }
        return deviceIds.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<string?> ResolveManagedDeviceIdAsync(string entraDeviceId, CancellationToken ct)
    {
        try
        {
            var result = await _graph.DeviceManagement.ManagedDevices.GetAsync(config =>
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
                URI = new Uri($"{_graph.RequestAdapter.BaseUrl}/beta/deviceManagement/managedDevices/{managedDeviceId}/initiateOnDemandProactiveRemediation")
            };
            var json = JsonSerializer.Serialize(new { scriptPolicyId });
            request.SetStreamContent(new MemoryStream(Encoding.UTF8.GetBytes(json)), "application/json");
            await _graph.RequestAdapter.SendNoContentAsync(request, cancellationToken: ct);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send remediation command to managed device {ManagedDeviceId}", managedDeviceId);
            return false;
        }
    }
}

/// <summary>Outcome of a privileged dispatch action (mirrors the API record).</summary>
public sealed record PushRemediationDispatchResult(
    bool Skipped,
    string Message,
    int TotalDevices,
    int CommandsSent,
    int CommandsFailed,
    int BatchesProcessed);
