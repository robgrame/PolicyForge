using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;
using ChromePolicyManager.Contracts;

namespace ChromePolicyManager.Api.Services;

public class AssignmentService
{
    private readonly AppDbContext _db;
    private readonly AuditService _audit;
    private readonly PushRemediationService _pushRemediation;
    private readonly ICommandPublisher _commandPublisher;
    private readonly bool _queuedMode;

    public AssignmentService(
        AppDbContext db,
        AuditService audit,
        PushRemediationService pushRemediation,
        ICommandPublisher commandPublisher,
        IConfiguration configuration)
    {
        _db = db;
        _audit = audit;
        _pushRemediation = pushRemediation;
        _commandPublisher = commandPublisher;
        _queuedMode = string.Equals(
            configuration["PrivilegedActions:Mode"], "Queued", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Dispatch push remediation for an assignment. In Inline mode (default) the API performs the
    /// Graph calls directly (legacy behavior). In Queued mode it enqueues a command for the Worker
    /// (ADR-001) and returns a "queued" result so the caller's flow is unchanged.
    /// </summary>
    private async Task<PushRemediationDispatchResult> DispatchAsync(
        PolicyAssignment assignment, string reason, string? actor)
    {
        if (_queuedMode && _commandPublisher.Enabled)
        {
            var payload = new PushRemediationDispatchPayload
            {
                AssignmentId = assignment.Id,
                EntraGroupId = assignment.EntraGroupId,
                GroupName = assignment.GroupName
            };
            var commandId = await _commandPublisher.PublishAsync(
                PrivilegedCommandType.PushRemediationDispatch, payload, actor, reason);
            return new PushRemediationDispatchResult(
                false, $"Push remediation queued (command {commandId}).", 0, 0, 0, 0);
        }

        return await _pushRemediation.DispatchToAssignmentAsync(assignment, reason, actor);
    }

    public async Task<PolicyAssignment> CreateAssignmentAsync(
        Guid policySetVersionId, string entraGroupId, string groupName,
        int priority, PolicyScope scope = PolicyScope.Mandatory,
        bool pushRemediationEnabled = false, string? actor = null)
    {
        // Guard the unique (PolicySetVersionId, EntraGroupId) index with a friendly error
        // instead of letting the SQL duplicate-key violation surface as a raw 500.
        var alreadyAssigned = await _db.PolicyAssignments
            .AnyAsync(a => a.PolicySetVersionId == policySetVersionId && a.EntraGroupId == entraGroupId);
        if (alreadyAssigned)
            throw new DuplicateAssignmentException(groupName);

        var assignment = new PolicyAssignment
        {
            PolicySetVersionId = policySetVersionId,
            EntraGroupId = entraGroupId,
            GroupName = groupName,
            Priority = priority,
            Scope = scope,
            PushRemediationEnabled = pushRemediationEnabled,
            CreatedBy = actor
        };
        _db.PolicyAssignments.Add(assignment);
        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            // Race condition: another request inserted the same pair between the check and the save.
            throw new DuplicateAssignmentException(groupName);
        }
        await _audit.LogAsync("Assignment.Created", actor, "PolicyAssignment", assignment.Id.ToString(),
            $"Group: {groupName}, Priority: {priority}, Scope: {scope}, PushRemediationEnabled: {pushRemediationEnabled}");

        if (pushRemediationEnabled)
        {
            await DispatchAsync(assignment, "Assignment created", actor);
        }
        return assignment;
    }

    public async Task<List<PolicyAssignment>> GetAssignmentsAsync(Guid? policySetVersionId = null)
    {
        var query = _db.PolicyAssignments
            .Include(a => a.PolicySetVersion)
            .ThenInclude(v => v.PolicySet)
            .AsQueryable();

        if (policySetVersionId.HasValue)
            query = query.Where(a => a.PolicySetVersionId == policySetVersionId.Value);

        return await query.OrderBy(a => a.Priority).ToListAsync();
    }

    public async Task<bool> DeleteAssignmentAsync(Guid assignmentId, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return false;

        _db.PolicyAssignments.Remove(assignment);
        await _db.SaveChangesAsync();
        await _audit.LogAsync("Assignment.Deleted", actor, "PolicyAssignment", assignmentId.ToString(),
            $"Group: {assignment.GroupName}");
        return true;
    }

    public async Task<PolicyAssignment?> UpdateAssignmentAsync(
        Guid assignmentId, string? entraGroupId, string? groupName,
        int? priority, PolicyScope? scope, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return null;

        var changes = new List<string>();
        if (entraGroupId != null && entraGroupId != assignment.EntraGroupId)
        {
            changes.Add($"Group: {assignment.GroupName} → {groupName}");
            assignment.EntraGroupId = entraGroupId;
            assignment.GroupName = groupName ?? entraGroupId;
        }
        if (priority.HasValue && priority.Value != assignment.Priority)
        {
            changes.Add($"Priority: {assignment.Priority} → {priority.Value}");
            assignment.Priority = priority.Value;
        }
        if (scope.HasValue && scope.Value != assignment.Scope)
        {
            changes.Add($"Scope: {assignment.Scope} → {scope.Value}");
            assignment.Scope = scope.Value;
        }

        if (changes.Count > 0)
        {
            await _db.SaveChangesAsync();
            await _audit.LogAsync("Assignment.Updated", actor, "PolicyAssignment", assignmentId.ToString(),
                string.Join("; ", changes));
        }
        return assignment;
    }

    public async Task<PolicyAssignment?> UpdatePriorityAsync(Guid assignmentId, int newPriority, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return null;

        var oldPriority = assignment.Priority;
        assignment.Priority = newPriority;
        await _db.SaveChangesAsync();
        await _audit.LogAsync("Assignment.PriorityChanged", actor, "PolicyAssignment", assignmentId.ToString(),
            $"Priority: {oldPriority} → {newPriority}");
        return assignment;
    }

    public async Task<PolicyAssignment?> UpdatePushRemediationAsync(Guid assignmentId, bool enabled, bool triggerNow, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return null;

        assignment.PushRemediationEnabled = enabled;
        await _db.SaveChangesAsync();
        await _audit.LogAsync("Assignment.PushRemediationChanged", actor, "PolicyAssignment", assignmentId.ToString(),
            $"PushRemediationEnabled: {enabled}, TriggerNow: {triggerNow}");

        if (enabled && triggerNow)
        {
            await DispatchAsync(assignment, "Push remediation enabled from assignment management", actor);
        }

        return assignment;
    }

    public async Task<PushRemediationDispatchResult?> TriggerPushRemediationAsync(Guid assignmentId, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return null;
        return await DispatchAsync(assignment, "Manual trigger from assignment management", actor);
    }

    private static bool IsUniqueViolation(DbUpdateException ex) =>
        ex.InnerException is Microsoft.Data.SqlClient.SqlException sql &&
        (sql.Number == 2601 || sql.Number == 2627);
}

/// <summary>
/// Thrown when an Entra group is already assigned to the same policy set version.
/// Mapped to HTTP 409 Conflict by the assignments endpoint.
/// </summary>
public sealed class DuplicateAssignmentException : Exception
{
    public DuplicateAssignmentException(string groupName)
        : base($"Group '{groupName}' is already assigned to this policy version.") { }
}
