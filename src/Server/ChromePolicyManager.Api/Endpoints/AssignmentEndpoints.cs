using Microsoft.AspNetCore.Mvc;
using ChromePolicyManager.Api.Models;
using ChromePolicyManager.Api.Services;

namespace ChromePolicyManager.Api.Endpoints;

public static class AssignmentEndpoints
{
    public static void MapAssignmentEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/assignments").WithTags("Assignments");

        group.MapGet("/", async (Guid? policySetVersionId, AssignmentService service) =>
        {
            var assignments = await service.GetAssignmentsAsync(policySetVersionId);
            return Results.Ok(assignments);
        }).WithName("GetAssignments");

        group.MapPost("/", async ([FromBody] CreateAssignmentRequest request, AssignmentService service) =>
        {
            try
            {
                var assignment = await service.CreateAssignmentAsync(
                    request.PolicySetVersionId,
                    request.EntraGroupId,
                    request.GroupName,
                    request.Priority,
                    request.Scope,
                    request.PushRemediationEnabled);
                return Results.Created($"/api/assignments/{assignment.Id}", assignment);
            }
            catch (DuplicateAssignmentException ex)
            {
                return Results.Conflict(new { message = ex.Message });
            }
        }).WithName("CreateAssignment");

        group.MapPut("/{id:guid}", async (Guid id, [FromBody] UpdateAssignmentRequest request, AssignmentService service) =>
        {
            var assignment = await service.UpdateAssignmentAsync(id, request.EntraGroupId, request.GroupName, request.Priority, request.Scope);
            return assignment is null ? Results.NotFound() : Results.Ok(assignment);
        }).WithName("UpdateAssignment");

        group.MapPut("/{id:guid}/priority", async (Guid id, [FromBody] UpdatePriorityRequest request, AssignmentService service) =>
        {
            var assignment = await service.UpdatePriorityAsync(id, request.Priority);
            return assignment is null ? Results.NotFound() : Results.Ok(assignment);
        }).WithName("UpdateAssignmentPriority");

        group.MapPut("/{id:guid}/push-remediation", async (Guid id, [FromBody] UpdatePushRemediationRequest request, AssignmentService service) =>
        {
            var assignment = await service.UpdatePushRemediationAsync(id, request.Enabled, request.TriggerNow);
            return assignment is null ? Results.NotFound() : Results.Ok(assignment);
        }).WithName("UpdateAssignmentPushRemediation");

        group.MapPost("/{id:guid}/push-remediation/trigger", async (Guid id, AssignmentService service) =>
        {
            var result = await service.TriggerPushRemediationAsync(id);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }).WithName("TriggerAssignmentPushRemediation");

        group.MapDelete("/{id:guid}", async (Guid id, AssignmentService service) =>
        {
            var deleted = await service.DeleteAssignmentAsync(id);
            return deleted ? Results.NoContent() : Results.NotFound();
        }).WithName("DeleteAssignment");

        // Group search endpoint for autocomplete
        app.MapGet("/api/groups/search", async (string q, int? top, IGraphService graphService) =>
        {
            if (string.IsNullOrWhiteSpace(q) || q.Length < 2)
                return Results.Ok(Array.Empty<object>());
            var groups = await graphService.SearchGroupsAsync(q, top ?? 10);
            return Results.Ok(groups);
        }).WithName("SearchEntraGroups").WithTags("Groups");
    }
}

public record CreateAssignmentRequest(
    Guid PolicySetVersionId,
    string EntraGroupId,
    string GroupName,
    int Priority,
    PolicyScope Scope = PolicyScope.Mandatory,
    bool PushRemediationEnabled = false);

public record UpdatePriorityRequest(int Priority);
public record UpdatePushRemediationRequest(bool Enabled, bool TriggerNow = false);
public record UpdateAssignmentRequest(string? EntraGroupId, string? GroupName, int? Priority, PolicyScope? Scope);
