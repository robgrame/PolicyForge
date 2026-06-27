using Microsoft.AspNetCore.Mvc;
using ChromePolicyManager.Api.Models;
using ChromePolicyManager.Api.Services;

namespace ChromePolicyManager.Api.Endpoints;

public static class PolicyEndpoints
{
    public static void MapPolicyEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/policies").WithTags("Policies");

        group.MapGet("/", async (PolicyService service) =>
        {
            var policies = await service.GetAllPolicySetsAsync();
            return Results.Ok(policies);
        }).WithName("GetAllPolicies");

        group.MapGet("/{id:guid}", async (Guid id, PolicyService service) =>
        {
            var policy = await service.GetPolicySetAsync(id);
            return policy is null ? Results.NotFound() : Results.Ok(policy);
        }).WithName("GetPolicy");

        group.MapPost("/", async ([FromBody] CreatePolicySetRequest request, PolicyService service) =>
        {
            var policy = await service.CreatePolicySetAsync(request.Name, request.Description);
            return Results.Created($"/api/policies/{policy.Id}", policy);
        }).WithName("CreatePolicy");

        group.MapPost("/{id:guid}/versions", async (Guid id, [FromBody] CreateVersionRequest request,
            PolicyService service, ChromePolicyValidator validator) =>
        {
            // Validate policy schema
            var validation = validator.Validate(request.SettingsJson);
            if (!validation.IsValid)
                return Results.BadRequest(new { Errors = validation.Errors, Warnings = validation.Warnings });

            var version = await service.CreateVersionAsync(id, request.Version, request.SettingsJson);
            return Results.Created($"/api/policies/{id}/versions/{version.Id}",
                new { Version = version, Validation = validation.Warnings.Any() ? validation : null });
        }).WithName("CreateVersion");

        group.MapPost("/versions/{versionId:guid}/promote", async (Guid versionId, PolicyService service) =>
        {
            var version = await service.PromoteVersionAsync(versionId);
            return version is null ? Results.NotFound() : Results.Ok(version);
        }).WithName("PromoteVersion");

        group.MapPost("/{policySetId:guid}/rollback/{targetVersionId:guid}", async (
            Guid policySetId, Guid targetVersionId, PolicyService service) =>
        {
            var version = await service.RollbackVersionAsync(policySetId, targetVersionId);
            return version is null ? Results.NotFound() : Results.Ok(version);
        }).WithName("RollbackVersion");

        // Add a single policy setting to the PolicySet's current draft
        group.MapPost("/{policySetId:guid}/add-setting", async (Guid policySetId,
            [FromBody] AddSettingRequest request, PolicyService service) =>
        {
            var result = await service.AddSettingToDraftAsync(policySetId, request.PolicyName, request.Value);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }).WithName("AddSettingToDraft");

        // Get the current draft settings for a PolicySet
        group.MapGet("/{policySetId:guid}/draft-settings", async (Guid policySetId, PolicyService service) =>
        {
            var settings = await service.GetDraftSettingsAsync(policySetId);
            return Results.Ok(settings);
        }).WithName("GetDraftSettings");

        group.MapDelete("/{id:guid}", async (Guid id, PolicyService service, bool? force) =>
        {
            try
            {
                var deleted = await service.DeletePolicySetAsync(id, force ?? false);
                return deleted ? Results.NoContent() : Results.NotFound();
            }
            catch (InvalidOperationException ex)
            {
                return Results.Conflict(new { Error = ex.Message });
            }
        }).WithName("DeletePolicySet");
    }
}

public record CreatePolicySetRequest(string Name, string Description);
public record CreateVersionRequest(string Version, string SettingsJson);
public record AddSettingRequest(string PolicyName, object Value);
