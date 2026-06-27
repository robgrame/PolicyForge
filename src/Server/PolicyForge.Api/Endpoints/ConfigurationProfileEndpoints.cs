using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PolicyForge.Api.Data;
using PolicyForge.Api.Models;
using PolicyForge.Api.Providers;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Endpoints;

/// <summary>
/// CRUD for generic <see cref="ConfigurationProfile"/>s, their versions and assignments — the
/// server side of the authoring UI. A profile holds authored items across any provider; a version
/// is an immutable snapshot of those items; an assignment targets a published version at a group.
/// </summary>
public static class ConfigurationProfileEndpoints
{
    public static void MapConfigurationProfileEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/configuration/profiles").WithTags("Configuration Profiles");

        // ---- Profiles -------------------------------------------------------------------------
        group.MapGet("/", async (AppDbContext db) =>
        {
            var profiles = await db.ConfigurationProfiles
                .OrderBy(p => p.Name)
                .Select(p => new
                {
                    p.Id, p.Name, p.Description, p.TargetOs, p.CreatedAt, p.UpdatedAt,
                    VersionCount = db.ConfigurationProfileVersions.Count(v => v.ProfileId == p.Id)
                })
                .ToListAsync();
            return Results.Ok(profiles);
        }).WithName("ListProfiles");

        group.MapGet("/{id:guid}", async (AppDbContext db, Guid id) =>
        {
            var profile = await db.ConfigurationProfiles.FindAsync(id);
            if (profile is null) return Results.NotFound();

            var versions = await db.ConfigurationProfileVersions
                .Where(v => v.ProfileId == id)
                .OrderByDescending(v => v.CreatedAt)
                .Select(v => new { v.Id, v.Version, v.Hash, v.AdmxVersion, v.Status, v.CreatedAt, v.CreatedBy, v.ItemsJson })
                .ToListAsync();

            return Results.Ok(new { profile.Id, profile.Name, profile.Description, profile.TargetOs, profile.CreatedAt, profile.UpdatedAt, Versions = versions });
        }).WithName("GetProfile");

        group.MapPost("/", async (AppDbContext db, ProfileRequest request) =>
        {
            if (string.IsNullOrWhiteSpace(request.Name))
                return Results.BadRequest("Name is required");
            if (await db.ConfigurationProfiles.AnyAsync(p => p.Name == request.Name))
                return Results.Conflict($"A profile named '{request.Name}' already exists");

            var profile = new ConfigurationProfile
            {
                Name = request.Name.Trim(),
                Description = request.Description ?? string.Empty,
                TargetOs = string.IsNullOrWhiteSpace(request.TargetOs) ? null : request.TargetOs
            };
            db.ConfigurationProfiles.Add(profile);
            await db.SaveChangesAsync();
            return Results.Created($"/api/configuration/profiles/{profile.Id}", new { profile.Id });
        }).WithName("CreateProfile");

        group.MapPut("/{id:guid}", async (AppDbContext db, Guid id, ProfileRequest request) =>
        {
            var profile = await db.ConfigurationProfiles.FindAsync(id);
            if (profile is null) return Results.NotFound();

            if (!string.IsNullOrWhiteSpace(request.Name)) profile.Name = request.Name.Trim();
            profile.Description = request.Description ?? profile.Description;
            profile.TargetOs = string.IsNullOrWhiteSpace(request.TargetOs) ? null : request.TargetOs;
            profile.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            return Results.NoContent();
        }).WithName("UpdateProfile");

        group.MapDelete("/{id:guid}", async (AppDbContext db, Guid id) =>
        {
            var profile = await db.ConfigurationProfiles.FindAsync(id);
            if (profile is null) return Results.NotFound();
            db.ConfigurationProfiles.Remove(profile);
            await db.SaveChangesAsync();
            return Results.NoContent();
        }).WithName("DeleteProfile");

        // ---- Versions -------------------------------------------------------------------------

        // Create a new version from authored items. Validates every item against its provider.
        group.MapPost("/{id:guid}/versions", async (AppDbContext db, ConfigurationCompiler compiler, Guid id, VersionRequest request) =>
        {
            var profile = await db.ConfigurationProfiles.FindAsync(id);
            if (profile is null) return Results.NotFound();

            var items = request.Items ?? new List<ConfigurationItem>();
            var errors = compiler.Validate(items);
            if (errors.Count > 0)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["items"] = errors.ToArray() });

            var version = string.IsNullOrWhiteSpace(request.Version) ? NextVersion(db, id) : request.Version!.Trim();
            if (await db.ConfigurationProfileVersions.AnyAsync(v => v.ProfileId == id && v.Version == version))
                return Results.Conflict($"Version '{version}' already exists for this profile");

            var itemsJson = JsonSerializer.Serialize(items, ConfigurationJson.Options);
            var entity = new ConfigurationProfileVersion
            {
                ProfileId = id,
                Version = version,
                ItemsJson = itemsJson,
                Hash = Sha256(itemsJson),
                AdmxVersion = request.AdmxVersion,
                Status = PolicyVersionStatus.Draft,
                CreatedBy = request.CreatedBy
            };
            db.ConfigurationProfileVersions.Add(entity);
            profile.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            return Results.Created($"/api/configuration/profiles/{id}/versions/{entity.Id}", new { entity.Id, entity.Version, entity.Hash });
        }).WithName("CreateProfileVersion");

        // Publish a draft version -> Active (and archive any previously-active version).
        group.MapPost("/versions/{versionId:guid}/publish", async (AppDbContext db, Guid versionId) =>
        {
            var version = await db.ConfigurationProfileVersions.FindAsync(versionId);
            if (version is null) return Results.NotFound();

            var previouslyActive = await db.ConfigurationProfileVersions
                .Where(v => v.ProfileId == version.ProfileId && v.Status == PolicyVersionStatus.Active && v.Id != versionId)
                .ToListAsync();
            foreach (var v in previouslyActive) v.Status = PolicyVersionStatus.Archived;

            version.Status = PolicyVersionStatus.Active;
            await db.SaveChangesAsync();
            return Results.NoContent();
        }).WithName("PublishProfileVersion");

        // ---- Assignments ----------------------------------------------------------------------
        group.MapGet("/versions/{versionId:guid}/assignments", async (AppDbContext db, Guid versionId) =>
        {
            var assignments = await db.ConfigurationAssignments
                .Where(a => a.ProfileVersionId == versionId)
                .OrderBy(a => a.Priority)
                .Select(a => new { a.Id, a.EntraGroupId, a.GroupName, a.Priority, a.Enabled, a.CreatedAt })
                .ToListAsync();
            return Results.Ok(assignments);
        }).WithName("ListProfileAssignments");

        group.MapPost("/versions/{versionId:guid}/assignments", async (AppDbContext db, Guid versionId, AssignmentRequest request) =>
        {
            var version = await db.ConfigurationProfileVersions.FindAsync(versionId);
            if (version is null) return Results.NotFound();
            if (string.IsNullOrWhiteSpace(request.EntraGroupId))
                return Results.BadRequest("entraGroupId is required");
            if (await db.ConfigurationAssignments.AnyAsync(a => a.ProfileVersionId == versionId && a.EntraGroupId == request.EntraGroupId))
                return Results.Conflict("This group is already assigned to this version");

            var assignment = new ConfigurationAssignment
            {
                ProfileVersionId = versionId,
                EntraGroupId = request.EntraGroupId.Trim(),
                GroupName = request.GroupName ?? string.Empty,
                Priority = request.Priority ?? 100,
                Enabled = request.Enabled ?? true,
                CreatedBy = request.CreatedBy
            };
            db.ConfigurationAssignments.Add(assignment);
            await db.SaveChangesAsync();
            return Results.Created($"/api/configuration/profiles/assignments/{assignment.Id}", new { assignment.Id });
        }).WithName("CreateProfileAssignment");

        group.MapDelete("/assignments/{assignmentId:guid}", async (AppDbContext db, Guid assignmentId) =>
        {
            var assignment = await db.ConfigurationAssignments.FindAsync(assignmentId);
            if (assignment is null) return Results.NotFound();
            db.ConfigurationAssignments.Remove(assignment);
            await db.SaveChangesAsync();
            return Results.NoContent();
        }).WithName("DeleteProfileAssignment");
    }

    private static string NextVersion(AppDbContext db, Guid profileId)
    {
        var count = db.ConfigurationProfileVersions.Count(v => v.ProfileId == profileId);
        return $"1.0.{count}";
    }

    private static string Sha256(string content)
        => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    public sealed record ProfileRequest(string? Name, string? Description, string? TargetOs);

    public sealed record VersionRequest
    {
        public string? Version { get; init; }
        public string? AdmxVersion { get; init; }
        public string? CreatedBy { get; init; }
        public List<ConfigurationItem>? Items { get; init; }
    }

    public sealed record AssignmentRequest
    {
        public string EntraGroupId { get; init; } = string.Empty;
        public string? GroupName { get; init; }
        public int? Priority { get; init; }
        public bool? Enabled { get; init; }
        public string? CreatedBy { get; init; }
    }
}
