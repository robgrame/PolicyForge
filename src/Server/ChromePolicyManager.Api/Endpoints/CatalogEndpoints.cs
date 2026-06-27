using System.IO.Compression;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;
using ChromePolicyManager.Api.Services;
using Microsoft.EntityFrameworkCore;

namespace ChromePolicyManager.Api.Endpoints;

public static class CatalogEndpoints
{
    public static void MapCatalogEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/catalog").WithTags("Policy Catalog");

        // GET /api/catalog - Get all catalog entries (lightweight, no description/enum)
        group.MapGet("/", async (AppDbContext db, string? category, string? dataType, string? search, bool? recommended) =>
        {
            var query = db.PolicyCatalog.AsQueryable();

            if (!string.IsNullOrEmpty(category))
                query = query.Where(e => e.Category == category);

            if (!string.IsNullOrEmpty(dataType))
                query = query.Where(e => e.DataType == dataType);

            if (recommended.HasValue)
                query = query.Where(e => e.IsRecommended == recommended.Value);

            if (!string.IsNullOrEmpty(search))
                query = query.Where(e =>
                    e.Name.Contains(search) ||
                    e.DisplayName.Contains(search) ||
                    e.Description.Contains(search));

            var entries = await query
                .OrderBy(e => e.Category).ThenBy(e => e.Name)
                .Select(e => new
                {
                    e.Id, e.Name, e.DisplayName, e.Category,
                    e.DataType, e.IsRecommended, e.PolicyClass,
                    e.RegistryKey, e.RegistryValueName
                })
                .ToListAsync();
            return Results.Ok(entries);
        }).WithName("GetCatalog");

        // GET /api/catalog/{id} - Get full details for a single policy
        group.MapGet("/{id:guid}", async (AppDbContext db, Guid id) =>
        {
            var entry = await db.PolicyCatalog.FindAsync(id);
            return entry is not null ? Results.Ok(entry) : Results.NotFound();
        }).WithName("GetCatalogEntry");

        // GET /api/catalog/categories - Get distinct categories
        group.MapGet("/categories", async (AppDbContext db) =>
        {
            var categories = await db.PolicyCatalog
                .Where(e => !e.IsRecommended)
                .Select(e => e.Category)
                .Distinct()
                .OrderBy(c => c)
                .ToListAsync();
            return Results.Ok(categories);
        }).WithName("GetCatalogCategories");


        // GET /api/catalog/stats - Import statistics
        group.MapGet("/stats", async (AppDbContext db) =>
        {
            var total = await db.PolicyCatalog.CountAsync();
            var mandatory = await db.PolicyCatalog.CountAsync(e => !e.IsRecommended);
            var recommended = await db.PolicyCatalog.CountAsync(e => e.IsRecommended);
            var categories = await db.PolicyCatalog.Where(e => !e.IsRecommended).Select(e => e.Category).Distinct().CountAsync();
            var version = await db.PolicyCatalog.Select(e => e.TemplateVersion).FirstOrDefaultAsync() ?? "none";

            return Results.Ok(new
            {
                TotalEntries = total,
                MandatoryPolicies = mandatory,
                RecommendedPolicies = recommended,
                Categories = categories,
                TemplateVersion = version,
                LastImport = await db.PolicyCatalog.MaxAsync(e => (DateTime?)e.ImportedAt)
            });
        }).WithName("GetCatalogStats");

        // POST /api/catalog/import - Import from ADMX zip upload
        group.MapPost("/import", async (HttpRequest request, AppDbContext db, AdmxParserService parser) =>
        {
            if (!request.HasFormContentType)
                return Results.BadRequest("Expected multipart/form-data with ADMX zip file");

            var form = await request.ReadFormAsync();
            var file = form.Files.GetFile("admxZip") ?? form.Files.FirstOrDefault();

            if (file is null || file.Length == 0)
                return Results.BadRequest("No file uploaded. Upload a zip containing chrome.admx + en-US/chrome.adml");

            var version = form["version"].FirstOrDefault() ?? "unknown";
            var diffMode = form["diffMode"].FirstOrDefault()?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false;

            using var zipStream = file.OpenReadStream();
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

            // Find chrome.admx and chrome.adml in the zip
            var admxEntry = archive.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("chrome.admx", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains("__MACOSX"));
            var admlEntry = archive.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("chrome.adml", StringComparison.OrdinalIgnoreCase) &&
                e.FullName.Contains("en-US", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains("__MACOSX"));

            if (admxEntry is null)
                return Results.BadRequest("chrome.admx not found in zip");
            if (admlEntry is null)
                return Results.BadRequest("en-US/chrome.adml not found in zip");

            // Prefer the real version embedded in the zip's root VERSION file;
            // fall back to whatever the user typed in the "Version Label" field.
            var effectiveVersion = ResolveVersion(version, ExtractVersionFromArchive(archive));

            using var admxStream = admxEntry.Open();
            using var admlStream = admlEntry.Open();

            var result = parser.Parse(admxStream, admlStream, effectiveVersion);
            var importResult = await ApplyImport(db, result, diffMode);
            return Results.Ok(importResult);
        }).WithName("ImportCatalog")
        .DisableAntiforgery();

        // POST /api/catalog/import-from-url - Download ADMX directly from Google and import
        group.MapPost("/import-from-url", async (string? version, bool? diffMode, AppDbContext db, AdmxParserService parser, IHttpClientFactory httpFactory) =>
        {
            var googleAdmxUrl = "https://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip";
            var useDiff = diffMode ?? false;

            using var httpClient = httpFactory.CreateClient();
            httpClient.Timeout = TimeSpan.FromMinutes(5);

            HttpResponseMessage response;
            try
            {
                response = await httpClient.GetAsync(googleAdmxUrl);
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                return Results.Problem($"Failed to download from Google: {ex.Message}");
            }

            using var zipStream = await response.Content.ReadAsStreamAsync();
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

            var admxEntry = archive.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("chrome.admx", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains("__MACOSX"));
            var admlEntry = archive.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("chrome.adml", StringComparison.OrdinalIgnoreCase) &&
                e.FullName.Contains("en-US", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains("__MACOSX"));

            if (admxEntry is null)
                return Results.BadRequest("chrome.admx not found in downloaded zip");
            if (admlEntry is null)
                return Results.BadRequest("en-US/chrome.adml not found in downloaded zip");

            using var admxStream = admxEntry.Open();
            using var admlStream = admlEntry.Open();

            // Prefer the real version embedded in the zip's root VERSION file.
            var effectiveVersion = ResolveVersion(version, ExtractVersionFromArchive(archive));

            var result = parser.Parse(admxStream, admlStream, effectiveVersion);
            var importResult = await ApplyImport(db, result, useDiff);
            return Results.Ok(importResult);
        }).WithName("ImportCatalogFromUrl")
        .DisableAntiforgery();

        // POST /api/catalog/import-local - Import from server-local ADMX files (for CLI/automation)
        group.MapPost("/import-local", async (ImportLocalRequest request, AppDbContext db, AdmxParserService parser) =>
        {
            if (!File.Exists(request.AdmxPath))
                return Results.BadRequest($"ADMX file not found: {request.AdmxPath}");
            if (!File.Exists(request.AdmlPath))
                return Results.BadRequest($"ADML file not found: {request.AdmlPath}");

            using var admxStream = File.OpenRead(request.AdmxPath);
            using var admlStream = File.OpenRead(request.AdmlPath);

            var result = parser.Parse(admxStream, admlStream, request.Version ?? "local");
            var importResult = await ApplyImport(db, result, false);
            return Results.Ok(importResult);
        }).WithName("ImportCatalogLocal");

        // GET /api/catalog/latest-available - Compare the imported catalog version
        // against the latest stable Chrome version published by Google, so the UI
        // can surface an "update available" hint and offer a one-click re-import.
        group.MapGet("/latest-available", async (AppDbContext db, IHttpClientFactory httpFactory) =>
        {
            var imported = await db.PolicyCatalog
                .Select(e => e.TemplateVersion)
                .FirstOrDefaultAsync();

            string? latest = null;
            string? error = null;
            try
            {
                using var http = httpFactory.CreateClient();
                http.Timeout = TimeSpan.FromSeconds(20);
                // Chrome VersionHistory API — latest stable release for Windows.
                const string url = "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions?order_by=version%20desc&pageSize=1";
                using var doc = System.Text.Json.JsonDocument.Parse(await http.GetStringAsync(url));
                if (doc.RootElement.TryGetProperty("versions", out var versions) &&
                    versions.GetArrayLength() > 0 &&
                    versions[0].TryGetProperty("version", out var v))
                {
                    latest = v.GetString();
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }

            return Results.Ok(new
            {
                Imported = string.IsNullOrWhiteSpace(imported) ? null : imported,
                Latest = latest,
                UpdateAvailable = IsNewer(latest, imported),
                Error = error
            });
        }).WithName("GetLatestAvailableVersion");
    }

    /// <summary>
    /// Picks the version to store: the user-supplied label wins when it is a real
    /// value, otherwise we fall back to the version detected inside the zip.
    /// </summary>
    private static string ResolveVersion(string? userSupplied, string? detected)
    {
        var u = userSupplied?.Trim();
        bool userIsPlaceholder = string.IsNullOrWhiteSpace(u) ||
            u.Equals("unknown", StringComparison.OrdinalIgnoreCase) ||
            u.Equals("latest", StringComparison.OrdinalIgnoreCase);

        if (!userIsPlaceholder)
            return u!;
        return !string.IsNullOrWhiteSpace(detected) ? detected! : (u ?? "unknown");
    }

    /// <summary>
    /// Reads the root VERSION file shipped inside Google's policy_templates.zip and
    /// turns the MAJOR/MINOR/BUILD/PATCH key-value pairs into a dotted version string
    /// (e.g. "149.0.7827.197"). Returns null when no usable VERSION file is present.
    /// </summary>
    private static string? ExtractVersionFromArchive(ZipArchive archive)
    {
        var versionEntry = archive.Entries.FirstOrDefault(e =>
            e.Name.Equals("VERSION", StringComparison.OrdinalIgnoreCase) &&
            !e.FullName.Contains("__MACOSX"));
        if (versionEntry is null)
            return null;

        try
        {
            using var reader = new StreamReader(versionEntry.Open());
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                var idx = line.IndexOf('=');
                if (idx <= 0) continue;
                map[line[..idx].Trim()] = line[(idx + 1)..].Trim();
            }

            if (map.TryGetValue("MAJOR", out var major) && !string.IsNullOrEmpty(major))
            {
                map.TryGetValue("MINOR", out var minor);
                map.TryGetValue("BUILD", out var build);
                map.TryGetValue("PATCH", out var patch);
                return $"{major}.{minor ?? "0"}.{build ?? "0"}.{patch ?? "0"}";
            }
        }
        catch
        {
            // Malformed VERSION file — treat as not present.
        }
        return null;
    }

    /// <summary>
    /// Returns true when <paramref name="latest"/> represents a newer release than
    /// <paramref name="imported"/>. Compares as dotted numeric versions when possible,
    /// otherwise falls back to a case-insensitive string difference.
    /// </summary>
    private static bool IsNewer(string? latest, string? imported)
    {
        if (string.IsNullOrWhiteSpace(latest)) return false;
        if (string.IsNullOrWhiteSpace(imported)) return true;

        if (Version.TryParse(latest, out var l) && Version.TryParse(imported, out var i))
            return l > i;

        // Fall back to comparing leading major numbers, then raw strings.
        if (int.TryParse(latest.Split('.')[0], out var lm) &&
            int.TryParse(imported.Split('.')[0], out var im))
            return lm > im;

        return !string.Equals(latest, imported, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Applies parsed ADMX entries to the database, supporting both full replace and differential mode.
    /// Differential mode (inspired by ADMxSqueezer): compares existing catalog entries by policy name
    /// and only adds new policies, updates changed policies, and optionally removes deprecated ones.
    /// </summary>
    private static async Task<object> ApplyImport(AppDbContext db, AdmxParserService.AdmxParseResult result, bool diffMode)
    {
        int added = 0, updated = 0, removed = 0;

        if (!diffMode)
        {
            // Full replace mode — deduplicate by Name+IsRecommended before inserting
            db.PolicyCatalog.RemoveRange(db.PolicyCatalog);
            var deduped = result.Entries
                .GroupBy(e => $"{e.Name}|{e.IsRecommended}", StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .ToList();
            await db.PolicyCatalog.AddRangeAsync(deduped);
            await db.SaveChangesAsync();
            added = deduped.Count;
        }
        else
        {
            // Differential mode — only add/update/remove differences
            // Key includes scope (IsRecommended) since same policy name can exist in both mandatory+recommended
            var existingEntries = await db.PolicyCatalog.ToListAsync();
            var existingByKey = new Dictionary<string, PolicyCatalogEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in existingEntries)
            {
                var key = $"{e.Name}|{e.IsRecommended}";
                existingByKey.TryAdd(key, e); // keep first if duplicates exist in DB
            }
            var newByKey = new Dictionary<string, PolicyCatalogEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in result.Entries)
            {
                var key = $"{e.Name}|{e.IsRecommended}";
                newByKey.TryAdd(key, e); // skip true duplicates
            }

            // Find new policies (in new ADMX but not in existing catalog)
            var toAdd = result.Entries
                .Where(e => !existingByKey.ContainsKey($"{e.Name}|{e.IsRecommended}"))
                .GroupBy(e => $"{e.Name}|{e.IsRecommended}")
                .Select(g => g.First())
                .ToList();

            // Find removed policies (in existing catalog but not in new ADMX)
            var toRemove = existingEntries
                .Where(e => !newByKey.ContainsKey($"{e.Name}|{e.IsRecommended}"))
                .ToList();

            // Find updated policies (exist in both but have different content)
            var toUpdate = new List<PolicyCatalogEntry>();
            foreach (var kvp in newByKey)
            {
                if (existingByKey.TryGetValue(kvp.Key, out var existing))
                {
                    var newEntry = kvp.Value;
                    if (existing.DisplayName != newEntry.DisplayName ||
                        existing.Description != newEntry.Description ||
                        existing.DataType != newEntry.DataType ||
                        existing.EnumOptions != newEntry.EnumOptions ||
                        existing.RegistryKey != newEntry.RegistryKey ||
                        existing.RegistryValueName != newEntry.RegistryValueName)
                    {
                        existing.DisplayName = newEntry.DisplayName;
                        existing.Description = newEntry.Description;
                        existing.DataType = newEntry.DataType;
                        existing.EnumOptions = newEntry.EnumOptions;
                        existing.RegistryKey = newEntry.RegistryKey;
                        existing.RegistryValueName = newEntry.RegistryValueName;
                        existing.SupportedOn = newEntry.SupportedOn;
                        existing.PolicyClass = newEntry.PolicyClass;
                        existing.TemplateVersion = newEntry.TemplateVersion;
                        existing.ImportedAt = DateTime.UtcNow;
                        toUpdate.Add(existing);
                    }
                }
            }

            // Apply changes
            if (toRemove.Count > 0) db.PolicyCatalog.RemoveRange(toRemove);
            if (toAdd.Count > 0) await db.PolicyCatalog.AddRangeAsync(toAdd);
            await db.SaveChangesAsync();

            added = toAdd.Count;
            updated = toUpdate.Count;
            removed = toRemove.Count;
        }

        var totalMandatory = await db.PolicyCatalog.CountAsync(e => !e.IsRecommended);
        var totalRecommended = await db.PolicyCatalog.CountAsync(e => e.IsRecommended);
        var totalCategories = await db.PolicyCatalog.Where(e => !e.IsRecommended).Select(e => e.Category).Distinct().CountAsync();

        return new
        {
            Message = diffMode
                ? $"Differential import: +{added} added, ~{updated} updated, -{removed} removed"
                : $"Imported {result.TotalParsed} policy definitions",
            result.TemplateVersion,
            result.TotalParsed,
            Mandatory = totalMandatory,
            Recommended = totalRecommended,
            Categories = totalCategories,
            Added = added,
            Updated = updated,
            Removed = removed,
            result.Warnings
        };
    }
}

public record ImportLocalRequest(string AdmxPath, string AdmlPath, string? Version);
