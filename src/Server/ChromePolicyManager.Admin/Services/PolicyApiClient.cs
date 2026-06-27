using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ChromePolicyManager.Admin.Services;

public class PolicyApiClient
{
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public PolicyApiClient(HttpClient http) => _http = http;

    // === Policies ===
    public async Task<List<PolicySetDto>> GetPoliciesAsync()
    {
        var response = await _http.GetAsync("/api/policies");
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<List<PolicySetDto>>(json, JsonOptions) ?? [];
    }

    public async Task<PolicySetDto> CreatePolicySetAsync(string name, string description)
    {
        var response = await _http.PostAsJsonAsync("/api/policies", new { name, description });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<PolicySetDto>(JsonOptions))!;
    }

    public async Task<VersionResponseDto> CreateVersionAsync(Guid policySetId, string version, string settingsJson)
    {
        var response = await _http.PostAsJsonAsync($"/api/policies/{policySetId}/versions", 
            new { version, settingsJson });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VersionResponseDto>(JsonOptions))!;
    }

    public async Task<PolicySetVersionDto> PromoteVersionAsync(Guid versionId)
    {
        var response = await _http.PostAsync($"/api/policies/versions/{versionId}/promote", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<PolicySetVersionDto>(JsonOptions))!;
    }

    public async Task<PolicySetVersionDto> RollbackVersionAsync(Guid policySetId, Guid targetVersionId)
    {
        var response = await _http.PostAsync($"/api/policies/{policySetId}/rollback/{targetVersionId}", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<PolicySetVersionDto>(JsonOptions))!;
    }

    public async Task DeletePolicySetAsync(Guid id, bool force = false)
    {
        var url = force ? $"/api/policies/{id}?force=true" : $"/api/policies/{id}";
        var response = await _http.DeleteAsync(url);
        if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
        {
            var error = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException(error);
        }
        response.EnsureSuccessStatusCode();
    }

    // === Assignments ===
    public async Task<List<AssignmentDto>> GetAssignmentsAsync()
    {
        return await _http.GetFromJsonAsync<List<AssignmentDto>>("/api/assignments", JsonOptions) ?? [];
    }

    public async Task<AssignmentDto> CreateAssignmentAsync(Guid policySetVersionId, string entraGroupId, 
        string groupName, int priority, int scope, bool pushRemediationEnabled)
    {
        var response = await _http.PostAsJsonAsync("/api/assignments", new
        {
            policySetVersionId, entraGroupId, groupName, priority, scope, pushRemediationEnabled
        });
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(await ExtractErrorMessageAsync(response));
        return (await response.Content.ReadFromJsonAsync<AssignmentDto>(JsonOptions))!;
    }

    private static async Task<string> ExtractErrorMessageAsync(HttpResponseMessage response)
    {
        try
        {
            var doc = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
            if (doc.ValueKind == System.Text.Json.JsonValueKind.Object &&
                doc.TryGetProperty("message", out var msg) &&
                msg.ValueKind == System.Text.Json.JsonValueKind.String)
            {
                return msg.GetString()!;
            }
        }
        catch { /* body wasn't JSON with a message field */ }
        return $"Request failed ({(int)response.StatusCode} {response.ReasonPhrase}).";
    }

    public async Task<AssignmentDto> UpdateAssignmentAsync(Guid assignmentId, string? entraGroupId, 
        string? groupName, int? priority, int? scope)
    {
        var response = await _http.PutAsJsonAsync($"/api/assignments/{assignmentId}", new
        {
            entraGroupId, groupName, priority, scope
        });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<AssignmentDto>(JsonOptions))!;
    }

    public async Task<AssignmentDto> UpdateAssignmentPushRemediationAsync(Guid assignmentId, bool enabled, bool triggerNow)
    {
        var response = await _http.PutAsJsonAsync($"/api/assignments/{assignmentId}/push-remediation", new
        {
            enabled, triggerNow
        });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<AssignmentDto>(JsonOptions))!;
    }

    public async Task<PushRemediationDispatchResultDto> TriggerAssignmentPushRemediationAsync(Guid assignmentId)
    {
        var response = await _http.PostAsync($"/api/assignments/{assignmentId}/push-remediation/trigger", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<PushRemediationDispatchResultDto>(JsonOptions))!;
    }

    public async Task DeleteAssignmentAsync(Guid id)
    {
        var response = await _http.DeleteAsync($"/api/assignments/{id}");
        response.EnsureSuccessStatusCode();
    }

    // === Monitoring ===
    public async Task<MonitoringDashboardDto> GetDashboardAsync()
    {
        return await _http.GetFromJsonAsync<MonitoringDashboardDto>("/api/monitoring/dashboard", JsonOptions) 
            ?? new MonitoringDashboardDto();
    }

    public async Task<List<DeviceStateDto>> GetOfflineDevicesAsync(int hours = 24)
    {
        return await _http.GetFromJsonAsync<List<DeviceStateDto>>($"/api/monitoring/offline?hours={hours}", JsonOptions) ?? [];
    }

    public async Task<List<DeviceStateDto>> GetErrorDevicesAsync()
    {
        return await _http.GetFromJsonAsync<List<DeviceStateDto>>("/api/monitoring/errors", JsonOptions) ?? [];
    }

    public async Task<PushRemediationDispatchResultDto> TriggerDeviceRemediationAsync(string deviceId)
    {
        var response = await _http.PostAsync($"/api/monitoring/devices/{deviceId}/trigger-remediation", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<PushRemediationDispatchResultDto>(JsonOptions))!;
    }

    // === Catalog ===
    public async Task<List<PolicyCatalogEntryDto>> GetCatalogAsync(string? category = null, string? search = null, bool? recommended = null)
    {
        var query = new List<string>();
        if (!string.IsNullOrEmpty(category)) query.Add($"category={Uri.EscapeDataString(category)}");
        if (!string.IsNullOrEmpty(search)) query.Add($"search={Uri.EscapeDataString(search)}");
        if (recommended.HasValue) query.Add($"recommended={recommended.Value}");
        var qs = query.Count > 0 ? "?" + string.Join("&", query) : "";
        return await _http.GetFromJsonAsync<List<PolicyCatalogEntryDto>>($"/api/catalog{qs}", JsonOptions) ?? [];
    }

    public async Task<PolicyCatalogEntryDto?> GetCatalogEntryAsync(Guid id)
    {
        return await _http.GetFromJsonAsync<PolicyCatalogEntryDto>($"/api/catalog/{id}", JsonOptions);
    }

    public async Task<List<string>> GetCatalogCategoriesAsync()
    {
        return await _http.GetFromJsonAsync<List<string>>("/api/catalog/categories", JsonOptions) ?? [];
    }

    public async Task<CatalogStatsDto> GetCatalogStatsAsync()
    {
        return await _http.GetFromJsonAsync<CatalogStatsDto>("/api/catalog/stats", JsonOptions) ?? new();
    }

    public async Task<LatestVersionDto> GetLatestAvailableVersionAsync()
    {
        return await _http.GetFromJsonAsync<LatestVersionDto>("/api/catalog/latest-available", JsonOptions) ?? new();
    }

    public async Task<CatalogImportResultDto> ImportCatalogAsync(Stream zipStream, string fileName, string version, bool diffMode = false)
    {
        using var content = new MultipartFormDataContent();
        content.Add(new StreamContent(zipStream), "admxZip", fileName);
        content.Add(new StringContent(version), "version");
        content.Add(new StringContent(diffMode.ToString().ToLower()), "diffMode");
        var response = await _http.PostAsync("/api/catalog/import", content);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<CatalogImportResultDto>(JsonOptions))!;
    }

    public async Task<CatalogImportResultDto> ImportCatalogFromUrlAsync(string version, bool diffMode = false)
    {
        var url = $"/api/catalog/import-from-url?version={Uri.EscapeDataString(version)}&diffMode={diffMode.ToString().ToLower()}";
        var response = await _http.PostAsync(url, null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<CatalogImportResultDto>(JsonOptions))!;
    }

    // === PolicySet Settings ===
    public async Task AddSettingToDraftAsync(Guid policySetId, string policyName, object value)
    {
        var response = await _http.PostAsJsonAsync($"/api/policies/{policySetId}/add-setting", 
            new { policyName, value });
        response.EnsureSuccessStatusCode();
    }

    // === Groups ===
    public async Task<List<EntraGroupDto>> SearchGroupsAsync(string query)
    {
        if (string.IsNullOrWhiteSpace(query) || query.Length < 2)
            return [];
        return await _http.GetFromJsonAsync<List<EntraGroupDto>>(
            $"/api/groups/search?q={Uri.EscapeDataString(query)}", JsonOptions) ?? [];
    }

    // === Client certificate trust configuration ===
    public async Task<ClientCertConfigDto> GetClientCertConfigAsync()
    {
        return await _http.GetFromJsonAsync<ClientCertConfigDto>("/api/config/clientcert", JsonOptions) ?? new();
    }

    public async Task SaveClientCertConfigAsync(ClientCertConfigDto config)
    {
        var response = await _http.PutAsJsonAsync("/api/config/clientcert", config);
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            throw new HttpRequestException($"Save failed ({(int)response.StatusCode}): {body}");
        }
    }
}

// === DTOs ===
public class PolicySetDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public List<PolicySetVersionDto> Versions { get; set; } = [];
}

public class PolicySetVersionDto
{
    public Guid Id { get; set; }
    public Guid PolicySetId { get; set; }
    public string Version { get; set; } = "";
    public string? AdmxVersion { get; set; }
    public string SettingsJson { get; set; } = "{}";
    public string Hash { get; set; } = "";
    public PolicyVersionStatus Status { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class VersionResponseDto
{
    public PolicySetVersionDto? Version { get; set; }
    public ValidationResultDto? Validation { get; set; }
}

public class ValidationResultDto
{
    public bool IsValid { get; set; }
    public List<string> Errors { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
}

public enum PolicyVersionStatus { Draft, Active, Archived }

public enum PolicyScope { Mandatory = 0, Recommended = 1 }

public class AssignmentDto
{
    public Guid Id { get; set; }
    public Guid PolicySetVersionId { get; set; }
    public string EntraGroupId { get; set; } = "";
    public string GroupName { get; set; } = "";
    public int Priority { get; set; }
    public PolicyScope Scope { get; set; } // serialized by the API as "Mandatory"/"Recommended"
    public bool Enabled { get; set; }
    public bool PushRemediationEnabled { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class PushRemediationDispatchResultDto
{
    public bool Skipped { get; set; }
    public string Message { get; set; } = "";
    public int TotalDevices { get; set; }
    public int CommandsSent { get; set; }
    public int CommandsFailed { get; set; }
    public int BatchesProcessed { get; set; }
}

public class MonitoringDashboardDto
{
    public int TotalDevices { get; set; }
    public int CompliantDevices { get; set; }
    public int NonCompliantDevices { get; set; }
    public int ErrorDevices { get; set; }
    public int OfflineDevices { get; set; }
    public List<DeviceStateDto> RecentReports { get; set; } = [];
}

public class DeviceStateDto
{
    public string DeviceId { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public string Status { get; set; } = "";
    public string? AppliedPolicyHash { get; set; }
    public string? Errors { get; set; }
    public string? ChromeVersion { get; set; }
    public string? OsVersion { get; set; }
    public string? OsBuild { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? ScriptVersion { get; set; }
    public DateTime LastContact { get; set; }
    public int PolicyKeysWritten { get; set; }
    public int PolicyKeysRemoved { get; set; }
}

public class PolicyCatalogEntryDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Description { get; set; } = "";
    public string Category { get; set; } = "";
    public string DataType { get; set; } = "";
    public string RegistryKey { get; set; } = "";
    public string RegistryValueName { get; set; } = "";
    public bool IsRecommended { get; set; }
    public string SupportedOn { get; set; } = "";
    public string? EnumOptions { get; set; }
    public string PolicyClass { get; set; } = "";
    public string TemplateVersion { get; set; } = "";
    public DateTime ImportedAt { get; set; }
}

public class CatalogStatsDto
{
    public int TotalEntries { get; set; }
    public int MandatoryPolicies { get; set; }
    public int RecommendedPolicies { get; set; }
    public int Categories { get; set; }
    public string TemplateVersion { get; set; } = "";
    public DateTime? LastImport { get; set; }
}

public class LatestVersionDto
{
    public string? Imported { get; set; }
    public string? Latest { get; set; }
    public bool UpdateAvailable { get; set; }
    public string? Error { get; set; }
}

public class CatalogImportResultDto
{
    public string Message { get; set; } = "";
    public string TemplateVersion { get; set; } = "";
    public int TotalParsed { get; set; }
    public int Mandatory { get; set; }
    public int Recommended { get; set; }
    public int Categories { get; set; }
    public int Added { get; set; }
    public int Removed { get; set; }
    public int Updated { get; set; }
    public List<string> Warnings { get; set; } = [];
}

public class EntraGroupDto
{
    public string Id { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string? Description { get; set; }
    public string? GroupType { get; set; }
}

public class AddToPolicySetResult
{
    public PolicySetDto PolicySet { get; set; } = default!;
    public object Value { get; set; } = default!;
}

public class ClientCertConfigDto
{
    public bool Enabled { get; set; }
    public bool CheckRevocation { get; set; }
    public string RevocationMode { get; set; } = "Online";
    public bool BackingStoreAvailable { get; set; }
    public List<CaCertificateDto> Certificates { get; set; } = [];
}

public class CaCertificateDto
{
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string Thumbprint { get; set; } = "";
    public string Base64 { get; set; } = "";
    public bool IsRoot { get; set; }
    public DateTime NotAfter { get; set; }
}
