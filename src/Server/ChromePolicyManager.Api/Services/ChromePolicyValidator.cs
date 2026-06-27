using System.Text.Json;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Validates Chrome policy settings against known policy schema.
/// Ensures correct types and value constraints for Chrome registry policies.
/// </summary>
public class ChromePolicyValidator
{
    // Known Chrome policy types (subset - extensible)
    private static readonly Dictionary<string, ChromePolicyType> KnownPolicies = new(StringComparer.OrdinalIgnoreCase)
    {
        // Boolean policies
        ["AutofillAddressEnabled"] = ChromePolicyType.Boolean,
        ["AutofillCreditCardEnabled"] = ChromePolicyType.Boolean,
        ["BookmarkBarEnabled"] = ChromePolicyType.Boolean,
        ["BrowserSignin"] = ChromePolicyType.Integer,
        ["DefaultBrowserSettingEnabled"] = ChromePolicyType.Boolean,
        ["DeveloperToolsAvailability"] = ChromePolicyType.Integer,
        ["DNSInterceptionChecksEnabled"] = ChromePolicyType.Boolean,
        ["EnableMediaRouter"] = ChromePolicyType.Boolean,
        ["HomepageIsNewTabPage"] = ChromePolicyType.Boolean,
        ["IncognitoModeAvailability"] = ChromePolicyType.Integer,
        ["MetricsReportingEnabled"] = ChromePolicyType.Boolean,
        ["PasswordManagerEnabled"] = ChromePolicyType.Boolean,
        ["SafeBrowsingEnabled"] = ChromePolicyType.Boolean,
        ["SafeBrowsingProtectionLevel"] = ChromePolicyType.Integer,
        ["SearchSuggestEnabled"] = ChromePolicyType.Boolean,
        ["ShowHomeButton"] = ChromePolicyType.Boolean,
        ["SyncDisabled"] = ChromePolicyType.Boolean,
        ["TranslateEnabled"] = ChromePolicyType.Boolean,

        // String policies
        ["HomepageLocation"] = ChromePolicyType.String,
        ["NewTabPageLocation"] = ChromePolicyType.String,
        ["RestoreOnStartupURLs"] = ChromePolicyType.StringList,
        ["DefaultSearchProviderName"] = ChromePolicyType.String,
        ["DefaultSearchProviderSearchURL"] = ChromePolicyType.String,
        ["ProxyServer"] = ChromePolicyType.String,
        ["DiskCacheDir"] = ChromePolicyType.String,
        ["DownloadDirectory"] = ChromePolicyType.String,

        // Integer policies
        ["DefaultCookiesSetting"] = ChromePolicyType.Integer,
        ["DefaultGeolocationSetting"] = ChromePolicyType.Integer,
        ["DefaultNotificationsSetting"] = ChromePolicyType.Integer,
        ["DefaultPopupsSetting"] = ChromePolicyType.Integer,
        ["DiskCacheSize"] = ChromePolicyType.Integer,
        ["MaxConnectionsPerProxy"] = ChromePolicyType.Integer,
        ["RestoreOnStartup"] = ChromePolicyType.Integer,

        // List policies
        ["URLBlocklist"] = ChromePolicyType.StringList,
        ["URLAllowlist"] = ChromePolicyType.StringList,
        ["ExtensionInstallForcelist"] = ChromePolicyType.StringList,
        ["ExtensionInstallBlocklist"] = ChromePolicyType.StringList,
        ["ExtensionInstallAllowlist"] = ChromePolicyType.StringList,
        ["CookiesAllowedForUrls"] = ChromePolicyType.StringList,
        ["CookiesBlockedForUrls"] = ChromePolicyType.StringList,
        ["PopupsAllowedForUrls"] = ChromePolicyType.StringList,
        ["PopupsBlockedForUrls"] = ChromePolicyType.StringList,
        ["NotificationsAllowedForUrls"] = ChromePolicyType.StringList,
        ["NotificationsBlockedForUrls"] = ChromePolicyType.StringList,

        // Dictionary policies
        ["ManagedBookmarks"] = ChromePolicyType.Dictionary,
        ["ProxySettings"] = ChromePolicyType.Dictionary,
    };

    public ValidationResult Validate(string settingsJson)
    {
        var result = new ValidationResult();

        Dictionary<string, JsonElement>? settings;
        try
        {
            settings = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(settingsJson);
        }
        catch (JsonException ex)
        {
            result.Errors.Add($"Invalid JSON: {ex.Message}");
            return result;
        }

        if (settings == null || settings.Count == 0)
        {
            result.Warnings.Add("Policy settings are empty");
            return result;
        }

        foreach (var (key, value) in settings)
        {
            if (!KnownPolicies.TryGetValue(key, out var expectedType))
            {
                result.Warnings.Add($"Unknown policy '{key}' - will be applied but may not be recognized by Chrome");
                continue;
            }

            var typeError = ValidateType(key, value, expectedType);
            if (typeError != null)
                result.Errors.Add(typeError);
        }

        result.IsValid = result.Errors.Count == 0;
        return result;
    }

    private static string? ValidateType(string key, JsonElement value, ChromePolicyType expectedType)
    {
        return expectedType switch
        {
            ChromePolicyType.Boolean when value.ValueKind != JsonValueKind.True && value.ValueKind != JsonValueKind.False
                => $"Policy '{key}' expects a boolean, got {value.ValueKind}",
            ChromePolicyType.Integer when value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out _)
                => $"Policy '{key}' expects an integer, got {value.ValueKind}",
            ChromePolicyType.String when value.ValueKind != JsonValueKind.String
                => $"Policy '{key}' expects a string, got {value.ValueKind}",
            ChromePolicyType.StringList when value.ValueKind != JsonValueKind.Array
                => $"Policy '{key}' expects a string array, got {value.ValueKind}",
            ChromePolicyType.StringList when value.ValueKind == JsonValueKind.Array &&
                value.EnumerateArray().Any(e => e.ValueKind != JsonValueKind.String)
                => $"Policy '{key}' expects all array items to be strings",
            ChromePolicyType.Dictionary when value.ValueKind != JsonValueKind.Object && value.ValueKind != JsonValueKind.String
                => $"Policy '{key}' expects an object or JSON string, got {value.ValueKind}",
            _ => null
        };
    }
}

public enum ChromePolicyType
{
    Boolean,
    Integer,
    String,
    StringList,
    Dictionary
}

public class ValidationResult
{
    public bool IsValid { get; set; } = true;
    public List<string> Errors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
}
