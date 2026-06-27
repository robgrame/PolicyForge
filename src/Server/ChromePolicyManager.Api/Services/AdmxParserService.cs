using System.Text.Json;
using System.Xml.Linq;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Parses Chrome ADMX + ADML files to produce PolicyCatalogEntry records.
/// Handles: boolean, enum, decimal, text, list policy types.
/// </summary>
public class AdmxParserService
{
    public record AdmxParseResult(
        List<PolicyCatalogEntry> Entries,
        string TemplateVersion,
        int TotalParsed,
        List<string> Warnings);

    /// <summary>
    /// Parse Chrome ADMX and ADML content streams into catalog entries.
    /// </summary>
    public AdmxParseResult Parse(Stream admxStream, Stream admlStream, string templateVersion = "unknown")
    {
        var admx = XDocument.Load(admxStream);
        var adml = XDocument.Load(admlStream);

        var strings = ParseStringTable(adml);
        var categories = ParseCategories(admx);
        var entries = new List<PolicyCatalogEntry>();
        var warnings = new List<string>();

        var policiesElement = admx.Root?.Element("policies");
        if (policiesElement is null)
        {
            warnings.Add("No <policies> element found in ADMX");
            return new AdmxParseResult(entries, templateVersion, 0, warnings);
        }

        foreach (var policy in policiesElement.Elements("policy"))
        {
            try
            {
                var entry = ParsePolicy(policy, strings, categories, templateVersion);
                if (entry is not null)
                    entries.Add(entry);
            }
            catch (Exception ex)
            {
                var name = policy.Attribute("name")?.Value ?? "unknown";
                warnings.Add($"Failed to parse policy '{name}': {ex.Message}");
            }
        }

        return new AdmxParseResult(entries, templateVersion, entries.Count, warnings);
    }

    private PolicyCatalogEntry? ParsePolicy(
        XElement policy,
        Dictionary<string, string> strings,
        Dictionary<string, string> categories,
        string templateVersion)
    {
        var name = policy.Attribute("name")?.Value;
        if (string.IsNullOrEmpty(name)) return null;

        var regKey = policy.Attribute("key")?.Value ?? "";
        var valueName = policy.Attribute("valueName")?.Value ?? "";
        var policyClass = policy.Attribute("class")?.Value ?? "Both";
        var categoryRef = policy.Element("parentCategory")?.Attribute("ref")?.Value ?? "";
        var supportedOnRef = policy.Element("supportedOn")?.Attribute("ref")?.Value ?? "";

        // Determine if this is a "Recommended" variant
        bool isRecommended = categoryRef.EndsWith("_recommended") ||
                             regKey.Contains("\\Recommended");

        // Strip _recommended suffix for clean category name
        var cleanCategory = categoryRef.Replace("_recommended", "");
        var categoryDisplayName = categories.GetValueOrDefault(cleanCategory, cleanCategory);
        // Resolve the category display name through ADML string table
        var categoryName = ResolveStringRef(categoryDisplayName, strings) ?? categoryDisplayName;

        // Get display name and description from ADML strings
        var displayName = ResolveStringRef(policy.Attribute("displayName")?.Value, strings)
                          ?? strings.GetValueOrDefault(name, name);
        var description = ResolveStringRef(policy.Attribute("explainText")?.Value, strings)
                          ?? strings.GetValueOrDefault($"{name}_Explain", "");

        // Determine data type from elements
        var (dataType, enumOptions) = DetermineDataType(policy, strings);

        // For recommended policies, use the base name without suffix
        var baseName = isRecommended && name.EndsWith("_recommended")
            ? name[..^"_recommended".Length]
            : name;

        return new PolicyCatalogEntry
        {
            Name = baseName,
            DisplayName = displayName,
            Description = description,
            Category = categoryName,
            DataType = dataType,
            RegistryKey = regKey,
            RegistryValueName = valueName,
            IsRecommended = isRecommended,
            SupportedOn = supportedOnRef,
            EnumOptions = enumOptions,
            PolicyClass = policyClass,
            TemplateVersion = templateVersion,
            ImportedAt = DateTime.UtcNow
        };
    }

    private (string DataType, string? EnumOptions) DetermineDataType(XElement policy, Dictionary<string, string> strings)
    {
        var elements = policy.Element("elements");

        if (elements is null)
        {
            // No elements = simple enable/disable boolean
            return ("Boolean", null);
        }

        var firstChild = elements.Elements().FirstOrDefault();
        if (firstChild is null) return ("Boolean", null);

        return firstChild.Name.LocalName switch
        {
            "enum" => ("Enum", ParseEnumOptions(firstChild, strings)),
            "decimal" => ("Integer", null),
            "text" => ("String", null),
            "list" => ("List", null),
            "boolean" => ("Boolean", null),
            "multiText" => ("MultiString", null),
            _ => ("String", null)
        };
    }

    private string? ParseEnumOptions(XElement enumElement, Dictionary<string, string> strings)
    {
        var items = enumElement.Elements("item").Select(item =>
        {
            var displayNameRef = item.Attribute("displayName")?.Value;
            var displayName = ResolveStringRef(displayNameRef, strings) ?? displayNameRef ?? "";
            var valueElement = item.Element("value")?.Element("decimal");
            var stringValue = item.Element("value")?.Element("string");

            object value = valueElement is not null
                ? int.Parse(valueElement.Attribute("value")?.Value ?? "0")
                : stringValue?.Value ?? "";

            return new { displayName, value };
        }).ToList();

        return items.Count > 0 ? JsonSerializer.Serialize(items) : null;
    }

    private string? ResolveStringRef(string? reference, Dictionary<string, string> strings)
    {
        if (string.IsNullOrEmpty(reference)) return null;

        // ADMX uses $(string.KEY) format
        if (reference.StartsWith("$(string.") && reference.EndsWith(")"))
        {
            var key = reference["$(string.".Length..^1];
            return strings.GetValueOrDefault(key);
        }

        return reference;
    }

    private Dictionary<string, string> ParseStringTable(XDocument adml)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var stringTable = adml.Root?
            .Element("resources")?
            .Element("stringTable");

        if (stringTable is null) return result;

        foreach (var str in stringTable.Elements("string"))
        {
            var id = str.Attribute("id")?.Value;
            if (!string.IsNullOrEmpty(id))
                result[id] = str.Value.Trim();
        }

        return result;
    }

    private Dictionary<string, string> ParseCategories(XDocument admx)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var categoriesElement = admx.Root?.Element("categories");
        if (categoriesElement is null) return result;

        foreach (var cat in categoriesElement.Elements("category"))
        {
            var name = cat.Attribute("name")?.Value;
            var displayName = cat.Attribute("displayName")?.Value;
            if (!string.IsNullOrEmpty(name))
                result[name] = displayName ?? name;
        }

        return result;
    }
}
