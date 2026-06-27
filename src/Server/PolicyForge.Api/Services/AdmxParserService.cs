using System.Text.Json;
using System.Xml.Linq;
using PolicyForge.Api.Models;

namespace PolicyForge.Api.Services;

/// <summary>
/// Parses ADMX + ADML files into PolicyCatalogEntry records. Namespace-aware (handles the standard
/// PolicyDefinitions XML namespace) and product-aware (captures each ADMX's target prefix), so it
/// can ingest arbitrary vendor ADMX, not just Chrome. Handles boolean, enum, decimal, text, list
/// and multiText policy element types.
/// </summary>
public class AdmxParserService
{
    public record AdmxParseResult(
        List<PolicyCatalogEntry> Entries,
        string TemplateVersion,
        int TotalParsed,
        List<string> Warnings,
        string Namespace = "",
        string ProductName = "");

    /// <summary>
    /// Parse ADMX and ADML content streams into catalog entries. The <paramref name="productName"/>
    /// is an optional friendly label; when omitted the ADML <c>displayName</c> resource is used.
    /// </summary>
    public AdmxParseResult Parse(Stream admxStream, Stream admlStream, string templateVersion = "unknown", string? productName = null)
    {
        var admx = XDocument.Load(admxStream);
        var adml = XDocument.Load(admlStream);

        // Standard ADMX/ADML files declare a default XML namespace; resolve it from the root so
        // element lookups work regardless of vendor. Falls back to no-namespace when absent.
        var ns = admx.Root?.Name.Namespace ?? XNamespace.None;
        var admlNs = adml.Root?.Name.Namespace ?? XNamespace.None;

        var strings = ParseStringTable(adml, admlNs);
        var categories = ParseCategories(admx, ns);
        var (prefix, _) = ParseTargetNamespace(admx, ns);
        var product = ResolveProductName(productName, prefix, adml, admlNs, strings);

        var entries = new List<PolicyCatalogEntry>();
        var warnings = new List<string>();

        var policiesElement = admx.Root?.Element(ns + "policies");
        if (policiesElement is null)
        {
            warnings.Add("No <policies> element found in ADMX");
            return new AdmxParseResult(entries, templateVersion, 0, warnings, prefix, product);
        }

        foreach (var policy in policiesElement.Elements(ns + "policy"))
        {
            try
            {
                var entry = ParsePolicy(policy, ns, strings, categories, templateVersion, prefix, product);
                if (entry is not null)
                    entries.Add(entry);
            }
            catch (Exception ex)
            {
                var name = policy.Attribute("name")?.Value ?? "unknown";
                warnings.Add($"Failed to parse policy '{name}': {ex.Message}");
            }
        }

        return new AdmxParseResult(entries, templateVersion, entries.Count, warnings, prefix, product);
    }

    private PolicyCatalogEntry? ParsePolicy(
        XElement policy,
        XNamespace ns,
        Dictionary<string, string> strings,
        Dictionary<string, string> categories,
        string templateVersion,
        string @namespace,
        string productName)
    {
        var name = policy.Attribute("name")?.Value;
        if (string.IsNullOrEmpty(name)) return null;

        var regKey = policy.Attribute("key")?.Value ?? "";
        var valueName = policy.Attribute("valueName")?.Value ?? "";
        var policyClass = policy.Attribute("class")?.Value ?? "Both";
        var categoryRef = policy.Element(ns + "parentCategory")?.Attribute("ref")?.Value ?? "";
        var supportedOnRef = policy.Element(ns + "supportedOn")?.Attribute("ref")?.Value ?? "";

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
        var (dataType, enumOptions) = DetermineDataType(policy, ns, strings);

        // For recommended policies, use the base name without suffix
        var baseName = isRecommended && name.EndsWith("_recommended")
            ? name[..^"_recommended".Length]
            : name;

        return new PolicyCatalogEntry
        {
            Namespace = @namespace,
            ProductName = productName,
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

    private (string DataType, string? EnumOptions) DetermineDataType(XElement policy, XNamespace ns, Dictionary<string, string> strings)
    {
        var elements = policy.Element(ns + "elements");

        if (elements is null)
        {
            // No elements = simple enable/disable boolean
            return ("Boolean", null);
        }

        var firstChild = elements.Elements().FirstOrDefault();
        if (firstChild is null) return ("Boolean", null);

        return firstChild.Name.LocalName switch
        {
            "enum" => ("Enum", ParseEnumOptions(firstChild, ns, strings)),
            "decimal" => ("Integer", null),
            "text" => ("String", null),
            "list" => ("List", null),
            "boolean" => ("Boolean", null),
            "multiText" => ("MultiString", null),
            _ => ("String", null)
        };
    }

    private string? ParseEnumOptions(XElement enumElement, XNamespace ns, Dictionary<string, string> strings)
    {
        var items = enumElement.Elements(ns + "item").Select(item =>
        {
            var displayNameRef = item.Attribute("displayName")?.Value;
            var displayName = ResolveStringRef(displayNameRef, strings) ?? displayNameRef ?? "";
            var valueElement = item.Element(ns + "value")?.Element(ns + "decimal");
            var stringValue = item.Element(ns + "value")?.Element(ns + "string");

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

    /// <summary>Reads the ADMX <c>policyNamespaces/target</c> prefix and namespace URI.</summary>
    private (string Prefix, string NamespaceUri) ParseTargetNamespace(XDocument admx, XNamespace ns)
    {
        var target = admx.Root?.Element(ns + "policyNamespaces")?.Element(ns + "target");
        var prefix = target?.Attribute("prefix")?.Value ?? "";
        var uri = target?.Attribute("namespace")?.Value ?? "";
        return (prefix, uri);
    }

    /// <summary>Determines a friendly product label: explicit override, ADML displayName, or prefix.</summary>
    private string ResolveProductName(string? productName, string prefix, XDocument adml, XNamespace admlNs, Dictionary<string, string> strings)
    {
        if (!string.IsNullOrWhiteSpace(productName)) return productName.Trim();

        var display = adml.Root?.Element(admlNs + "displayName")?.Value?.Trim();
        if (!string.IsNullOrWhiteSpace(display) && !display.StartsWith("$("))
            return display;

        var resolved = ResolveStringRef(display, strings);
        if (!string.IsNullOrWhiteSpace(resolved)) return resolved;

        return string.IsNullOrWhiteSpace(prefix) ? "Unknown" : prefix;
    }

    private Dictionary<string, string> ParseStringTable(XDocument adml, XNamespace ns)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var stringTable = adml.Root?
            .Element(ns + "resources")?
            .Element(ns + "stringTable");

        if (stringTable is null) return result;

        foreach (var str in stringTable.Elements(ns + "string"))
        {
            var id = str.Attribute("id")?.Value;
            if (!string.IsNullOrEmpty(id))
                result[id] = str.Value.Trim();
        }

        return result;
    }

    private Dictionary<string, string> ParseCategories(XDocument admx, XNamespace ns)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var categoriesElement = admx.Root?.Element(ns + "categories");
        if (categoriesElement is null) return result;

        foreach (var cat in categoriesElement.Elements(ns + "category"))
        {
            var name = cat.Attribute("name")?.Value;
            var displayName = cat.Attribute("displayName")?.Value;
            if (!string.IsNullOrEmpty(name))
                result[name] = displayName ?? name;
        }

        return result;
    }
}
