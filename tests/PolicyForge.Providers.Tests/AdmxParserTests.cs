using System.Text;
using PolicyForge.Api.Services;
using Xunit;

namespace PolicyForge.Providers.Tests;

/// <summary>
/// Verifies the ADMX parser is namespace-aware and product-aware, so it can ingest arbitrary
/// vendor ADMX (not just Chrome). Uses a minimal but standards-compliant ADMX/ADML pair with the
/// default PolicyDefinitions XML namespace and a non-Chrome target prefix.
/// </summary>
public class AdmxParserTests
{
    private const string Admx = """
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"
                   revision="1.0" schemaVersion="1.0">
  <policyNamespaces>
    <target prefix="contoso" namespace="Contoso.Policies.SuperApp" />
  </policyNamespaces>
  <resources minRequiredRevision="1.0" />
  <categories>
    <category name="SuperApp" displayName="$(string.SuperApp)" />
  </categories>
  <policies>
    <policy name="EnableTelemetry" class="Machine"
            displayName="$(string.EnableTelemetry)" explainText="$(string.EnableTelemetry_Explain)"
            key="Software\Policies\Contoso\SuperApp" valueName="EnableTelemetry">
      <parentCategory ref="SuperApp" />
      <supportedOn ref="windows:SUPPORTED_Windows10" />
      <enabledValue><decimal value="1" /></enabledValue>
      <disabledValue><decimal value="0" /></disabledValue>
    </policy>
    <policy name="UpdateChannel" class="Machine"
            displayName="$(string.UpdateChannel)" explainText="$(string.UpdateChannel_Explain)"
            key="Software\Policies\Contoso\SuperApp" valueName="UpdateChannel">
      <parentCategory ref="SuperApp" />
      <supportedOn ref="windows:SUPPORTED_Windows10" />
      <elements>
        <enum id="UpdateChannel" valueName="UpdateChannel">
          <item displayName="$(string.Channel_Stable)"><value><decimal value="0" /></value></item>
          <item displayName="$(string.Channel_Beta)"><value><decimal value="1" /></value></item>
        </enum>
      </elements>
    </policy>
  </policies>
</policyDefinitions>
""";

    private const string Adml = """
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitionResources xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"
                           revision="1.0" schemaVersion="1.0">
  <displayName>Contoso SuperApp</displayName>
  <description>Contoso SuperApp policies</description>
  <resources>
    <stringTable>
      <string id="SuperApp">Contoso SuperApp</string>
      <string id="EnableTelemetry">Enable telemetry</string>
      <string id="EnableTelemetry_Explain">Controls telemetry collection.</string>
      <string id="UpdateChannel">Update channel</string>
      <string id="UpdateChannel_Explain">Selects the update channel.</string>
      <string id="Channel_Stable">Stable</string>
      <string id="Channel_Beta">Beta</string>
    </stringTable>
  </resources>
</policyDefinitionResources>
""";

    [Fact]
    public void Parses_NonChrome_Admx_With_Namespace_And_Product()
    {
        var parser = new AdmxParserService();
        using var admx = new MemoryStream(Encoding.UTF8.GetBytes(Admx));
        using var adml = new MemoryStream(Encoding.UTF8.GetBytes(Adml));

        var result = parser.Parse(admx, adml, "1.2.3");

        Assert.Empty(result.Warnings);
        Assert.Equal("contoso", result.Namespace);
        Assert.Equal("Contoso SuperApp", result.ProductName);
        Assert.Equal(2, result.TotalParsed);

        var telemetry = Assert.Single(result.Entries, e => e.Name == "EnableTelemetry");
        Assert.Equal("contoso", telemetry.Namespace);
        Assert.Equal("Contoso SuperApp", telemetry.ProductName);
        Assert.Equal("Enable telemetry", telemetry.DisplayName);
        Assert.Equal("Boolean", telemetry.DataType);
        Assert.Equal(@"Software\Policies\Contoso\SuperApp", telemetry.RegistryKey);
        Assert.Equal("Contoso SuperApp", telemetry.Category);

        var channel = Assert.Single(result.Entries, e => e.Name == "UpdateChannel");
        Assert.Equal("Enum", channel.DataType);
        Assert.NotNull(channel.EnumOptions);
        Assert.Contains("Stable", channel.EnumOptions);
        Assert.Contains("Beta", channel.EnumOptions);
    }

    [Fact]
    public void ProductName_Override_Wins()
    {
        var parser = new AdmxParserService();
        using var admx = new MemoryStream(Encoding.UTF8.GetBytes(Admx));
        using var adml = new MemoryStream(Encoding.UTF8.GetBytes(Adml));

        var result = parser.Parse(admx, adml, "1.0", productName: "My Override");

        Assert.Equal("My Override", result.ProductName);
        Assert.All(result.Entries, e => Assert.Equal("My Override", e.ProductName));
    }
}
