using System.Text.Json;
using Microsoft.Extensions.Configuration;
using PolicyForge.Api.Providers;
using IConfigurationProvider = PolicyForge.Api.Providers.IConfigurationProvider;
using PolicyForge.Contracts.Configuration;
using Xunit;

namespace PolicyForge.Providers.Tests;

public class ProviderEngineTests
{
    private static JsonElement Element(object value) =>
        JsonSerializer.SerializeToElement(value, ConfigurationJson.Options);

    private static RegistryValuePayload AsRegistry(ResolvedInstruction instruction) =>
        instruction.Data.Deserialize<RegistryValuePayload>(ConfigurationJson.Options)!;

    private static ConfigurationCompiler BuildCompiler() =>
        new(new ConfigurationProviderRegistry(new IConfigurationProvider[]
        {
            new RegistryValueProvider(),
            new AdmxPolicyProvider(),
            new WindowsServiceProvider(),
            new ScheduledTaskProvider(),
            new FileResourceProvider(),
            new LocalGroupMembershipProvider(),
            new EnvironmentVariableProvider(),
        }), new ConfigurationGuardrails());

    [Fact]
    public void RegistryValue_MissingKey_FailsValidation()
    {
        var provider = new RegistryValueProvider();
        var result = provider.Validate("""{ "data": 1 }""");
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Key"));
    }

    [Fact]
    public void RegistryValue_Absent_CompilesToRemove()
    {
        var item = ConfigurationItem.Create(ProviderType.RegistryValue, new RegistryValuePayload
        {
            Hive = RegistryHive.Hklm,
            Key = @"SOFTWARE\Contoso",
            Name = "Flag",
            Ensure = EnsureState.Absent,
        });

        var instructions = new RegistryValueProvider().Compile(item);

        var instruction = Assert.Single(instructions);
        Assert.Equal(ProviderType.RegistryValue, instruction.Provider);
        Assert.Equal("Remove", instruction.Action);
    }

    [Fact]
    public void AdmxPolicy_Scalar_CompilesToSingleRegistryValue()
    {
        var item = ConfigurationItem.Create(ProviderType.AdmxPolicy, new AdmxPolicyPayload
        {
            Namespace = "chrome",
            PolicyId = "SafeBrowsingProtectionLevel",
            Hive = RegistryHive.Hklm,
            RegistryKey = @"SOFTWARE\Policies\Google\Chrome",
            ValueName = "SafeBrowsingProtectionLevel",
            ValueType = RegistryValueKind.Dword,
            Value = Element(2),
            AdmxVersion = "120.0.6099.x",
        });

        var instruction = Assert.Single(new AdmxPolicyProvider().Compile(item));
        Assert.Equal(ProviderType.RegistryValue, instruction.Provider);

        var reg = AsRegistry(instruction);
        Assert.Equal(@"SOFTWARE\Policies\Google\Chrome", reg.Key);
        Assert.Equal("SafeBrowsingProtectionLevel", reg.Name);
        Assert.Equal(RegistryValueKind.Dword, reg.Type);
        Assert.Equal(2, reg.Data!.Value.GetInt32());
    }

    [Fact]
    public void AdmxPolicy_List_ExpandsToNumberedSubkeyValues()
    {
        var item = ConfigurationItem.Create(ProviderType.AdmxPolicy, new AdmxPolicyPayload
        {
            Namespace = "chrome",
            PolicyId = "URLAllowlist",
            RegistryKey = @"SOFTWARE\Policies\Google\Chrome",
            ValueName = "URLAllowlist",
            ValueType = RegistryValueKind.String,
            IsList = true,
            Value = Element(new[] { "contoso.com", "fabrikam.com" }),
        });

        var instructions = new AdmxPolicyProvider().Compile(item);

        Assert.Equal(2, instructions.Count);
        Assert.All(instructions, i => Assert.Equal(ProviderType.RegistryValue, i.Provider));

        var first = AsRegistry(instructions[0]);
        var second = AsRegistry(instructions[1]);
        Assert.Equal(@"SOFTWARE\Policies\Google\Chrome\URLAllowlist", first.Key);
        Assert.Equal("1", first.Name);
        Assert.Equal("contoso.com", first.Data!.Value.GetString());
        Assert.Equal("2", second.Name);
        Assert.Equal("fabrikam.com", second.Data!.Value.GetString());
    }

    [Fact]
    public void AdmxPolicy_List_AbsentRemovesSubkey()
    {
        var item = ConfigurationItem.Create(ProviderType.AdmxPolicy, new AdmxPolicyPayload
        {
            Namespace = "chrome",
            PolicyId = "URLAllowlist",
            RegistryKey = @"SOFTWARE\Policies\Google\Chrome",
            ValueName = "URLAllowlist",
            IsList = true,
            Ensure = EnsureState.Absent,
        });

        var instruction = Assert.Single(new AdmxPolicyProvider().Compile(item));
        Assert.Equal("Remove", instruction.Action);
        var reg = AsRegistry(instruction);
        Assert.Equal(@"SOFTWARE\Policies\Google\Chrome\URLAllowlist", reg.Key);
    }

    [Fact]
    public void EnvironmentVariable_PresentWithoutValue_FailsValidation()
    {
        var result = new EnvironmentVariableProvider().Validate("""{ "name": "FOO", "ensure": "Present" }""");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Compiler_AggregatesValidationErrorsAcrossItems()
    {
        var compiler = BuildCompiler();
        var items = new[]
        {
            ConfigurationItem.Create(ProviderType.RegistryValue, new RegistryValuePayload()), // missing key + data
            ConfigurationItem.Create(ProviderType.LocalGroupMembership, new LocalGroupMembershipPayload { Group = "" }),
        };

        var errors = compiler.Validate(items);
        Assert.NotEmpty(errors);
        Assert.Contains(errors, e => e.Contains("RegistryValue"));
        Assert.Contains(errors, e => e.Contains("LocalGroupMembership"));
    }

    [Fact]
    public void Compiler_BuildResolved_IsDeterministic()
    {
        var compiler = BuildCompiler();
        var items = new[]
        {
            ConfigurationItem.Create(ProviderType.EnvironmentVariable, new EnvironmentVariablePayload
            {
                Name = "PF_HOME", Value = @"C:\PolicyForge", Scope = EnvironmentVariableScope.Machine,
            }),
        };

        var a = compiler.BuildResolved("device-1", items);
        var b = compiler.BuildResolved("device-1", items);

        Assert.Equal(a.Hash, b.Hash);
        Assert.Single(a.Instructions);
        Assert.Equal(ProviderType.EnvironmentVariable, a.Instructions[0].Provider);
    }

    [Fact]
    public void AllV1Providers_AreRegistered()
    {
        var registry = new ConfigurationProviderRegistry(new IConfigurationProvider[]
        {
            new RegistryValueProvider(),
            new AdmxPolicyProvider(),
            new WindowsServiceProvider(),
            new ScheduledTaskProvider(),
            new FileResourceProvider(),
            new LocalGroupMembershipProvider(),
            new EnvironmentVariableProvider(),
        });

        foreach (var type in Enum.GetValues<ProviderType>())
            Assert.True(registry.IsSupported(type), $"Provider {type} should be registered.");
    }

    // --- Guardrails -----------------------------------------------------------------------------

    [Fact]
    public void Guardrails_BlockProtectedRegistryKey()
    {
        var compiler = BuildCompiler();
        var items = new[]
        {
            ConfigurationItem.Create(ProviderType.RegistryValue, new RegistryValuePayload
            {
                Hive = RegistryHive.Hklm,
                Key = @"SYSTEM\CurrentControlSet\Services\Foo",
                Name = "Start",
                Type = RegistryValueKind.Dword,
                Data = Element(4),
            }, "disable-foo"),
        };

        var errors = compiler.Validate(items);
        Assert.Contains(errors, e => e.Contains("protected registry path"));
    }

    [Fact]
    public void Guardrails_BlockDisablingCriticalService()
    {
        var compiler = BuildCompiler();
        var items = new[]
        {
            ConfigurationItem.Create(ProviderType.WindowsService, new WindowsServicePayload
            {
                Name = "RpcSs", StartupType = ServiceStartupType.Disabled, State = ServiceState.Stopped,
            }, "kill-rpc"),
        };

        var errors = compiler.Validate(items);
        Assert.Contains(errors, e => e.Contains("critical service"));
    }

    [Fact]
    public void Guardrails_AllowOrdinaryRegistryAndService()
    {
        var compiler = BuildCompiler();
        var items = new[]
        {
            ConfigurationItem.Create(ProviderType.RegistryValue, new RegistryValuePayload
            {
                Hive = RegistryHive.Hklm,
                Key = @"SOFTWARE\Policies\Google\Chrome",
                Name = "HomepageLocation",
                Type = RegistryValueKind.String,
                Data = Element("https://example.com"),
            }),
            ConfigurationItem.Create(ProviderType.WindowsService, new WindowsServicePayload
            {
                Name = "Spooler", StartupType = ServiceStartupType.Disabled, State = ServiceState.Stopped,
            }),
        };

        Assert.Empty(compiler.Validate(items));
    }

    [Fact]
    public void Guardrails_CanBeDisabledViaConfiguration()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PolicyForge:Guardrails:Enabled"] = "false" })
            .Build();
        var compiler = new ConfigurationCompiler(
            new ConfigurationProviderRegistry(new IConfigurationProvider[] { new RegistryValueProvider() }),
            new ConfigurationGuardrails(config));

        var items = new[]
        {
            ConfigurationItem.Create(ProviderType.RegistryValue, new RegistryValuePayload
            {
                Hive = RegistryHive.Hklm, Key = @"SAM\Domains", Name = "x",
                Type = RegistryValueKind.Dword, Data = Element(1),
            }),
        };

        Assert.Empty(compiler.Validate(items));
    }

    // --- Conflict warnings ----------------------------------------------------------------------

    [Fact]
    public void ConflictWarnings_FlagsDuplicateTarget()
    {
        var compiler = BuildCompiler();
        var items = new[]
        {
            ConfigurationItem.Create(ProviderType.RegistryValue, new RegistryValuePayload
            {
                Hive = RegistryHive.Hklm, Key = @"SOFTWARE\Policies\App", Name = "Mode",
                Type = RegistryValueKind.Dword, Data = Element(1),
            }, "winner"),
            ConfigurationItem.Create(ProviderType.RegistryValue, new RegistryValuePayload
            {
                Hive = RegistryHive.Hklm, Key = @"SOFTWARE\Policies\App", Name = "Mode",
                Type = RegistryValueKind.Dword, Data = Element(2),
            }, "loser"),
        };

        var resolved = compiler.BuildResolved("device-1", items);
        Assert.Single(resolved.Warnings);
        Assert.Contains("shadowed", resolved.Warnings[0]);
    }
}
