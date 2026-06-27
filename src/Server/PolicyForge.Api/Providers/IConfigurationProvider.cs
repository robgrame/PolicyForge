using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>
/// Server-side contract for a configuration domain. A provider validates authored payloads and
/// compiles them into flat, client-ready <see cref="ResolvedInstruction"/>s. Providers are pure
/// with respect to the item payload (no DB / IO) so resolution is deterministic and cacheable —
/// any external data (e.g. an ADMX registry mapping) is captured into the payload at authoring time.
/// </summary>
public interface IConfigurationProvider
{
    /// <summary>The provider type this handler owns.</summary>
    ProviderType Type { get; }

    /// <summary>Validate an authored payload (shape and required fields).</summary>
    ProviderValidationResult Validate(string payloadJson);

    /// <summary>Compile an authored item into one or more client-ready instructions.</summary>
    IReadOnlyList<ResolvedInstruction> Compile(ConfigurationItem item);
}

/// <summary>Outcome of <see cref="IConfigurationProvider.Validate"/>.</summary>
public sealed record ProviderValidationResult(bool IsValid, IReadOnlyList<string> Errors)
{
    public static ProviderValidationResult Ok { get; } = new(true, Array.Empty<string>());

    public static ProviderValidationResult Fail(params string[] errors) => new(false, errors);
}
