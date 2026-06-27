using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>Resolves the <see cref="IConfigurationProvider"/> for a given <see cref="ProviderType"/>.</summary>
public sealed class ConfigurationProviderRegistry
{
    private readonly IReadOnlyDictionary<ProviderType, IConfigurationProvider> _providers;

    public ConfigurationProviderRegistry(IEnumerable<IConfigurationProvider> providers)
    {
        _providers = providers.ToDictionary(p => p.Type);
    }

    public IEnumerable<ProviderType> SupportedTypes => _providers.Keys;

    public bool IsSupported(ProviderType type) => _providers.ContainsKey(type);

    public IConfigurationProvider Get(ProviderType type) =>
        _providers.TryGetValue(type, out var provider)
            ? provider
            : throw new NotSupportedException($"No configuration provider is registered for '{type}'.");

    public bool TryGet(ProviderType type, out IConfigurationProvider provider) =>
        _providers.TryGetValue(type, out provider!);
}
