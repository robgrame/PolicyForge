using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>Provider for machine/user environment variables.</summary>
public sealed class EnvironmentVariableProvider : PassthroughProviderBase<EnvironmentVariablePayload>
{
    public override ProviderType Type => ProviderType.EnvironmentVariable;

    protected override string ResolveAction(EnvironmentVariablePayload payload) => SetOrRemove(payload.Ensure);

    protected override IReadOnlyList<string> ValidatePayload(EnvironmentVariablePayload payload)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(payload.Name))
            errors.Add("EnvironmentVariable.Name is required.");
        if (payload.Ensure == EnsureState.Present && payload.Value is null)
            errors.Add("EnvironmentVariable.Value is required when Ensure is Present.");
        return errors;
    }
}
