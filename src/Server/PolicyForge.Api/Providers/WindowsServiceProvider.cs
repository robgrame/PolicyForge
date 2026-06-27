using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>Provider for Windows service desired state (startup type, run state, logon account).</summary>
public sealed class WindowsServiceProvider : PassthroughProviderBase<WindowsServicePayload>
{
    public override ProviderType Type => ProviderType.WindowsService;

    protected override IReadOnlyList<string> ValidatePayload(WindowsServicePayload payload)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(payload.Name))
            errors.Add("WindowsService.Name is required.");
        if (payload.StartupType == ServiceStartupType.Unchanged && payload.State == ServiceState.Unchanged
            && string.IsNullOrWhiteSpace(payload.Account))
            errors.Add("WindowsService must change at least one of StartupType, State or Account.");
        return errors;
    }
}
