using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>Provider for Windows scheduled tasks (create/update via XML, enable/disable, remove).</summary>
public sealed class ScheduledTaskProvider : PassthroughProviderBase<ScheduledTaskPayload>
{
    public override ProviderType Type => ProviderType.ScheduledTask;

    protected override string ResolveAction(ScheduledTaskPayload payload) => SetOrRemove(payload.Ensure);

    protected override IReadOnlyList<string> ValidatePayload(ScheduledTaskPayload payload)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(payload.Name))
            errors.Add("ScheduledTask.Name is required.");

        if (payload.Ensure == EnsureState.Present
            && string.IsNullOrWhiteSpace(payload.DefinitionXml)
            && payload.State == ScheduledTaskState.Unchanged)
        {
            errors.Add("ScheduledTask requires a DefinitionXml (to create/update) or a State change when Ensure is Present.");
        }
        return errors;
    }
}
