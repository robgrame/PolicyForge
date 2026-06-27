using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>Provider for local group membership (add/remove/replace members).</summary>
public sealed class LocalGroupMembershipProvider : PassthroughProviderBase<LocalGroupMembershipPayload>
{
    public override ProviderType Type => ProviderType.LocalGroupMembership;

    protected override IReadOnlyList<string> ValidatePayload(LocalGroupMembershipPayload payload)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(payload.Group))
            errors.Add("LocalGroupMembership.Group is required.");
        if (payload.Members is null || payload.Members.Count == 0)
            errors.Add("LocalGroupMembership.Members must contain at least one member.");
        else if (payload.Members.Any(string.IsNullOrWhiteSpace))
            errors.Add("LocalGroupMembership.Members must not contain empty entries.");
        return errors;
    }
}
