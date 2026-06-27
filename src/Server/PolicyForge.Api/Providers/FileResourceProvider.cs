using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>Provider for files, directories and shortcuts on disk (GPP-style).</summary>
public sealed class FileResourceProvider : PassthroughProviderBase<FileResourcePayload>
{
    public override ProviderType Type => ProviderType.FileResource;

    protected override string ResolveAction(FileResourcePayload payload) => SetOrRemove(payload.Ensure);

    protected override IReadOnlyList<string> ValidatePayload(FileResourcePayload payload)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(payload.TargetPath))
            errors.Add("FileResource.TargetPath is required.");

        if (payload.Ensure == EnsureState.Present)
        {
            switch (payload.ResourceType)
            {
                case FileResourceType.File:
                    if (string.IsNullOrEmpty(payload.Content) && string.IsNullOrWhiteSpace(payload.SourceUrl))
                        errors.Add("FileResource (File) requires Content or SourceUrl when Ensure is Present.");
                    break;
                case FileResourceType.Shortcut:
                    if (string.IsNullOrWhiteSpace(payload.TargetExecutable))
                        errors.Add("FileResource (Shortcut) requires TargetExecutable.");
                    break;
                case FileResourceType.Directory:
                    break;
            }
        }
        return errors;
    }
}
