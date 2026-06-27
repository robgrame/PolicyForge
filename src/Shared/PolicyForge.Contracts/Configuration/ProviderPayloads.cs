namespace PolicyForge.Contracts.Configuration;

// ---------------------------------------------------------------------------------------------
// v1 provider payloads (besides RegistryValue and AdmxPolicy). These are passed through to the
// client unchanged: the client has a native handler per provider that applies and reports them.
// ---------------------------------------------------------------------------------------------

public enum ServiceStartupType { Unchanged = 0, Automatic = 1, AutomaticDelayedStart = 2, Manual = 3, Disabled = 4 }

public enum ServiceState { Unchanged = 0, Running = 1, Stopped = 2 }

/// <summary>Payload for <see cref="ProviderType.WindowsService"/>.</summary>
public sealed record WindowsServicePayload
{
    /// <summary>Service short name (e.g. <c>Spooler</c>).</summary>
    public string Name { get; init; } = string.Empty;

    public ServiceStartupType StartupType { get; init; } = ServiceStartupType.Unchanged;

    /// <summary>Desired runtime state after applying the startup type.</summary>
    public ServiceState State { get; init; } = ServiceState.Unchanged;

    /// <summary>Optional logon account (e.g. <c>NT AUTHORITY\LocalService</c>). Null = leave unchanged.</summary>
    public string? Account { get; init; }
}

public enum ScheduledTaskState { Unchanged = 0, Enabled = 1, Disabled = 2 }

/// <summary>Payload for <see cref="ProviderType.ScheduledTask"/>.</summary>
public sealed record ScheduledTaskPayload
{
    /// <summary>Task name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Task folder path. Defaults to the root <c>\</c>.</summary>
    public string Path { get; init; } = "\\";

    public EnsureState Ensure { get; init; } = EnsureState.Present;

    /// <summary>Full Task Scheduler definition XML (used to create/update the task when present).</summary>
    public string? DefinitionXml { get; init; }

    /// <summary>Desired enabled/disabled state.</summary>
    public ScheduledTaskState State { get; init; } = ScheduledTaskState.Unchanged;
}

public enum FileResourceType { File = 0, Directory = 1, Shortcut = 2 }

public enum FileContentEncoding { Utf8 = 0, Base64 = 1 }

/// <summary>Payload for <see cref="ProviderType.FileResource"/> (file/folder/shortcut, GPP-style).</summary>
public sealed record FileResourcePayload
{
    public string TargetPath { get; init; } = string.Empty;

    public FileResourceType ResourceType { get; init; } = FileResourceType.File;

    public EnsureState Ensure { get; init; } = EnsureState.Present;

    public bool Overwrite { get; init; } = true;

    // --- File ---
    /// <summary>Inline content for a file resource (interpreted per <see cref="ContentEncoding"/>).</summary>
    public string? Content { get; init; }

    public FileContentEncoding ContentEncoding { get; init; } = FileContentEncoding.Utf8;

    /// <summary>Alternative to <see cref="Content"/>: download the file from this URL.</summary>
    public string? SourceUrl { get; init; }

    // --- Shortcut (.lnk) ---
    public string? TargetExecutable { get; init; }
    public string? Arguments { get; init; }
    public string? WorkingDirectory { get; init; }
    public string? IconPath { get; init; }
    public string? Description { get; init; }
}

public enum LocalGroupAction { Add = 0, Remove = 1, Replace = 2 }

/// <summary>Payload for <see cref="ProviderType.LocalGroupMembership"/>.</summary>
public sealed record LocalGroupMembershipPayload
{
    /// <summary>Local group name (e.g. <c>Administrators</c>).</summary>
    public string Group { get; init; } = string.Empty;

    public LocalGroupAction Action { get; init; } = LocalGroupAction.Add;

    /// <summary>Members to add/remove/replace (e.g. <c>AzureAD\user@contoso.com</c>, a SID, or <c>Domain\Group</c>).</summary>
    public IReadOnlyList<string> Members { get; init; } = Array.Empty<string>();
}

public enum EnvironmentVariableScope { Machine = 0, User = 1 }

/// <summary>Payload for <see cref="ProviderType.EnvironmentVariable"/>.</summary>
public sealed record EnvironmentVariablePayload
{
    public string Name { get; init; } = string.Empty;

    public EnvironmentVariableScope Scope { get; init; } = EnvironmentVariableScope.Machine;

    public string? Value { get; init; }

    public EnsureState Ensure { get; init; } = EnsureState.Present;
}
