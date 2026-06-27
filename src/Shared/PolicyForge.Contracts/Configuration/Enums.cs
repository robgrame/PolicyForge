namespace PolicyForge.Contracts.Configuration;

/// <summary>
/// The kind of configuration a <see cref="ConfigurationItem"/> represents. Each value maps to a
/// server-side provider that validates/compiles the item and (eventually) a client-side handler
/// that applies and reports it. New domains are added here without touching the core engine.
/// </summary>
public enum ProviderType
{
    /// <summary>A policy referenced from an imported ADMX namespace. Compiles down to one or more RegistryValue instructions.</summary>
    AdmxPolicy = 0,

    /// <summary>An arbitrary registry value (GPP-style).</summary>
    RegistryValue = 1,

    /// <summary>A Windows service desired state (startup type, running state).</summary>
    WindowsService = 2,

    /// <summary>A Windows scheduled task.</summary>
    ScheduledTask = 3,

    /// <summary>A file, folder or shortcut on disk.</summary>
    FileResource = 4,

    /// <summary>Local group membership.</summary>
    LocalGroupMembership = 5,

    /// <summary>A system or user environment variable.</summary>
    EnvironmentVariable = 6,
}

/// <summary>Windows registry hive.</summary>
public enum RegistryHive
{
    Hklm = 0,
    Hkcu = 1,
    Hkcr = 2,
    Hku = 3,
    Hkcc = 4,
}

/// <summary>Registry value data type (mirrors <c>Microsoft.Win32.RegistryValueKind</c> / PowerShell <c>PropertyType</c>).</summary>
public enum RegistryValueKind
{
    String = 0,        // REG_SZ
    ExpandString = 1,  // REG_EXPAND_SZ
    MultiString = 2,   // REG_MULTI_SZ
    Dword = 3,         // REG_DWORD
    Qword = 4,         // REG_QWORD
    Binary = 5,        // REG_BINARY
}

/// <summary>Whether a resource must be present (enforced) or absent (removed).</summary>
public enum EnsureState
{
    Present = 0,
    Absent = 1,
}
