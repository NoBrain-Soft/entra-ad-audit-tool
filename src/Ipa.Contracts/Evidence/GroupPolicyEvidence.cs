namespace Ipa.Contracts.Evidence;

/// <summary>Where a GPO is linked and whether the link is enforced or disabled.</summary>
public sealed record GpoLink
{
    public required string TargetDistinguishedName { get; init; }

    /// <summary>Site, domain or organisational unit.</summary>
    public required string TargetType { get; init; }

    public bool Enforced { get; init; }
    public bool LinkEnabled { get; init; } = true;
    public int Order { get; init; }
}

/// <summary>One value parsed from a <c>registry.pol</c> file.</summary>
public sealed record RegistryPolicySetting
{
    public required string KeyPath { get; init; }
    public required string ValueName { get; init; }

    /// <summary>Registry value type, using the standard <c>REG_*</c> numbering.</summary>
    public required int ValueType { get; init; }

    /// <summary>Rendered value. Binary values are hex-encoded.</summary>
    public required string Value { get; init; }

    /// <summary>True for a machine-scope value, false for a user-scope value.</summary>
    public bool IsMachineScope { get; init; } = true;
}

/// <summary>A setting parsed from a security template (<c>GptTmpl.inf</c>).</summary>
public sealed record SecurityTemplateSetting
{
    /// <summary>Section of the template, for example <c>System Access</c> or <c>Privilege Rights</c>.</summary>
    public required string Section { get; init; }

    public required string Name { get; init; }

    public required string Value { get; init; }

    /// <summary>Trustees for privilege-rights entries, normalised to SIDs where possible.</summary>
    public IReadOnlyList<string> Trustees { get; init; } = [];
}

/// <summary>An ACE on the GPO container or its SYSVOL folder.</summary>
public sealed record GpoPermissionEntry
{
    public required string TrusteeSid { get; init; }
    public string? TrusteeName { get; init; }
    public required string Rights { get; init; }
    public required bool AppliesToSysvol { get; init; }
    public bool IsInherited { get; init; }
}

/// <summary>
/// A Group Policy Preferences file that stores a credential. The value is never retained: only
/// the location and the element are recorded, which is all a finding needs.
/// </summary>
public sealed record GpoPreferencePasswordArtifact
{
    /// <summary>SYSVOL-relative path of the preferences file.</summary>
    public required string RelativePath { get; init; }

    /// <summary>Preference element carrying the credential, for example <c>Groups/User</c>.</summary>
    public required string Element { get; init; }

    /// <summary>Account name the credential belongs to, when the file names one.</summary>
    public string? AccountName { get; init; }
}

/// <summary>A normalised Group Policy object combining directory metadata and SYSVOL content.</summary>
public sealed record GroupPolicyObject
{
    public required string Guid { get; init; }
    public required string DisplayName { get; init; }
    public required string DomainDnsName { get; init; }
    public string? FileSystemPath { get; init; }

    /// <summary>Version stored on the directory object.</summary>
    public int DirectoryVersion { get; init; }

    /// <summary>Version stored in <c>GPT.INI</c> in SYSVOL.</summary>
    public int SysvolVersion { get; init; }

    /// <summary>True when the SYSVOL folder for this GPO could not be read.</summary>
    public bool SysvolUnavailable { get; init; }

    public bool ComputerSettingsDisabled { get; init; }
    public bool UserSettingsDisabled { get; init; }
    public string? WmiFilter { get; init; }
    public DateTimeOffset? WhenCreated { get; init; }
    public DateTimeOffset? WhenChanged { get; init; }
    public string? OwnerSid { get; init; }

    public IReadOnlyList<GpoLink> Links { get; init; } = [];
    public IReadOnlyList<RegistryPolicySetting> RegistrySettings { get; init; } = [];
    public IReadOnlyList<SecurityTemplateSetting> SecuritySettings { get; init; } = [];
    public IReadOnlyList<GpoPermissionEntry> Permissions { get; init; } = [];

    /// <summary>
    /// Group Policy Preferences files in SYSVOL that carry a <c>cpassword</c> attribute. Only the
    /// file path and attribute name are recorded: the obfuscated value itself is never stored.
    /// </summary>
    public IReadOnlyList<GpoPreferencePasswordArtifact> PreferencePasswords { get; init; } = [];

    /// <summary>True when the GPO has no enabled link anywhere in the forest.</summary>
    public bool IsUnlinked => Links.Count == 0 || Links.All(link => !link.LinkEnabled);
}
