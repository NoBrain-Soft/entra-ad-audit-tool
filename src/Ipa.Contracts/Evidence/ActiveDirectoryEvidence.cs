namespace Ipa.Contracts.Evidence;

/// <summary>Well-known user-account-control flags surfaced by the normaliser.</summary>
[Flags]
public enum AdAccountFlags
{
    None = 0,
    Disabled = 1 << 0,
    PasswordNeverExpires = 1 << 1,
    PasswordNotRequired = 1 << 2,
    DoesNotRequirePreAuth = 1 << 3,
    TrustedForDelegation = 1 << 4,
    TrustedToAuthForDelegation = 1 << 5,
    NotDelegated = 1 << 6,
    UseDesKeyOnly = 1 << 7,
    SmartCardRequired = 1 << 8,
    LockedOut = 1 << 9,
    PasswordExpired = 1 << 10,
}

/// <summary>Kerberos delegation configured on an account.</summary>
public enum AdDelegationKind
{
    None,
    Unconstrained,
    ConstrainedKerberosOnly,
    ConstrainedWithProtocolTransition,
    ResourceBasedConstrained,
}

/// <summary>A normalised Active Directory security principal.</summary>
public sealed record AdPrincipal
{
    public required string Sid { get; init; }

    /// <summary>
    /// The object's globally unique identifier. This is the value a synchronised cloud object
    /// encodes as its immutable identifier, so it is the authoritative hybrid matching anchor.
    /// </summary>
    public Guid? ObjectGuid { get; init; }

    public required string DistinguishedName { get; init; }
    public required string SamAccountName { get; init; }
    public string? UserPrincipalName { get; init; }
    public string? DisplayName { get; init; }
    public required string DomainSid { get; init; }
    public string? DomainDnsName { get; init; }
    public DateTimeOffset? WhenCreated { get; init; }
    public DateTimeOffset? LastLogonTimestamp { get; init; }
    public DateTimeOffset? PasswordLastSet { get; init; }
    public AdAccountFlags Flags { get; init; }
    public AdDelegationKind Delegation { get; init; } = AdDelegationKind.None;
    public IReadOnlyList<string> ServicePrincipalNames { get; init; } = [];
    public IReadOnlyList<string> AllowedToDelegateTo { get; init; } = [];
    public IReadOnlyList<string> SidHistory { get; init; } = [];
    public bool AdminCount { get; init; }
    public int? PrimaryGroupId { get; init; }
    public string? ObjectClass { get; init; }
}

/// <summary>A normalised Active Directory computer account.</summary>
public sealed record AdComputer
{
    public required string Sid { get; init; }
    public required string DistinguishedName { get; init; }
    public required string SamAccountName { get; init; }
    public string? DnsHostName { get; init; }
    public string? OperatingSystem { get; init; }
    public string? OperatingSystemVersion { get; init; }
    public DateTimeOffset? LastLogonTimestamp { get; init; }
    public DateTimeOffset? WhenCreated { get; init; }
    public AdAccountFlags Flags { get; init; }
    public AdDelegationKind Delegation { get; init; } = AdDelegationKind.None;
    public IReadOnlyList<string> AllowedToDelegateTo { get; init; } = [];
    public bool IsDomainController { get; init; }
    public bool HasLapsPassword { get; init; }
    public DateTimeOffset? LapsPasswordExpiry { get; init; }
}

/// <summary>Group scope as stored in <c>groupType</c>.</summary>
public enum AdGroupScope
{
    DomainLocal,
    Global,
    Universal,
    BuiltinLocal,
}

/// <summary>A normalised Active Directory group with resolved direct membership.</summary>
public sealed record AdGroup
{
    public required string Sid { get; init; }
    public required string DistinguishedName { get; init; }
    public required string SamAccountName { get; init; }
    public required string DomainSid { get; init; }
    public AdGroupScope Scope { get; init; } = AdGroupScope.Global;
    public bool IsSecurityGroup { get; init; } = true;
    public bool AdminCount { get; init; }

    /// <summary>Distinguished names of direct members (users, computers and nested groups).</summary>
    public IReadOnlyList<string> MemberDistinguishedNames { get; init; } = [];
}

/// <summary>Access-control entry rights the tool reasons about.</summary>
[Flags]
public enum AdAceRight
{
    None = 0,
    GenericAll = 1 << 0,
    GenericWrite = 1 << 1,
    WriteDacl = 1 << 2,
    WriteOwner = 1 << 3,
    WriteProperty = 1 << 4,
    ExtendedRight = 1 << 5,
    AllExtendedRights = 1 << 6,
    DeleteChild = 1 << 7,
    CreateChild = 1 << 8,
    Self = 1 << 9,
}

/// <summary>A normalised access-control entry on a directory object.</summary>
public sealed record AdAccessControlEntry
{
    public required string ObjectDistinguishedName { get; init; }
    public required string ObjectClass { get; init; }
    public required string TrusteeSid { get; init; }
    public string? TrusteeName { get; init; }
    public required AdAceRight Rights { get; init; }

    /// <summary>Schema GUID of the property set or extended right, when the ACE is object-specific.</summary>
    public string? ObjectTypeGuid { get; init; }

    /// <summary>Friendly name of the extended right, for example <c>DS-Replication-Get-Changes-All</c>.</summary>
    public string? ExtendedRightName { get; init; }

    public bool IsInherited { get; init; }
    public bool IsDeny { get; init; }
}

/// <summary>Trust direction as reported by <c>trustDirection</c>.</summary>
public enum AdTrustDirection
{
    Disabled = 0,
    Inbound = 1,
    Outbound = 2,
    Bidirectional = 3,
}

/// <summary>A normalised domain trust.</summary>
public sealed record AdTrust
{
    public required string SourceDomain { get; init; }
    public required string TargetDomain { get; init; }
    public required AdTrustDirection Direction { get; init; }

    /// <summary>Raw <c>trustAttributes</c> value, retained so new flags remain inspectable.</summary>
    public int TrustAttributes { get; init; }

    public bool IsTransitive { get; init; }
    public bool IsForestTrust { get; init; }
    public bool IsExternal { get; init; }

    /// <summary>True when quarantine (SID filtering) is enabled on the trust.</summary>
    public bool SidFilteringEnabled { get; init; }

    /// <summary>True when SID history is explicitly enabled across the trust.</summary>
    public bool SidHistoryEnabled { get; init; }

    public bool SelectiveAuthentication { get; init; }
    public DateTimeOffset? WhenCreated { get; init; }
}

/// <summary>Domain password and lockout policy read from the domain naming context.</summary>
public sealed record AdPasswordPolicy
{
    public required string DomainDnsName { get; init; }
    public int MinimumPasswordLength { get; init; }
    public int PasswordHistoryLength { get; init; }
    public TimeSpan MinimumPasswordAge { get; init; }
    public TimeSpan MaximumPasswordAge { get; init; }
    public bool ComplexityEnabled { get; init; }
    public bool ReversibleEncryptionEnabled { get; init; }
    public int LockoutThreshold { get; init; }
    public TimeSpan LockoutDuration { get; init; }
    public TimeSpan LockoutObservationWindow { get; init; }

    /// <summary>True when at least one fine-grained password policy object exists.</summary>
    public bool HasFineGrainedPolicies { get; init; }
}

/// <summary>A domain within the assessed forest.</summary>
public sealed record AdDomain
{
    public required string DnsName { get; init; }
    public required string NetBiosName { get; init; }
    public required string DomainSid { get; init; }
    public required string DistinguishedName { get; init; }
    public int FunctionalLevel { get; init; }
    public int MachineAccountQuota { get; init; }
    public DateTimeOffset? KrbtgtPasswordLastSet { get; init; }
    public AdPasswordPolicy? PasswordPolicy { get; init; }
    public bool IsRootDomain { get; init; }
    public bool RecycleBinEnabled { get; init; }
}

/// <summary>A domain controller discovered through LDAP.</summary>
public sealed record AdDomainController
{
    public required string DnsHostName { get; init; }
    public required string DomainDnsName { get; init; }
    public string? SiteName { get; init; }
    public string? OperatingSystem { get; init; }
    public bool IsGlobalCatalog { get; init; }
    public bool IsReadOnly { get; init; }
    public IReadOnlyList<string> FsmoRoles { get; init; } = [];

    /// <summary>True when LDAPS was negotiated successfully against this controller.</summary>
    public bool LdapsAvailable { get; init; }
}

/// <summary>A replication site and its subnets.</summary>
public sealed record AdSite
{
    public required string Name { get; init; }
    public IReadOnlyList<string> Subnets { get; init; } = [];
    public IReadOnlyList<string> DomainControllers { get; init; } = [];
    public IReadOnlyList<string> SiteLinks { get; init; } = [];
}

/// <summary>The forest-wide view assembled from RootDSE and the configuration partition.</summary>
public sealed record AdForest
{
    public required string ForestRootDomain { get; init; }
    public int ForestFunctionalLevel { get; init; }
    public int SchemaVersion { get; init; }
    public string? SchemaNamingContext { get; init; }
    public string? ConfigurationNamingContext { get; init; }
    public IReadOnlyList<string> DomainNamingContexts { get; init; } = [];
    public IReadOnlyList<string> UpnSuffixes { get; init; } = [];
    public DateTimeOffset? CollectedFromServerTime { get; init; }
}

/// <summary>The complete normalised Active Directory view handed to rule evaluators.</summary>
public sealed record ActiveDirectoryEvidence
{
    public required AdForest Forest { get; init; }
    public IReadOnlyList<AdDomain> Domains { get; init; } = [];
    public IReadOnlyList<AdDomainController> DomainControllers { get; init; } = [];
    public IReadOnlyList<AdSite> Sites { get; init; } = [];
    public IReadOnlyList<AdTrust> Trusts { get; init; } = [];
    public IReadOnlyList<AdPrincipal> Users { get; init; } = [];
    public IReadOnlyList<AdComputer> Computers { get; init; } = [];
    public IReadOnlyList<AdGroup> Groups { get; init; } = [];
    public IReadOnlyList<AdAccessControlEntry> AccessControlEntries { get; init; } = [];
    public IReadOnlyList<GroupPolicyObject> GroupPolicies { get; init; } = [];
    public AdCertificateServicesEvidence? CertificateServices { get; init; }

    /// <summary>Timestamp used as "now" by every age-based rule, so recalculation is reproducible.</summary>
    public required DateTimeOffset ReferenceTime { get; init; }
}
