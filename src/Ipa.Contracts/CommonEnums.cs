namespace Ipa.Contracts;

/// <summary>Identity source that produced a piece of evidence or a rule result.</summary>
public enum AssessmentSource
{
    /// <summary>On-premises Active Directory forest (LDAP, SYSVOL, Group Policy).</summary>
    ActiveDirectory,

    /// <summary>Microsoft Entra ID tenant (Microsoft Graph).</summary>
    Entra,

    /// <summary>Correlation across the Active Directory forest and the Entra tenant.</summary>
    Hybrid,

    /// <summary>Operator-imported material such as a Microsoft security baseline.</summary>
    ImportedBaseline,

    /// <summary>Operator-entered material such as an attestation or attachment.</summary>
    Operator,
}

/// <summary>
/// Coarse grouping used for scope selection, permission scoping and score categories.
/// Each rule belongs to exactly one check group.
/// </summary>
public enum CheckGroup
{
    // Active Directory
    AdPrivilegedAccess,
    AdAccountHygiene,
    AdDelegationAndAcl,
    AdDomainPolicy,
    AdTrustsAndTopology,
    AdGroupPolicy,
    AdCertificateServices,

    // Entra ID
    EntraPrivilegedAccess,
    EntraAuthentication,
    EntraConditionalAccess,
    EntraApplications,
    EntraDirectoryHygiene,
    EntraSecureScore,

    // Hybrid
    HybridIdentityCorrelation,
    HybridPrivilegeExposure,
    HybridSynchronisation,

    // Baseline comparison (reported separately from the posture score)
    BaselineConformity,
}

/// <summary>Sensitivity classification driving report redaction defaults.</summary>
public enum Sensitivity
{
    /// <summary>Aggregate counts and configuration state; safe for a summary report.</summary>
    Summary = 0,

    /// <summary>Object names, distinguished names and identifiers.</summary>
    ObjectIdentifying = 1,

    /// <summary>Raw directory attributes, membership lists and imported attachments.</summary>
    RawAttribute = 2,
}

/// <summary>Availability of a data set that a rule depends upon.</summary>
public enum EvidenceAvailability
{
    /// <summary>Collected successfully and usable for evaluation.</summary>
    Collected,

    /// <summary>Not collected: the check group was disabled or the source was not connected.</summary>
    NotSelected,

    /// <summary>Not collected: consent, role or licence prerequisites were missing.</summary>
    PermissionDenied,

    /// <summary>Not collected: the endpoint or protocol is unavailable in this environment.</summary>
    Unsupported,

    /// <summary>Collection was attempted and failed.</summary>
    Error,
}
