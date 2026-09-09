namespace Ipa.Contracts.Evidence;

/// <summary>
/// How a hybrid identity match was established. Display name and mail address alone are never
/// sufficient: a match built only from those signals becomes a review item, not a match.
/// </summary>
public enum HybridMatchMethod
{
    /// <summary>Matched on <c>onPremisesSecurityIdentifier</c> against the on-premises object SID.</summary>
    SecurityIdentifier,

    /// <summary>Matched on the immutable id derived from the on-premises object GUID.</summary>
    ImmutableId,

    /// <summary>Matched on <c>onPremisesDistinguishedName</c>.</summary>
    DistinguishedName,

    /// <summary>Matched on a user principal name whose suffix is a verified tenant domain.</summary>
    VerifiedUserPrincipalName,
}

/// <summary>Confidence attached to a hybrid identity match.</summary>
public enum HybridMatchConfidence
{
    /// <summary>Derived from an authoritative synchronisation anchor.</summary>
    Authoritative,

    /// <summary>Derived from a strong but non-anchor identifier.</summary>
    Strong,

    /// <summary>Requires operator review before it is treated as a match.</summary>
    Review,
}

/// <summary>A correlated on-premises and cloud identity.</summary>
public sealed record HybridIdentityMatch
{
    public required string AdSid { get; init; }
    public required string AdDistinguishedName { get; init; }
    public required string EntraObjectId { get; init; }
    public required string EntraUserPrincipalName { get; init; }
    public required HybridMatchMethod Method { get; init; }
    public required HybridMatchConfidence Confidence { get; init; }

    /// <summary>The identifier values that produced the match, for the evidence appendix.</summary>
    public IReadOnlyList<string> MatchSignals { get; init; } = [];
}

/// <summary>An ambiguous or contradictory correlation the operator must resolve.</summary>
public sealed record HybridReviewItem
{
    public required string Reason { get; init; }
    public IReadOnlyList<string> AdCandidates { get; init; } = [];
    public IReadOnlyList<string> EntraCandidates { get; init; } = [];
    public string? Detail { get; init; }
}

/// <summary>A detected directory-synchronisation service account.</summary>
public sealed record SyncServiceAccount
{
    public required string Identifier { get; init; }
    public required AssessmentSource Source { get; init; }
    public required string DisplayName { get; init; }

    /// <summary>Directory roles or on-premises privileges held by the account.</summary>
    public IReadOnlyList<string> Privileges { get; init; } = [];

    /// <summary>True when the account is excluded from Conditional Access enforcement.</summary>
    public bool ExcludedFromConditionalAccess { get; init; }

    public bool MfaRegistered { get; init; }
    public DateTimeOffset? LastSignIn { get; init; }
}

/// <summary>Federation configuration for one verified domain.</summary>
public sealed record FederationConfiguration
{
    public required string DomainName { get; init; }
    public required string AuthenticationType { get; init; }
    public string? IssuerUri { get; init; }
    public DateTimeOffset? SigningCertificateExpiry { get; init; }
    public bool SupportsMfa { get; init; }

    /// <summary>True when the federation trust permits the unsupported-by-default sign-on bypass.</summary>
    public bool PromptLoginBehaviourWeak { get; init; }
}

/// <summary>The complete normalised hybrid view handed to rule evaluators.</summary>
public sealed record HybridEvidence
{
    public IReadOnlyList<HybridIdentityMatch> Matches { get; init; } = [];
    public IReadOnlyList<HybridReviewItem> ReviewItems { get; init; } = [];
    public IReadOnlyList<SyncServiceAccount> SyncServiceAccounts { get; init; } = [];
    public IReadOnlyList<FederationConfiguration> Federation { get; init; } = [];

    /// <summary>On-premises SIDs of privileged accounts that also hold a privileged cloud role.</summary>
    public IReadOnlyList<string> PrivilegedSynchronisedAccountSids { get; init; } = [];

    /// <summary>Cloud objects that claim on-premises origin but have no matching directory object.</summary>
    public IReadOnlyList<string> OrphanedCloudObjectIds { get; init; } = [];

    /// <summary>Immutable identifiers claimed by more than one cloud object.</summary>
    public IReadOnlyList<string> DuplicateAnchors { get; init; } = [];

    public DateTimeOffset? LastDirectorySyncTime { get; init; }

    /// <summary>Timestamp used as "now" by every age-based rule, so recalculation is reproducible.</summary>
    public required DateTimeOffset ReferenceTime { get; init; }
}
