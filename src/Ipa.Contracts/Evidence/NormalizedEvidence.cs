using Ipa.Contracts.Baselines;

namespace Ipa.Contracts.Evidence;

/// <summary>
/// Availability of one named evidence set, together with the reason it is missing. Rules consult
/// this map so that a missing data set produces <c>NotCollected</c> instead of a misleading pass.
/// </summary>
public sealed record EvidenceAvailabilityEntry
{
    public required string EvidenceKey { get; init; }
    public required EvidenceAvailability Availability { get; init; }
    public string? Reason { get; init; }

    public bool IsAvailable => Availability == EvidenceAvailability.Collected;
}

/// <summary>
/// The complete, network-free view a rule evaluator sees. Everything a rule needs must be
/// reachable from this object: evaluators never perform input or output of any kind.
/// </summary>
public sealed record NormalizedEvidence
{
    public ActiveDirectoryEvidence? ActiveDirectory { get; init; }
    public EntraEvidence? Entra { get; init; }
    public HybridEvidence? Hybrid { get; init; }
    public BaselineComparison? BaselineComparison { get; init; }

    /// <summary>Availability of each named evidence set, keyed by evidence key.</summary>
    public IReadOnlyDictionary<string, EvidenceAvailabilityEntry> Availability { get; init; } =
        new Dictionary<string, EvidenceAvailabilityEntry>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Auditable records backing the report's evidence appendix.</summary>
    public IReadOnlyList<EvidenceRecord> Records { get; init; } = [];

    /// <summary>Reference instant used by every age-based rule. Fixed per assessment run.</summary>
    public required DateTimeOffset ReferenceTime { get; init; }

    /// <summary>Returns the availability of an evidence set, defaulting to not selected.</summary>
    public EvidenceAvailabilityEntry GetAvailability(string evidenceKey)
    {
        ArgumentNullException.ThrowIfNull(evidenceKey);

        return Availability.TryGetValue(evidenceKey, out var entry)
            ? entry
            : new EvidenceAvailabilityEntry
            {
                EvidenceKey = evidenceKey,
                Availability = EvidenceAvailability.NotSelected,
                Reason = "The evidence set was not part of this assessment.",
            };
    }

    /// <summary>True when every supplied evidence key was collected successfully.</summary>
    public bool HasAll(params string[] evidenceKeys)
    {
        ArgumentNullException.ThrowIfNull(evidenceKeys);
        return evidenceKeys.All(key => GetAvailability(key).IsAvailable);
    }
}

/// <summary>
/// Canonical evidence keys. Rules declare their requirements with these constants so that
/// availability is checked consistently across collectors, rules and the coverage calculation.
/// </summary>
public static class EvidenceKeys
{
    public const string AdForest = "ad.forest";
    public const string AdDomains = "ad.domains";
    public const string AdUsers = "ad.users";
    public const string AdComputers = "ad.computers";
    public const string AdGroups = "ad.groups";
    public const string AdAcls = "ad.acls";
    public const string AdTrusts = "ad.trusts";
    public const string AdSites = "ad.sites";
    public const string AdPasswordPolicy = "ad.passwordPolicy";
    public const string AdGroupPolicy = "ad.groupPolicy";
    public const string AdSysvol = "ad.sysvol";
    public const string AdCertificateServices = "ad.certificateServices";

    public const string EntraTenant = "entra.tenant";
    public const string EntraUsers = "entra.users";
    public const string EntraGroups = "entra.groups";
    public const string EntraDevices = "entra.devices";
    public const string EntraRoles = "entra.roleAssignments";
    public const string EntraApplications = "entra.applications";
    public const string EntraServicePrincipals = "entra.servicePrincipals";
    public const string EntraConditionalAccess = "entra.conditionalAccess";
    public const string EntraAuthenticationMethods = "entra.authenticationMethods";
    public const string EntraRegistrationDetails = "entra.registrationDetails";
    public const string EntraSignInActivity = "entra.signInActivity";
    public const string EntraLegacyAuthentication = "entra.legacyAuthentication";
    public const string EntraSecureScore = "entra.secureScore";
    public const string EntraPrivilegedIdentityManagement = "entra.pim";

    public const string HybridMatches = "hybrid.matches";
    public const string HybridSync = "hybrid.sync";
    public const string HybridFederation = "hybrid.federation";

    public const string BaselineComparison = "baseline.comparison";

    /// <summary>All keys, used by the coverage report and by rule-pack validation.</summary>
    public static IReadOnlyList<string> All { get; } =
    [
        AdForest, AdDomains, AdUsers, AdComputers, AdGroups, AdAcls, AdTrusts, AdSites,
        AdPasswordPolicy, AdGroupPolicy, AdSysvol, AdCertificateServices,
        EntraTenant, EntraUsers, EntraGroups, EntraDevices, EntraRoles, EntraApplications,
        EntraServicePrincipals, EntraConditionalAccess, EntraAuthenticationMethods,
        EntraRegistrationDetails, EntraSignInActivity, EntraLegacyAuthentication,
        EntraSecureScore, EntraPrivilegedIdentityManagement,
        HybridMatches, HybridSync, HybridFederation,
        BaselineComparison,
    ];
}
