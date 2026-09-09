using Ipa.Contracts;
using Ipa.Contracts.Rules;

namespace Ipa.Rules.Engine;

/// <summary>Builds rule definitions with the pack's conventions applied consistently.</summary>
public static class RuleFactory
{
    /// <summary>
    /// Creates a definition. The weight defaults to the severity band maximum; a rule may pass a
    /// lower value but the definition rejects anything higher.
    /// </summary>
    public static RuleDefinition Create(
        string id,
        int version,
        string title,
        RuleDomain domain,
        CheckGroup group,
        RuleSeverity severity,
        string rationale,
        string remediation,
        string[] evidenceKeys,
        string? applicability = null,
        int? weight = null,
        (string Framework, string ControlId, string Relevance)[]? mappings = null,
        (string Title, string Url)[]? references = null,
        string[]? permissions = null)
    {
        var definition = new RuleDefinition
        {
            Id = new RuleId(id),
            Version = version,
            Title = title,
            Domain = domain,
            Group = group,
            Severity = severity,
            Weight = weight ?? SeverityWeights.Maximum(severity),
            Rationale = rationale,
            Remediation = remediation,
            Applicability = applicability ?? "Applies to every assessed environment of this domain.",
            RequiredEvidence = evidenceKeys
                .Select(key => new EvidenceRequirement(key, EvidenceDescriptions.Describe(key)))
                .ToList(),
            FrameworkMappings = (mappings ?? [])
                .Select(mapping => new FrameworkMapping
                {
                    Framework = mapping.Framework,
                    ControlId = mapping.ControlId,
                    Relevance = mapping.Relevance,
                })
                .ToList(),
            References = (references ?? [])
                .Select(reference => new ReferenceLink(reference.Title, reference.Url))
                .ToList(),
            RequiredPermissions = permissions ?? [],
        };

        definition.Validate();
        return definition;
    }

    /// <summary>Convenience for the ISO/IEC 27001:2022 framework identifier.</summary>
    public const string Iso27001 = "ISO/IEC 27001:2022";
}

/// <summary>Human-readable descriptions of the canonical evidence keys.</summary>
public static class EvidenceDescriptions
{
    private static readonly Dictionary<string, string> Descriptions = new(StringComparer.OrdinalIgnoreCase)
    {
        [Contracts.Evidence.EvidenceKeys.AdForest] = "Forest metadata from RootDSE and the configuration partition",
        [Contracts.Evidence.EvidenceKeys.AdDomains] = "Domain objects and functional levels",
        [Contracts.Evidence.EvidenceKeys.AdUsers] = "User accounts and their account-control flags",
        [Contracts.Evidence.EvidenceKeys.AdComputers] = "Computer accounts and delegation settings",
        [Contracts.Evidence.EvidenceKeys.AdGroups] = "Groups and their direct membership",
        [Contracts.Evidence.EvidenceKeys.AdAcls] = "Access-control entries on directory objects",
        [Contracts.Evidence.EvidenceKeys.AdTrusts] = "Domain and forest trusts",
        [Contracts.Evidence.EvidenceKeys.AdSites] = "Sites, subnets and site links",
        [Contracts.Evidence.EvidenceKeys.AdPasswordPolicy] = "Domain password and lockout policy",
        [Contracts.Evidence.EvidenceKeys.AdGroupPolicy] = "Group Policy objects, links and permissions",
        [Contracts.Evidence.EvidenceKeys.AdSysvol] = "SYSVOL policy content: registry.pol and security templates",
        [Contracts.Evidence.EvidenceKeys.AdCertificateServices] = "Certificate templates and enrolment services",
        [Contracts.Evidence.EvidenceKeys.EntraTenant] = "Tenant organisation, verified domains and service plans",
        [Contracts.Evidence.EvidenceKeys.EntraUsers] = "Directory users, including guests",
        [Contracts.Evidence.EvidenceKeys.EntraGroups] = "Directory groups and membership",
        [Contracts.Evidence.EvidenceKeys.EntraDevices] = "Registered and joined devices",
        [Contracts.Evidence.EvidenceKeys.EntraRoles] = "Directory role assignments",
        [Contracts.Evidence.EvidenceKeys.EntraApplications] = "Application registrations and credentials",
        [Contracts.Evidence.EvidenceKeys.EntraServicePrincipals] = "Service principals and granted permissions",
        [Contracts.Evidence.EvidenceKeys.EntraConditionalAccess] = "Conditional Access policies",
        [Contracts.Evidence.EvidenceKeys.EntraAuthenticationMethods] = "Authentication method policy and security defaults",
        [Contracts.Evidence.EvidenceKeys.EntraRegistrationDetails] = "Authentication method registration details",
        [Contracts.Evidence.EvidenceKeys.EntraSignInActivity] = "Sign-in activity timestamps",
        [Contracts.Evidence.EvidenceKeys.EntraLegacyAuthentication] = "Legacy authentication observations from sign-in logs",
        [Contracts.Evidence.EvidenceKeys.EntraSecureScore] = "Microsoft Secure Score snapshot",
        [Contracts.Evidence.EvidenceKeys.EntraPrivilegedIdentityManagement] = "Privileged Identity Management eligibility",
        [Contracts.Evidence.EvidenceKeys.HybridMatches] = "Correlated on-premises and cloud identities",
        [Contracts.Evidence.EvidenceKeys.HybridSync] = "Directory synchronisation configuration and accounts",
        [Contracts.Evidence.EvidenceKeys.HybridFederation] = "Federation configuration per verified domain",
        [Contracts.Evidence.EvidenceKeys.BaselineComparison] = "Comparison against the imported Microsoft baseline",
    };

    /// <summary>Returns the description of an evidence key, or the key itself when unknown.</summary>
    public static string Describe(string evidenceKey) =>
        Descriptions.TryGetValue(evidenceKey, out var description) ? description : evidenceKey;
}
