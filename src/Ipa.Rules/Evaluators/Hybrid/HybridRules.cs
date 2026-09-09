using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;

namespace Ipa.Rules.Evaluators.Hybrid;

/// <summary>Synchronisation anchors are unique across the tenant.</summary>
public sealed class DuplicateAnchorRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "HYB-COR-001",
        version: 1,
        title: "Synchronisation anchors are unique",
        domain: RuleDomain.Hybrid,
        group: CheckGroup.HybridIdentityCorrelation,
        severity: RuleSeverity.High,
        rationale: "Two cloud objects claiming the same on-premises anchor means the directory " +
                   "synchronisation model is ambiguous. Access decisions then depend on which " +
                   "object a given service resolves, which is neither predictable nor auditable.",
        remediation: "Resolve the duplicate anchors: remove or re-anchor the objects that should " +
                     "not exist, then run a full synchronisation cycle and confirm the conflict is cleared.",
        evidenceKeys: [EvidenceKeys.HybridMatches],
        mappings: [(RuleFactory.Iso27001, "A.5.16", "Integrity of the identity lifecycle.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Hybrid!;

        return evidence.DuplicateAnchors.Count == 0
            ? Pass(context, "Every synchronisation anchor is claimed by exactly one cloud object.")
            : Fail(
                context,
                $"{evidence.DuplicateAnchors.Count} synchronisation anchor(s) are claimed by more " +
                "than one cloud object.",
                RuleHelpers.Cap(evidence.DuplicateAnchors.Select(anchor => new AffectedObject
                {
                    Identifier = anchor,
                    DisplayName = anchor,
                    ObjectType = "anchor",
                    Source = AssessmentSource.Hybrid,
                    Detail = "Claimed by more than one cloud object",
                })));
    }
}

/// <summary>Cloud objects claiming on-premises origin have a matching directory object.</summary>
public sealed class OrphanedCloudObjectRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "HYB-COR-002",
        version: 1,
        title: "Synchronised cloud objects have a matching directory object",
        domain: RuleDomain.Hybrid,
        group: CheckGroup.HybridIdentityCorrelation,
        severity: RuleSeverity.Medium,
        rationale: "A cloud object marked as synchronised with no surviving on-premises object " +
                   "cannot be managed from either side: the directory no longer controls it, and " +
                   "the tenant refuses changes because it believes the directory does.",
        remediation: "Restore the on-premises object, or convert the orphaned cloud object to " +
                     "cloud-only management before removing or re-provisioning it.",
        evidenceKeys: [EvidenceKeys.HybridMatches],
        mappings: [(RuleFactory.Iso27001, "A.5.16", "Identity lifecycle consistency.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Hybrid!;

        return evidence.OrphanedCloudObjectIds.Count == 0
            ? Pass(context, "Every cloud object marked as synchronised has a matching directory object.")
            : Fail(
                context,
                $"{evidence.OrphanedCloudObjectIds.Count} cloud object(s) are marked as " +
                "synchronised but have no matching on-premises object.",
                RuleHelpers.Cap(evidence.OrphanedCloudObjectIds.Select(id => new AffectedObject
                {
                    Identifier = id,
                    DisplayName = id,
                    ObjectType = "cloudObject",
                    Source = AssessmentSource.Hybrid,
                    Detail = "No matching on-premises object",
                })));
    }
}

/// <summary>Ambiguous correlations are surfaced for operator review.</summary>
public sealed class AmbiguousCorrelationRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "HYB-COR-003",
        version: 1,
        title: "Hybrid correlation has no unresolved ambiguity",
        domain: RuleDomain.Hybrid,
        group: CheckGroup.HybridIdentityCorrelation,
        severity: RuleSeverity.Low,
        rationale: "Where an on-premises and a cloud identity cannot be matched on an " +
                   "authoritative anchor, this assessment declines to guess. Those pairs are " +
                   "reported for review rather than silently treated as the same person.",
        remediation: "Review each ambiguous pair and correct the underlying anchor, or record the " +
                     "correct relationship so that later assessments resolve it.",
        evidenceKeys: [EvidenceKeys.HybridMatches],
        mappings: [(RuleFactory.Iso27001, "A.5.16", "Unique attribution of identities.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Hybrid!;

        return evidence.ReviewItems.Count == 0
            ? Pass(context, "Hybrid correlation produced no ambiguous matches.")
            : Fail(
                context,
                $"{evidence.ReviewItems.Count} correlation(s) could not be resolved from an " +
                "authoritative anchor and require operator review.",
                RuleHelpers.Cap(evidence.ReviewItems.Select(item => new AffectedObject
                {
                    Identifier = string.Join("|", item.AdCandidates.Concat(item.EntraCandidates).Take(4)),
                    DisplayName = item.Reason,
                    ObjectType = "correlationReview",
                    Source = AssessmentSource.Hybrid,
                    Detail = item.Detail,
                })));
    }
}

/// <summary>Cloud privilege is not attached to a synchronised on-premises account.</summary>
public sealed class SynchronisedPrivilegedAccountRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "HYB-PRIV-001",
        version: 1,
        title: "Cloud privilege is not held by synchronised accounts",
        domain: RuleDomain.Hybrid,
        group: CheckGroup.HybridPrivilegeExposure,
        severity: RuleSeverity.Critical,
        rationale: "When a synchronised account holds a privileged cloud role, compromising the " +
                   "on-premises directory yields cloud administration too. The password hash of " +
                   "that account is present on domain controllers, and its credential can be reset " +
                   "by anyone with on-premises user administration rights.",
        remediation: "Move privileged cloud roles to dedicated cloud-only accounts protected with " +
                     "phishing-resistant authentication, and remove those roles from synchronised accounts.",
        evidenceKeys: [EvidenceKeys.HybridMatches, EvidenceKeys.EntraRoles],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Separation of privileged access across environments."),
            (RuleFactory.Iso27001, "A.5.23", "Security of cloud service administration."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Hybrid!;

        return evidence.PrivilegedSynchronisedAccountSids.Count == 0
            ? Pass(context, "No synchronised on-premises account holds a privileged cloud role.")
            : Fail(
                context,
                $"{evidence.PrivilegedSynchronisedAccountSids.Count} synchronised on-premises " +
                "account(s) hold a privileged cloud role.",
                RuleHelpers.Cap(evidence.PrivilegedSynchronisedAccountSids.Select(sid =>
                {
                    var match = evidence.Matches.FirstOrDefault(candidate =>
                        string.Equals(candidate.AdSid, sid, StringComparison.OrdinalIgnoreCase));

                    return new AffectedObject
                    {
                        Identifier = sid,
                        DisplayName = match?.EntraUserPrincipalName ?? sid,
                        ObjectType = "hybridUser",
                        Source = AssessmentSource.Hybrid,
                        Detail = match is null
                            ? "Synchronised account with a privileged cloud role"
                            : $"On-premises {match.AdDistinguishedName} holds a privileged cloud role",
                    };
                })));
    }
}

/// <summary>Synchronisation service accounts are protected.</summary>
public sealed class SyncServiceAccountRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "HYB-PRIV-002",
        version: 1,
        title: "Directory synchronisation accounts are protected",
        domain: RuleDomain.Hybrid,
        group: CheckGroup.HybridPrivilegeExposure,
        severity: RuleSeverity.High,
        rationale: "The synchronisation service account can write to the directory and, depending " +
                   "on configuration, reset passwords and update credentials. Excluding it from " +
                   "access policy without a compensating control leaves a high-value account " +
                   "reachable with a password alone.",
        remediation: "Keep synchronisation accounts inside a Conditional Access policy scoped to " +
                     "the synchronisation server's network location, register a strong " +
                     "authentication method where the account supports it, and monitor its sign-ins.",
        evidenceKeys: [EvidenceKeys.HybridSync],
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Protection of accounts holding elevated rights.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Hybrid!;

        if (evidence.SyncServiceAccounts.Count == 0)
        {
            return NotApplicable(
                context,
                "No directory synchronisation service account was identified in either directory.");
        }

        var offenders = evidence.SyncServiceAccounts
            .Where(account => account.ExcludedFromConditionalAccess && !account.MfaRegistered)
            .Select(account => new AffectedObject
            {
                Identifier = account.Identifier,
                DisplayName = account.DisplayName,
                ObjectType = "syncAccount",
                Source = AssessmentSource.Hybrid,
                Detail = "Excluded from Conditional Access with no registered strong method",
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {evidence.SyncServiceAccounts.Count} synchronisation account(s) " +
                            "are covered by access policy or a registered strong method.")
            : Fail(
                context,
                $"{offenders.Count} synchronisation account(s) are excluded from Conditional Access " +
                "with no compensating strong authentication.",
                offenders);
    }
}

/// <summary>On-premises tier-zero accounts are not synchronised to the tenant.</summary>
public sealed class OnPremisesPrivilegeSyncRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "HYB-PRIV-003",
        version: 1,
        title: "On-premises tier-zero accounts are not synchronised",
        domain: RuleDomain.Hybrid,
        group: CheckGroup.HybridPrivilegeExposure,
        severity: RuleSeverity.High,
        rationale: "Synchronising a domain administrator to the tenant exposes that identity to " +
                   "cloud attack paths - password spray, consent phishing and token theft - none " +
                   "of which the on-premises controls can see or stop.",
        remediation: "Exclude the tier-zero organisational unit from directory synchronisation and " +
                     "remove any tier-zero account that is already present in the tenant.",
        evidenceKeys: [EvidenceKeys.HybridMatches, EvidenceKeys.AdGroups, EvidenceKeys.AdUsers, EvidenceKeys.AdDomains],
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Separation of privileged access across environments.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var hybrid = context.Evidence.Hybrid!;
        var activeDirectory = context.Evidence.ActiveDirectory!;

        var resolver = new Support.PrivilegedPrincipalResolver(activeDirectory);
        var tierZeroSids = resolver.TierZeroUsers
            .Select(user => user.Sid)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (tierZeroSids.Count == 0)
        {
            return NotApplicable(context, "No on-premises tier-zero accounts were identified.");
        }

        var offenders = hybrid.Matches
            .Where(match => tierZeroSids.Contains(match.AdSid))
            .Select(match => new AffectedObject
            {
                Identifier = match.AdSid,
                DisplayName = match.EntraUserPrincipalName,
                ObjectType = "hybridUser",
                Source = AssessmentSource.Hybrid,
                Detail = $"On-premises {match.AdDistinguishedName} is present in the tenant " +
                         $"(matched by {match.Method})",
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"None of the {tierZeroSids.Count} on-premises tier-zero account(s) are " +
                            "synchronised to the tenant.")
            : Fail(
                context,
                $"{offenders.Count} on-premises tier-zero account(s) are synchronised to the tenant.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Directory synchronisation is running.</summary>
public sealed class SynchronisationFreshnessRule : RuleBase
{
    public const string ThresholdName = "hybrid.sync.maxAgeHours";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "HYB-SYNC-001",
        version: 1,
        title: "Directory synchronisation is current",
        domain: RuleDomain.Hybrid,
        group: CheckGroup.HybridSynchronisation,
        severity: RuleSeverity.Medium,
        rationale: "When synchronisation stops, disabled and deleted on-premises accounts stay " +
                   "active in the tenant. A leaver who was removed from the directory keeps cloud " +
                   "access for as long as the outage lasts.",
        remediation: "Restore the synchronisation service, and alert on synchronisation age so " +
                     "that a stalled cycle is noticed within hours rather than at the next audit.",
        evidenceKeys: [EvidenceKeys.HybridSync],
        mappings: [(RuleFactory.Iso27001, "A.5.18", "Timely propagation of access changes.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Hybrid!;
        var maxAgeHours = context.Threshold(ThresholdName, 6);

        if (evidence.LastDirectorySyncTime is not { } lastSync)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "The tenant reported no last directory synchronisation time.");
        }

        var ageHours = (context.ReferenceTime - lastSync).TotalHours;

        return ageHours <= maxAgeHours
            ? Pass(context, $"Directory synchronisation last completed {ageHours:F1} hours ago.")
            : Fail(
                context,
                $"Directory synchronisation last completed {ageHours:F1} hours ago, beyond the " +
                $"{maxAgeHours}-hour threshold.");
    }
}

/// <summary>Federation signing certificates are renewed before they expire.</summary>
public sealed class FederationCertificateRule : RuleBase
{
    public const string ThresholdName = "hybrid.federation.warningDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "HYB-SYNC-002",
        version: 1,
        title: "Federation signing certificates are current",
        domain: RuleDomain.Hybrid,
        group: CheckGroup.HybridSynchronisation,
        severity: RuleSeverity.High,
        rationale: "An expired federation signing certificate stops authentication for every user " +
                   "of the federated domain at once. Recovery under that pressure often involves " +
                   "temporarily weakening the configuration.",
        remediation: "Renew the token-signing certificate before expiry and update the tenant's " +
                     "federation settings, with automatic rollover monitored rather than assumed.",
        evidenceKeys: [EvidenceKeys.HybridFederation],
        applicability: "Applies when at least one verified domain is federated.",
        mappings: [(RuleFactory.Iso27001, "A.8.24", "Management of cryptographic certificates.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Hybrid!;
        var warningDays = context.Threshold(ThresholdName, 30);

        var federated = evidence.Federation
            .Where(configuration => string.Equals(configuration.AuthenticationType, "Federated", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (federated.Count == 0)
        {
            return NotApplicable(context, "No verified domain is federated.");
        }

        var horizon = context.ReferenceTime.AddDays(warningDays);

        var offenders = federated
            .Where(configuration => configuration.SigningCertificateExpiry is { } expiry && expiry <= horizon)
            .Select(configuration => new AffectedObject
            {
                Identifier = configuration.DomainName,
                DisplayName = configuration.DomainName,
                ObjectType = "federatedDomain",
                Source = AssessmentSource.Hybrid,
                Detail = $"Signing certificate expires {configuration.SigningCertificateExpiry:yyyy-MM-dd}",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {federated.Count} federated domain(s) have a signing certificate " +
                            $"valid beyond {warningDays} days.")
            : Fail(
                context,
                $"{offenders.Count} federated domain(s) have a signing certificate expiring within " +
                $"{warningDays} days or already expired.",
                offenders);
    }
}

/// <summary>Federated domains pass a multi-factor claim to the tenant.</summary>
public sealed class FederationMfaRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "HYB-SYNC-003",
        version: 1,
        title: "Federated domains support multi-factor claims",
        domain: RuleDomain.Hybrid,
        group: CheckGroup.HybridSynchronisation,
        severity: RuleSeverity.Medium,
        rationale: "If the federation trust does not advertise support for multi-factor claims, " +
                   "the tenant cannot honour a second factor performed on premises, and " +
                   "Conditional Access either double-prompts or cannot enforce the requirement at all.",
        remediation: "Enable the multi-factor claim capability on the federation trust, or migrate " +
                     "the domain to managed authentication so the tenant performs authentication directly.",
        evidenceKeys: [EvidenceKeys.HybridFederation],
        applicability: "Applies when at least one verified domain is federated.",
        mappings: [(RuleFactory.Iso27001, "A.8.5", "Consistent enforcement of secure authentication.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Hybrid!;

        var federated = evidence.Federation
            .Where(configuration => string.Equals(configuration.AuthenticationType, "Federated", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (federated.Count == 0)
        {
            return NotApplicable(context, "No verified domain is federated.");
        }

        var offenders = federated
            .Where(configuration => !configuration.SupportsMfa)
            .Select(configuration => new AffectedObject
            {
                Identifier = configuration.DomainName,
                DisplayName = configuration.DomainName,
                ObjectType = "federatedDomain",
                Source = AssessmentSource.Hybrid,
                Detail = "The federation trust does not advertise multi-factor support",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {federated.Count} federated domain(s) advertise multi-factor support.")
            : Fail(context, $"{offenders.Count} federated domain(s) do not advertise multi-factor support.", offenders);
    }
}
