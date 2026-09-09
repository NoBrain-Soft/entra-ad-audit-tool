using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;

namespace Ipa.Rules.Evaluators.ActiveDirectory;

/// <summary>SID filtering is active on trusts that cross a security boundary.</summary>
public sealed class SidFilteringRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-TRUST-001",
        version: 1,
        title: "SID filtering is enabled on external and forest trusts",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdTrustsAndTopology,
        severity: RuleSeverity.High,
        rationale: "Without SID filtering, an administrator in the trusted domain can inject the " +
                   "SID of a privileged group from this forest into an authentication token and " +
                   "receive that privilege here. The trust boundary stops being a security boundary.",
        remediation: "Enable quarantine (SID filtering) on external trusts and confirm it remains " +
                     "enabled on forest trusts, then re-test any cross-forest application that " +
                     "relies on migrated identities.",
        evidenceKeys: [EvidenceKeys.AdTrusts],
        applicability: "Applies when the forest has at least one external or forest trust.",
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.19", "Security in supplier and partner relationships."),
            (RuleFactory.Iso27001, "A.8.2", "Prevention of privilege injection across boundaries."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        var relevant = evidence.Trusts
            .Where(trust => trust.IsExternal || trust.IsForestTrust)
            .Where(trust => trust.Direction is AdTrustDirection.Inbound or AdTrustDirection.Bidirectional)
            .ToList();

        if (relevant.Count == 0)
        {
            return NotApplicable(
                context,
                "The forest has no inbound external or forest trust, so SID filtering does not apply.");
        }

        var offenders = relevant
            .Where(trust => !trust.SidFilteringEnabled || trust.SidHistoryEnabled)
            .Select(trust => new AffectedObject
            {
                Identifier = $"{trust.SourceDomain}->{trust.TargetDomain}",
                DisplayName = trust.TargetDomain,
                ObjectType = "trust",
                Source = AssessmentSource.ActiveDirectory,
                Detail = trust.SidHistoryEnabled
                    ? "SID history is enabled across the trust"
                    : "SID filtering (quarantine) is not enabled",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {relevant.Count} inbound external or forest trust(s) enforce SID filtering.")
            : Fail(
                context,
                $"{offenders.Count} of {relevant.Count} inbound trust(s) do not enforce SID filtering.",
                offenders);
    }
}

/// <summary>Selective authentication limits which principals can use a trust.</summary>
public sealed class SelectiveAuthenticationRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-TRUST-002",
        version: 1,
        title: "External trusts use selective authentication",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdTrustsAndTopology,
        severity: RuleSeverity.Medium,
        rationale: "Forest-wide authentication over a trust lets every principal in the trusted " +
                   "forest authenticate to every resource here. Selective authentication reduces " +
                   "that to the servers the partnership actually requires.",
        remediation: "Switch inbound external and forest trusts to selective authentication and " +
                     "grant the allowed-to-authenticate right only on the resources the partner needs.",
        evidenceKeys: [EvidenceKeys.AdTrusts],
        applicability: "Applies when the forest has at least one inbound external or forest trust.",
        mappings: [(RuleFactory.Iso27001, "A.5.19", "Managing risk in partner relationships.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        var relevant = evidence.Trusts
            .Where(trust => trust.IsExternal || trust.IsForestTrust)
            .Where(trust => trust.Direction is AdTrustDirection.Inbound or AdTrustDirection.Bidirectional)
            .ToList();

        if (relevant.Count == 0)
        {
            return NotApplicable(context, "The forest has no inbound external or forest trust.");
        }

        var offenders = relevant
            .Where(trust => !trust.SelectiveAuthentication)
            .Select(trust => new AffectedObject
            {
                Identifier = $"{trust.SourceDomain}->{trust.TargetDomain}",
                DisplayName = trust.TargetDomain,
                ObjectType = "trust",
                Source = AssessmentSource.ActiveDirectory,
                Detail = "Forest-wide authentication is in effect",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {relevant.Count} inbound trust(s) use selective authentication.")
            : Fail(
                context,
                $"{offenders.Count} of {relevant.Count} inbound trust(s) allow forest-wide authentication.",
                offenders);
    }
}

/// <summary>Forest functional level is current.</summary>
public sealed class ForestFunctionalLevelRule : RuleBase
{
    public const string ThresholdName = "ad.forest.minimumFunctionalLevel";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-TOPO-001",
        version: 1,
        title: "Forest functional level is current",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdTrustsAndTopology,
        severity: RuleSeverity.Medium,
        rationale: "The forest functional level gates forest-wide features, including the " +
                   "directory recycle bin and privileged access management. An older level keeps " +
                   "those protections unavailable no matter how the domains are configured.",
        remediation: "Raise the forest functional level once every domain controller in every " +
                     "domain runs a supported version.",
        evidenceKeys: [EvidenceKeys.AdForest],
        mappings: [(RuleFactory.Iso27001, "A.8.8", "Management of technical vulnerabilities.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var minimum = context.Threshold(ThresholdName, 7);

        return evidence.Forest.ForestFunctionalLevel >= minimum
            ? Pass(context, $"The forest runs functional level {evidence.Forest.ForestFunctionalLevel}.")
            : Fail(
                context,
                $"The forest runs functional level {evidence.Forest.ForestFunctionalLevel}, " +
                $"below the required level {minimum}.");
    }
}

/// <summary>Every domain has enough domain controllers to survive a failure.</summary>
public sealed class DomainControllerRedundancyRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-TOPO-002",
        version: 1,
        title: "Each domain has redundant domain controllers",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdTrustsAndTopology,
        severity: RuleSeverity.Medium,
        rationale: "A domain served by a single controller has no authentication service during " +
                   "maintenance, and no replica to recover from if that controller is lost or " +
                   "encrypted during an incident.",
        remediation: "Deploy at least two writable domain controllers per domain, placed so that a " +
                     "single site or host failure cannot take authentication offline.",
        evidenceKeys: [EvidenceKeys.AdDomains, EvidenceKeys.AdSites],
        mappings: [(RuleFactory.Iso27001, "A.8.14", "Redundancy of information processing facilities.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        if (evidence.DomainControllers.Count == 0)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "No domain controllers were enumerated, so redundancy could not be assessed.");
        }

        var offenders = evidence.Domains
            .Select(domain => (Domain: domain, Count: evidence.DomainControllers.Count(controller =>
                string.Equals(controller.DomainDnsName, domain.DnsName, StringComparison.OrdinalIgnoreCase)
                && !controller.IsReadOnly)))
            .Where(entry => entry.Count < 2)
            .Select(entry => new AffectedObject
            {
                Identifier = entry.Domain.DomainSid,
                DisplayName = entry.Domain.DnsName,
                ObjectType = "domain",
                Source = AssessmentSource.ActiveDirectory,
                Detail = $"{entry.Count} writable domain controller(s)",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "Every domain has at least two writable domain controllers.")
            : Fail(context, $"{offenders.Count} domain(s) have fewer than two writable domain controllers.", offenders);
    }
}

/// <summary>Replication topology has no site without a controller or subnet.</summary>
public sealed class SiteTopologyRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-TOPO-003",
        version: 1,
        title: "Replication sites are correctly defined",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdTrustsAndTopology,
        severity: RuleSeverity.Low,
        rationale: "A site with no subnet attracts no clients, and a site with no domain " +
                   "controller sends its clients across the network for every authentication. " +
                   "Both make the location of authentication traffic unpredictable.",
        remediation: "Associate every site with the subnets it serves and remove sites that no " +
                     "longer host a domain controller or any client network.",
        evidenceKeys: [EvidenceKeys.AdSites],
        mappings: [(RuleFactory.Iso27001, "A.8.9", "Configuration management of directory services.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        if (evidence.Sites.Count == 0)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "No sites were enumerated from the configuration partition.");
        }

        var offenders = evidence.Sites
            .Where(site => site.Subnets.Count == 0 || site.DomainControllers.Count == 0)
            .Select(site => new AffectedObject
            {
                Identifier = site.Name,
                DisplayName = site.Name,
                ObjectType = "site",
                Source = AssessmentSource.ActiveDirectory,
                Detail = site.Subnets.Count == 0
                    ? "No subnet is associated with the site"
                    : "No domain controller is present in the site",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {evidence.Sites.Count} site(s) have both subnets and domain controllers.")
            : Fail(context, $"{offenders.Count} site(s) lack a subnet association or a domain controller.", offenders);
    }
}
