using Ipa.Contracts;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Support;

namespace Ipa.Rules.Evaluators.ActiveDirectory;

/// <summary>Unconstrained delegation is confined to domain controllers.</summary>
public sealed class UnconstrainedDelegationRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-DELEG-001",
        version: 1,
        title: "Unconstrained delegation is limited to domain controllers",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDelegationAndAcl,
        severity: RuleSeverity.Critical,
        rationale: "A host trusted for unconstrained delegation caches the forwardable ticket of " +
                   "every user who authenticates to it, including administrators. Compromising " +
                   "one such host is equivalent to compromising every account that has used it.",
        remediation: "Remove unconstrained delegation from every account that is not a domain " +
                     "controller. Where delegation is genuinely required, use resource-based " +
                     "constrained delegation scoped to the specific target service.",
        evidenceKeys: [EvidenceKeys.AdComputers, EvidenceKeys.AdUsers],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Preventing uncontrolled acquisition of privileged access."),
            (RuleFactory.Iso27001, "A.8.9", "Secure configuration of directory services."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var offenders = new List<AffectedObject>();

        offenders.AddRange(evidence.Computers
            .Where(computer => computer.Delegation == AdDelegationKind.Unconstrained)
            .Where(computer => !computer.IsDomainController)
            .Select(computer => RuleHelpers.ForComputer(computer, "Trusted for unconstrained delegation")));

        offenders.AddRange(evidence.Users
            .Where(user => user.Delegation == AdDelegationKind.Unconstrained)
            .Select(user => RuleHelpers.ForPrincipal(user, "Trusted for unconstrained delegation")));

        return offenders.Count == 0
            ? Pass(context, "Unconstrained delegation is configured only on domain controllers.")
            : Fail(
                context,
                $"{offenders.Count} account(s) other than domain controllers are trusted for " +
                "unconstrained delegation.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Constrained delegation does not use protocol transition.</summary>
public sealed class ProtocolTransitionRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-DELEG-002",
        version: 1,
        title: "Constrained delegation does not permit protocol transition",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDelegationAndAcl,
        severity: RuleSeverity.High,
        rationale: "Constrained delegation with protocol transition lets a service obtain a ticket " +
                   "for any user to the configured target without that user ever authenticating. " +
                   "Compromising the service is enough to impersonate an administrator.",
        remediation: "Reconfigure the service to use Kerberos-only constrained delegation, or " +
                     "resource-based constrained delegation controlled by the target resource.",
        evidenceKeys: [EvidenceKeys.AdComputers, EvidenceKeys.AdUsers],
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Restriction of impersonation capability.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var offenders = new List<AffectedObject>();

        offenders.AddRange(evidence.Computers
            .Where(computer => computer.Delegation == AdDelegationKind.ConstrainedWithProtocolTransition)
            .Select(computer => RuleHelpers.ForComputer(
                computer,
                $"Targets: {string.Join(", ", computer.AllowedToDelegateTo.Take(3))}")));

        offenders.AddRange(evidence.Users
            .Where(user => user.Delegation == AdDelegationKind.ConstrainedWithProtocolTransition)
            .Select(user => RuleHelpers.ForPrincipal(
                user,
                $"Targets: {string.Join(", ", user.AllowedToDelegateTo.Take(3))}")));

        return offenders.Count == 0
            ? Pass(context, "No account uses constrained delegation with protocol transition.")
            : Fail(
                context,
                $"{offenders.Count} account(s) use constrained delegation with protocol transition.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Directory replication rights are held only by tier-zero principals.</summary>
public sealed class ReplicationRightsRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-DELEG-003",
        version: 1,
        title: "Directory replication rights are restricted to tier zero",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDelegationAndAcl,
        severity: RuleSeverity.Critical,
        rationale: "The replication extended rights allow a principal to pull password hashes for " +
                   "every account in the domain, including the key distribution account. Any " +
                   "principal holding them is effectively a domain administrator.",
        remediation: "Remove the directory replication extended rights from every principal that " +
                     "is not a domain controller or an approved tier-zero group, and review the " +
                     "credentials of any principal that held them.",
        evidenceKeys: [EvidenceKeys.AdAcls, EvidenceKeys.AdGroups, EvidenceKeys.AdUsers, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Control of privileged directory operations."),
            (RuleFactory.Iso27001, "A.5.17", "Protection of stored authentication information."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var domainSids = evidence.Domains.Select(domain => domain.DomainSid).ToList();

        var offenders = evidence.AccessControlEntries
            .Where(ace => !ace.IsDeny)
            .Where(ace => ExtendedRights.IsReplicationRight(ace.ObjectTypeGuid)
                          || ace.Rights.HasFlag(AdAceRight.AllExtendedRights)
                          || ace.Rights.HasFlag(AdAceRight.GenericAll))
            .Where(ace => IsDomainRoot(ace, evidence))
            .Where(ace => !WellKnownSids.IsExpectedPrivilegedTrustee(ace.TrusteeSid, domainSids))
            .Where(ace => !resolver.TierZeroGroupSids.Contains(ace.TrusteeSid))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "Directory replication rights on the domain naming contexts are held " +
                            "only by expected tier-zero principals.")
            : Fail(
                context,
                $"{offenders.Count} access-control entr(ies) grant replication-capable rights on a " +
                "domain naming context to a principal outside tier zero.",
                RuleHelpers.Cap(offenders.Select(ace => new AffectedObject
                {
                    Identifier = ace.TrusteeSid,
                    DisplayName = ace.TrusteeName ?? ace.TrusteeSid,
                    ObjectType = "trustee",
                    Source = AssessmentSource.ActiveDirectory,
                    Detail = $"{ace.ExtendedRightName ?? ace.Rights.ToString()} on {ace.ObjectDistinguishedName}",
                })));
    }

    private static bool IsDomainRoot(AdAccessControlEntry ace, ActiveDirectoryEvidence evidence) =>
        evidence.Domains.Any(domain => string.Equals(
            domain.DistinguishedName,
            ace.ObjectDistinguishedName,
            StringComparison.OrdinalIgnoreCase));
}

/// <summary>Privileged objects are not writable by non-privileged principals.</summary>
public sealed class DangerousAclRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-DELEG-004",
        version: 1,
        title: "Tier-zero objects are not writable by non-privileged principals",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDelegationAndAcl,
        severity: RuleSeverity.Critical,
        rationale: "Write access to a tier-zero object is equivalent to membership of it: a " +
                   "principal that can modify a privileged group, reset an administrator's " +
                   "password or rewrite an object's security descriptor can grant itself full control.",
        remediation: "Remove full-control, write-property, write-owner and write-DACL grants over " +
                     "tier-zero objects from principals outside tier zero, and re-check inheritance " +
                     "on the containers holding those objects.",
        evidenceKeys: [EvidenceKeys.AdAcls, EvidenceKeys.AdGroups, EvidenceKeys.AdUsers, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.3", "Restriction of access to privileged information assets."),
            (RuleFactory.Iso27001, "A.8.2", "Control of paths that lead to privileged access."),
        ]);

    private const AdAceRight DangerousRights =
        AdAceRight.GenericAll | AdAceRight.GenericWrite | AdAceRight.WriteDacl |
        AdAceRight.WriteOwner | AdAceRight.WriteProperty | AdAceRight.AllExtendedRights;

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var domainSids = evidence.Domains.Select(domain => domain.DomainSid).ToList();

        var tierZeroDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in resolver.GetTierZeroGroups())
        {
            tierZeroDns.Add(group.DistinguishedName);
        }

        foreach (var user in resolver.TierZeroUsers)
        {
            tierZeroDns.Add(user.DistinguishedName);
        }

        var tierZeroPrincipalSids = new HashSet<string>(resolver.TierZeroGroupSids, StringComparer.OrdinalIgnoreCase);
        foreach (var user in resolver.TierZeroUsers)
        {
            tierZeroPrincipalSids.Add(user.Sid);
        }

        var offenders = evidence.AccessControlEntries
            .Where(ace => !ace.IsDeny)
            .Where(ace => (ace.Rights & DangerousRights) != AdAceRight.None)
            .Where(ace => tierZeroDns.Contains(ace.ObjectDistinguishedName))
            .Where(ace => !tierZeroPrincipalSids.Contains(ace.TrusteeSid))
            .Where(ace => !WellKnownSids.IsExpectedPrivilegedTrustee(ace.TrusteeSid, domainSids))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No principal outside tier zero holds write access over a tier-zero object.")
            : Fail(
                context,
                $"{offenders.Count} access-control entr(ies) grant write access over tier-zero " +
                "objects to principals outside tier zero.",
                RuleHelpers.Cap(offenders.Select(ace => new AffectedObject
                {
                    Identifier = ace.TrusteeSid,
                    DisplayName = ace.TrusteeName ?? ace.TrusteeSid,
                    ObjectType = "trustee",
                    Source = AssessmentSource.ActiveDirectory,
                    Detail = $"{ace.Rights} on {ace.ObjectDistinguishedName}" +
                             (ace.IsInherited ? " (inherited)" : string.Empty),
                })));
    }
}

/// <summary>The AdminSDHolder template is not delegated to unexpected principals.</summary>
public sealed class AdminSdHolderRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-DELEG-005",
        version: 1,
        title: "The protected-account template has no unexpected delegation",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDelegationAndAcl,
        severity: RuleSeverity.High,
        rationale: "The AdminSDHolder object's security descriptor is stamped onto every protected " +
                   "account. A permission added there propagates to every administrator in the " +
                   "domain within the hour, and survives manual correction of individual accounts.",
        remediation: "Remove non-default access-control entries from the AdminSDHolder object and " +
                     "verify that protected accounts have been re-stamped with the corrected descriptor.",
        evidenceKeys: [EvidenceKeys.AdAcls, EvidenceKeys.AdDomains, EvidenceKeys.AdGroups, EvidenceKeys.AdUsers],
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Integrity of the privileged access model.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var domainSids = evidence.Domains.Select(domain => domain.DomainSid).ToList();

        var adminSdHolderAces = evidence.AccessControlEntries
            .Where(ace => ace.ObjectDistinguishedName.StartsWith(
                "CN=AdminSDHolder,CN=System,",
                StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (adminSdHolderAces.Count == 0)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "The AdminSDHolder security descriptor was not among the collected access-control " +
                "entries, so the delegation on the protected-account template could not be assessed.");
        }

        var offenders = adminSdHolderAces
            .Where(ace => !ace.IsDeny)
            .Where(ace => ace.Rights != AdAceRight.None)
            .Where(ace => !WellKnownSids.IsExpectedPrivilegedTrustee(ace.TrusteeSid, domainSids))
            .Where(ace => !resolver.TierZeroGroupSids.Contains(ace.TrusteeSid))
            .Where(ace => ace.TrusteeSid != WellKnownSids.AuthenticatedUsers || ace.Rights != AdAceRight.None)
            .Where(ace => !IsDefaultReadTrustee(ace))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "The protected-account template carries only expected access-control entries.")
            : Fail(
                context,
                $"{offenders.Count} unexpected access-control entr(ies) are present on the " +
                "protected-account template and will be stamped onto every privileged account.",
                RuleHelpers.Cap(offenders.Select(ace => new AffectedObject
                {
                    Identifier = ace.TrusteeSid,
                    DisplayName = ace.TrusteeName ?? ace.TrusteeSid,
                    ObjectType = "trustee",
                    Source = AssessmentSource.ActiveDirectory,
                    Detail = $"{ace.Rights} on AdminSDHolder",
                })));
    }

    /// <summary>Read-only grants held by the pre-Windows 2000 compatibility group are default.</summary>
    private static bool IsDefaultReadTrustee(AdAccessControlEntry ace) =>
        string.Equals(ace.TrusteeSid, WellKnownSids.PreWindows2000CompatibleAccess, StringComparison.OrdinalIgnoreCase)
        && (ace.Rights & (AdAceRight.GenericAll | AdAceRight.GenericWrite | AdAceRight.WriteDacl
                          | AdAceRight.WriteOwner | AdAceRight.WriteProperty)) == AdAceRight.None;
}
