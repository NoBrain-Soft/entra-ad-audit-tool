using Ipa.Contracts;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Support;

namespace Ipa.Rules.Evaluators.ActiveDirectory;

/// <summary>Tier-zero group membership is small enough to be reviewed and controlled.</summary>
public sealed class TierZeroMembershipSizeRule : RuleBase
{
    /// <summary>Threshold name an operator may tune in the rule pack configuration.</summary>
    public const string ThresholdName = "ad.tierZero.maxMembers";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-PRIV-001",
        version: 1,
        title: "Tier-zero group membership is limited",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdPrivilegedAccess,
        severity: RuleSeverity.High,
        rationale: "Every account in Domain Admins, Enterprise Admins, Schema Admins or the " +
                   "built-in Administrators group can take full control of the forest. Large " +
                   "membership makes review impractical and widens the blast radius of a single " +
                   "compromised credential.",
        remediation: "Reduce standing membership of tier-zero groups to a small, named set of " +
                     "dedicated administrative accounts. Move day-to-day duties to delegated roles " +
                     "and use just-in-time elevation for the remainder.",
        evidenceKeys: [EvidenceKeys.AdGroups, EvidenceKeys.AdUsers, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Restricting privileged access rights to the minimum necessary."),
            (RuleFactory.Iso27001, "A.5.18", "Periodic review and restriction of assigned access rights."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var maximum = context.Threshold(ThresholdName, 5);

        var tierZeroUsers = resolver.TierZeroUsers
            .Where(user => !user.Flags.HasFlag(AdAccountFlags.Disabled))
            .ToList();

        if (tierZeroUsers.Count <= maximum)
        {
            return Pass(
                context,
                $"{tierZeroUsers.Count} enabled account(s) hold tier-zero privilege, within the " +
                $"threshold of {maximum}.");
        }

        return Fail(
            context,
            $"{tierZeroUsers.Count} enabled account(s) hold tier-zero privilege, above the " +
            $"threshold of {maximum}.",
            RuleHelpers.Cap(tierZeroUsers.Select(user =>
                RuleHelpers.ForPrincipal(user, $"Effective tier-zero via {user.DistinguishedName}"))));
    }
}

/// <summary>Tier-zero groups contain no nested groups, so membership stays reviewable.</summary>
public sealed class TierZeroNestingRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-PRIV-002",
        version: 1,
        title: "Tier-zero groups contain no nested groups",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdPrivilegedAccess,
        severity: RuleSeverity.High,
        rationale: "Nested groups hide the true membership of a privileged group. Privilege " +
                   "reached through three levels of nesting is exactly as effective as direct " +
                   "membership, but far less likely to be noticed during a review.",
        remediation: "Replace nested group membership in tier-zero groups with explicit, direct " +
                     "membership of named administrative accounts, and re-review the resulting list.",
        evidenceKeys: [EvidenceKeys.AdGroups, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Making privileged access rights visible and reviewable."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var offenders = new List<AffectedObject>();

        foreach (var seed in resolver.GetTierZeroGroups())
        {
            foreach (var nested in resolver.GetNestedGroups(seed.Sid))
            {
                offenders.Add(RuleHelpers.ForGroup(nested, $"Nested inside {seed.SamAccountName}"));
            }
        }

        return offenders.Count == 0
            ? Pass(context, "No groups are nested inside tier-zero groups.")
            : Fail(
                context,
                $"{offenders.Count} group(s) are nested inside tier-zero groups.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Privileged accounts carry no service principal name, so they cannot be Kerberoasted.</summary>
public sealed class PrivilegedAccountSpnRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-PRIV-003",
        version: 1,
        title: "Tier-zero accounts have no service principal name",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdPrivilegedAccess,
        severity: RuleSeverity.Critical,
        rationale: "Any authenticated user can request a service ticket for an account that has a " +
                   "service principal name and attempt to crack it offline. When such an account " +
                   "holds tier-zero privilege, a single weak password yields full forest control.",
        remediation: "Remove service principal names from privileged accounts. Run services under " +
                     "dedicated group-managed service accounts that hold only the privileges the " +
                     "service actually needs.",
        evidenceKeys: [EvidenceKeys.AdUsers, EvidenceKeys.AdGroups, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Preventing offline recovery of privileged credentials."),
            (RuleFactory.Iso27001, "A.5.17", "Protection of authentication information."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);

        var offenders = resolver.TierZeroUsers
            .Where(user => user.ServicePrincipalNames.Count > 0)
            .Where(user => !string.Equals(user.ObjectClass, "computer", StringComparison.OrdinalIgnoreCase))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No tier-zero account publishes a service principal name.")
            : Fail(
                context,
                $"{offenders.Count} tier-zero account(s) publish a service principal name and are " +
                "exposed to offline credential recovery.",
                RuleHelpers.Cap(offenders.Select(user => RuleHelpers.ForPrincipal(
                    user,
                    $"SPNs: {string.Join(", ", user.ServicePrincipalNames.Take(3))}"))));
    }
}

/// <summary>Privileged accounts belong to Protected Users and cannot be delegated.</summary>
public sealed class ProtectedUsersRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-PRIV-004",
        version: 1,
        title: "Tier-zero accounts are protected against credential theft",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdPrivilegedAccess,
        severity: RuleSeverity.Medium,
        rationale: "Membership of Protected Users, together with the account option that marks an " +
                   "account as sensitive and not delegatable, prevents privileged credentials from " +
                   "being cached and reused by a compromised member server.",
        remediation: "Add tier-zero accounts to the Protected Users group and set the account " +
                     "option that marks them sensitive and not delegatable. Confirm that the " +
                     "resulting authentication restrictions are compatible with administrative workflows.",
        evidenceKeys: [EvidenceKeys.AdUsers, EvidenceKeys.AdGroups, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Hardening privileged accounts against credential reuse."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);

        var protectedUserSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in evidence.Domains)
        {
            var sid = WellKnownSids.DomainRelative(domain.DomainSid, WellKnownSids.ProtectedUsersRid);
            foreach (var member in resolver.GetTransitiveUsers(sid))
            {
                protectedUserSids.Add(member.Sid);
            }
        }

        var candidates = resolver.TierZeroUsers
            .Where(user => !user.Flags.HasFlag(AdAccountFlags.Disabled))
            .Where(user => !string.Equals(user.ObjectClass, "computer", StringComparison.OrdinalIgnoreCase))
            .Where(user => WellKnownSids.GetRid(user.Sid) != WellKnownSids.KrbtgtRid)
            .ToList();

        if (candidates.Count == 0)
        {
            return NotApplicable(context, "No enabled tier-zero user accounts were found to assess.");
        }

        var offenders = candidates
            .Where(user => !protectedUserSids.Contains(user.Sid)
                           && !user.Flags.HasFlag(AdAccountFlags.NotDelegated))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {candidates.Count} enabled tier-zero account(s) are protected " +
                            "by Protected Users membership or the not-delegated account option.")
            : Fail(
                context,
                $"{offenders.Count} of {candidates.Count} enabled tier-zero account(s) are neither " +
                "in Protected Users nor marked as not delegated.",
                RuleHelpers.Cap(offenders.Select(user => RuleHelpers.ForPrincipal(user))));
    }
}

/// <summary>Privileged accounts are in active use, so dormant privilege is removed.</summary>
public sealed class StalePrivilegedAccountRule : RuleBase
{
    public const string ThresholdName = "ad.tierZero.maxIdleDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-PRIV-005",
        version: 1,
        title: "No dormant tier-zero accounts",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdPrivilegedAccess,
        severity: RuleSeverity.High,
        rationale: "A privileged account that nobody uses is a privileged account that nobody " +
                   "watches. Dormant administrative credentials are a common foothold because " +
                   "their misuse produces no anomaly for the legitimate owner to notice.",
        remediation: "Disable or remove tier-zero accounts that have not signed in within the " +
                     "review period, and record a justification for any that must remain.",
        evidenceKeys: [EvidenceKeys.AdUsers, EvidenceKeys.AdGroups, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.18", "Removal of access rights that are no longer required."),
            (RuleFactory.Iso27001, "A.8.2", "Review of privileged access rights."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var maxIdleDays = context.Threshold(ThresholdName, 90);

        var candidates = resolver.TierZeroUsers
            .Where(user => !user.Flags.HasFlag(AdAccountFlags.Disabled))
            .Where(user => WellKnownSids.GetRid(user.Sid) != WellKnownSids.KrbtgtRid)
            .ToList();

        if (candidates.Count == 0)
        {
            return NotApplicable(context, "No enabled tier-zero accounts were found to assess.");
        }

        var offenders = candidates
            .Where(user => RuleHelpers.IsStale(user.LastLogonTimestamp, context.ReferenceTime, maxIdleDays))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {candidates.Count} enabled tier-zero account(s) signed in within " +
                            $"the last {maxIdleDays} days.")
            : Fail(
                context,
                $"{offenders.Count} enabled tier-zero account(s) have not signed in within " +
                $"{maxIdleDays} days.",
                RuleHelpers.Cap(offenders.Select(user => RuleHelpers.ForPrincipal(
                    user,
                    user.LastLogonTimestamp is null
                        ? "No recorded sign-in"
                        : $"Last sign-in {user.LastLogonTimestamp:yyyy-MM-dd}"))));
    }
}

/// <summary>Privileged credentials are rotated within the review period.</summary>
public sealed class PrivilegedPasswordAgeRule : RuleBase
{
    public const string ThresholdName = "ad.tierZero.maxPasswordAgeDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-PRIV-006",
        version: 1,
        title: "Tier-zero credentials are rotated",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdPrivilegedAccess,
        severity: RuleSeverity.Medium,
        rationale: "A privileged password that has never been changed survives every staff change " +
                   "and every historical compromise since it was set.",
        remediation: "Rotate tier-zero credentials on a defined schedule, and rotate immediately " +
                     "when an administrator leaves or a compromise is suspected.",
        evidenceKeys: [EvidenceKeys.AdUsers, EvidenceKeys.AdGroups, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.17", "Management of authentication information."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var maxAgeDays = context.Threshold(ThresholdName, 365);

        var candidates = resolver.TierZeroUsers
            .Where(user => !user.Flags.HasFlag(AdAccountFlags.Disabled))
            .Where(user => !string.Equals(user.ObjectClass, "computer", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (candidates.Count == 0)
        {
            return NotApplicable(context, "No enabled tier-zero user accounts were found to assess.");
        }

        var offenders = candidates
            .Where(user => RuleHelpers.IsStale(user.PasswordLastSet, context.ReferenceTime, maxAgeDays))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {candidates.Count} enabled tier-zero account(s) had their " +
                            $"password set within {maxAgeDays} days.")
            : Fail(
                context,
                $"{offenders.Count} enabled tier-zero account(s) have a password older than " +
                $"{maxAgeDays} days.",
                RuleHelpers.Cap(offenders.Select(user => RuleHelpers.ForPrincipal(
                    user,
                    user.PasswordLastSet is null
                        ? "No recorded password change"
                        : $"Password set {user.PasswordLastSet:yyyy-MM-dd}"))));
    }
}

/// <summary>Accounts marked as protected still belong to a privileged group.</summary>
public sealed class OrphanedAdminCountRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-PRIV-007",
        version: 1,
        title: "No accounts retain protected-account status after losing privilege",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdPrivilegedAccess,
        severity: RuleSeverity.Low,
        rationale: "When an account leaves a privileged group its adminCount attribute stays set " +
                   "and its access-control list stops inheriting from its organisational unit. " +
                   "The result is an account whose permissions no longer match the delegation " +
                   "model anyone believes is in force.",
        remediation: "For accounts that are no longer privileged, clear adminCount and re-enable " +
                     "inheritance on the object so that the intended delegation applies again.",
        evidenceKeys: [EvidenceKeys.AdUsers, EvidenceKeys.AdGroups, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.18", "Access rights reflect current responsibilities."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var tierZeroSids = resolver.TierZeroUsers
            .Select(user => user.Sid)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var offenders = evidence.Users
            .Where(user => user.AdminCount)
            .Where(user => !tierZeroSids.Contains(user.Sid))
            .Where(user => WellKnownSids.GetRid(user.Sid) != WellKnownSids.KrbtgtRid)
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "Every account marked as a protected account still holds tier-zero privilege.")
            : Fail(
                context,
                $"{offenders.Count} account(s) are still marked as protected accounts but no longer " +
                "hold tier-zero privilege.",
                RuleHelpers.Cap(offenders.Select(user => RuleHelpers.ForPrincipal(user, "adminCount is set"))));
    }
}
