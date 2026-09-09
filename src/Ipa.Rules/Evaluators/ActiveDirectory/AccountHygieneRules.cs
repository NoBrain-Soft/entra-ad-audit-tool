using Ipa.Contracts;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;

namespace Ipa.Rules.Evaluators.ActiveDirectory;

/// <summary>Enabled user accounts are in active use.</summary>
public sealed class StaleUserAccountRule : RuleBase
{
    public const string ThresholdName = "ad.users.maxIdleDays";
    public const string TolerancePercentName = "ad.users.stalePercentTolerance";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-ACCT-001",
        version: 1,
        title: "Enabled user accounts are in active use",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdAccountHygiene,
        severity: RuleSeverity.Medium,
        rationale: "Enabled accounts that nobody uses expand the attack surface without providing " +
                   "value. They are attractive targets precisely because their misuse is unlikely " +
                   "to be reported by a user.",
        remediation: "Disable enabled accounts with no sign-in inside the review period, then " +
                     "delete them once the retention period has passed.",
        evidenceKeys: [EvidenceKeys.AdUsers],
        mappings: [(RuleFactory.Iso27001, "A.5.18", "Timely removal of access rights.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var maxIdleDays = context.Threshold(ThresholdName, 180);
        var tolerancePercent = context.Threshold(TolerancePercentName, 5);

        var enabled = evidence.Users
            .Where(user => !user.Flags.HasFlag(AdAccountFlags.Disabled))
            .Where(user => WellKnownSids.GetRid(user.Sid) is not (WellKnownSids.KrbtgtRid or WellKnownSids.GuestRid))
            .ToList();

        if (enabled.Count == 0)
        {
            return NotApplicable(context, "The forest contains no enabled user accounts to assess.");
        }

        var stale = enabled
            .Where(user => RuleHelpers.IsStale(user.LastLogonTimestamp, context.ReferenceTime, maxIdleDays))
            .ToList();

        var stalePercent = stale.Count * 100d / enabled.Count;

        return stalePercent <= tolerancePercent
            ? Pass(context, $"{stale.Count} of {enabled.Count} enabled accounts ({stalePercent:F1}%) " +
                            $"are dormant, within the tolerance of {tolerancePercent}%.")
            : Fail(
                context,
                $"{stale.Count} of {enabled.Count} enabled accounts ({stalePercent:F1}%) have not " +
                $"signed in within {maxIdleDays} days, above the tolerance of {tolerancePercent}%.",
                RuleHelpers.Cap(stale.Select(user => RuleHelpers.ForPrincipal(
                    user,
                    user.LastLogonTimestamp is null
                        ? "No recorded sign-in"
                        : $"Last sign-in {user.LastLogonTimestamp:yyyy-MM-dd}"))));
    }
}

/// <summary>Accounts do not carry the option that exempts them from password expiry.</summary>
public sealed class PasswordNeverExpiresRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-ACCT-002",
        version: 1,
        title: "Enabled accounts are subject to password expiry",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdAccountHygiene,
        severity: RuleSeverity.Medium,
        rationale: "An account whose password never expires keeps the same credential " +
                   "indefinitely, so a password exposed years ago still works today.",
        remediation: "Remove the password-never-expires option from interactive accounts. Where a " +
                     "service genuinely needs a non-expiring credential, move it to a group-managed " +
                     "service account whose password the directory rotates automatically.",
        evidenceKeys: [EvidenceKeys.AdUsers],
        mappings: [(RuleFactory.Iso27001, "A.5.17", "Management of authentication information.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        var offenders = evidence.Users
            .Where(user => !user.Flags.HasFlag(AdAccountFlags.Disabled))
            .Where(user => user.Flags.HasFlag(AdAccountFlags.PasswordNeverExpires))
            .Where(user => WellKnownSids.GetRid(user.Sid) != WellKnownSids.KrbtgtRid)
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No enabled account is exempt from password expiry.")
            : Fail(
                context,
                $"{offenders.Count} enabled account(s) have a password that never expires.",
                RuleHelpers.Cap(offenders.Select(user => RuleHelpers.ForPrincipal(user))));
    }
}

/// <summary>No account is exempt from the requirement to have a password.</summary>
public sealed class PasswordNotRequiredRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-ACCT-003",
        version: 1,
        title: "No enabled account may have an empty password",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdAccountHygiene,
        severity: RuleSeverity.High,
        rationale: "The password-not-required option lets an account be set to a blank password " +
                   "regardless of the domain password policy, bypassing every length and " +
                   "complexity requirement in force.",
        remediation: "Clear the password-not-required option on every enabled account and reset " +
                     "the affected credentials.",
        evidenceKeys: [EvidenceKeys.AdUsers],
        mappings: [(RuleFactory.Iso27001, "A.5.17", "Enforcement of authentication requirements.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        var offenders = evidence.Users
            .Where(user => !user.Flags.HasFlag(AdAccountFlags.Disabled))
            .Where(user => user.Flags.HasFlag(AdAccountFlags.PasswordNotRequired))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No enabled account is exempt from the password requirement.")
            : Fail(
                context,
                $"{offenders.Count} enabled account(s) may be set to an empty password.",
                RuleHelpers.Cap(offenders.Select(user => RuleHelpers.ForPrincipal(user))));
    }
}

/// <summary>Kerberos pre-authentication is required for every account.</summary>
public sealed class KerberosPreAuthenticationRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-ACCT-004",
        version: 1,
        title: "Kerberos pre-authentication is required",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdAccountHygiene,
        severity: RuleSeverity.High,
        rationale: "With pre-authentication disabled, anyone can ask a domain controller for " +
                   "encrypted material for the account and attack the password offline, without " +
                   "any credential and without generating a failed logon.",
        remediation: "Clear the do-not-require-pre-authentication option on every account, and " +
                     "reset the password of any account that had it set.",
        evidenceKeys: [EvidenceKeys.AdUsers],
        mappings: [(RuleFactory.Iso27001, "A.5.17", "Protection of authentication information.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        var offenders = evidence.Users
            .Where(user => !user.Flags.HasFlag(AdAccountFlags.Disabled))
            .Where(user => user.Flags.HasFlag(AdAccountFlags.DoesNotRequirePreAuth))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "Every enabled account requires Kerberos pre-authentication.")
            : Fail(
                context,
                $"{offenders.Count} enabled account(s) do not require Kerberos pre-authentication.",
                RuleHelpers.Cap(offenders.Select(user => RuleHelpers.ForPrincipal(user))));
    }
}

/// <summary>No account carries SID history from a completed migration.</summary>
public sealed class SidHistoryRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-ACCT-005",
        version: 1,
        title: "No residual SID history on accounts",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdAccountHygiene,
        severity: RuleSeverity.Medium,
        rationale: "SID history grants an account the access rights of a principal from another " +
                   "domain. Left in place after a migration it becomes an invisible privilege " +
                   "path that no group membership review will reveal.",
        remediation: "Re-permission resources against the current principals, then clear SID " +
                     "history from migrated accounts.",
        evidenceKeys: [EvidenceKeys.AdUsers],
        mappings: [(RuleFactory.Iso27001, "A.5.18", "Access rights match the current identity model.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        var offenders = evidence.Users
            .Where(user => user.SidHistory.Count > 0)
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No account carries SID history.")
            : Fail(
                context,
                $"{offenders.Count} account(s) carry SID history from a previous domain.",
                RuleHelpers.Cap(offenders.Select(user => RuleHelpers.ForPrincipal(
                    user,
                    $"{user.SidHistory.Count} historical SID(s)"))));
    }
}

/// <summary>Computer accounts are in active use.</summary>
public sealed class StaleComputerAccountRule : RuleBase
{
    public const string ThresholdName = "ad.computers.maxIdleDays";
    public const string TolerancePercentName = "ad.computers.stalePercentTolerance";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-ACCT-006",
        version: 1,
        title: "Computer accounts are in active use",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdAccountHygiene,
        severity: RuleSeverity.Low,
        rationale: "Stale computer accounts keep valid credentials in the directory for machines " +
                   "that no longer exist, and inflate the population that any delegation or group " +
                   "policy applies to.",
        remediation: "Disable and then remove computer accounts that have not authenticated within " +
                     "the review period.",
        evidenceKeys: [EvidenceKeys.AdComputers],
        mappings: [(RuleFactory.Iso27001, "A.8.9", "Configuration and asset records stay current.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var maxIdleDays = context.Threshold(ThresholdName, 180);
        var tolerancePercent = context.Threshold(TolerancePercentName, 5);

        var enabled = evidence.Computers
            .Where(computer => !computer.Flags.HasFlag(AdAccountFlags.Disabled))
            .ToList();

        if (enabled.Count == 0)
        {
            return NotApplicable(context, "The forest contains no enabled computer accounts to assess.");
        }

        var stale = enabled
            .Where(computer => RuleHelpers.IsStale(computer.LastLogonTimestamp, context.ReferenceTime, maxIdleDays))
            .ToList();

        var stalePercent = stale.Count * 100d / enabled.Count;

        return stalePercent <= tolerancePercent
            ? Pass(context, $"{stale.Count} of {enabled.Count} enabled computer accounts " +
                            $"({stalePercent:F1}%) are dormant, within the tolerance of {tolerancePercent}%.")
            : Fail(
                context,
                $"{stale.Count} of {enabled.Count} enabled computer accounts ({stalePercent:F1}%) " +
                $"have not authenticated within {maxIdleDays} days.",
                RuleHelpers.Cap(stale.Select(computer => RuleHelpers.ForComputer(
                    computer,
                    computer.LastLogonTimestamp is null
                        ? "No recorded authentication"
                        : $"Last authentication {computer.LastLogonTimestamp:yyyy-MM-dd}"))));
    }
}

/// <summary>Domain-joined systems run a supported operating system.</summary>
public sealed class UnsupportedOperatingSystemRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-ACCT-007",
        version: 1,
        title: "No domain-joined systems run an unsupported operating system",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdAccountHygiene,
        severity: RuleSeverity.High,
        rationale: "An operating system past its support date receives no security updates. A " +
                   "single such machine inside the domain provides a durable foothold that cannot " +
                   "be patched.",
        remediation: "Replace or isolate systems running unsupported operating systems, and " +
                     "remove their computer accounts once decommissioned.",
        evidenceKeys: [EvidenceKeys.AdComputers],
        mappings: [(RuleFactory.Iso27001, "A.8.8", "Management of technical vulnerabilities.")]);

    /// <summary>Operating system name fragments that are out of support for the v1 rule pack.</summary>
    private static readonly string[] UnsupportedFragments =
    [
        "Windows 2000", "Windows XP", "Windows Vista", "Windows 7", "Windows 8",
        "Server 2003", "Server 2008", "Server 2012",
    ];

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        var offenders = evidence.Computers
            .Where(computer => !computer.Flags.HasFlag(AdAccountFlags.Disabled))
            .Where(computer => computer.OperatingSystem is not null
                               && UnsupportedFragments.Any(fragment =>
                                   computer.OperatingSystem.Contains(fragment, StringComparison.OrdinalIgnoreCase)))
            // "Windows 8.1" and "Server 2012 R2" are matched by the fragments above by design:
            // both reached end of support before this rule pack was published.
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No enabled computer account reports an unsupported operating system.")
            : Fail(
                context,
                $"{offenders.Count} enabled computer account(s) report an unsupported operating system.",
                RuleHelpers.Cap(offenders.Select(computer => RuleHelpers.ForComputer(
                    computer,
                    computer.OperatingSystem))));
    }
}
