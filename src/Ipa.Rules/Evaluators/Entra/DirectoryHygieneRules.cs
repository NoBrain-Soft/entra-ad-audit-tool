using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;

namespace Ipa.Rules.Evaluators.Entra;

/// <summary>Enabled member accounts are in active use.</summary>
public sealed class StaleMemberAccountRule : RuleBase
{
    public const string ThresholdName = "entra.users.maxIdleDays";
    public const string TolerancePercentName = "entra.users.stalePercentTolerance";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-DIR-001",
        version: 1,
        title: "Enabled member accounts are in active use",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraDirectoryHygiene,
        severity: RuleSeverity.Medium,
        rationale: "Dormant cloud accounts remain fully usable from anywhere on the internet. " +
                   "Unlike an unused workstation, nothing about them is physically out of reach.",
        remediation: "Disable enabled accounts with no sign-in inside the review period, and " +
                     "remove their licences before deleting them at the end of retention.",
        evidenceKeys: [EvidenceKeys.EntraUsers, EvidenceKeys.EntraSignInActivity],
        mappings: [(RuleFactory.Iso27001, "A.5.18", "Timely removal of access rights.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var maxIdleDays = context.Threshold(ThresholdName, 90);
        var tolerancePercent = context.Threshold(TolerancePercentName, 5);

        var members = evidence.Users
            .Where(user => user.AccountEnabled)
            .Where(user => string.Equals(user.UserType, "Member", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (members.Count == 0)
        {
            return NotApplicable(context, "The tenant contains no enabled member accounts.");
        }

        var stale = members
            .Where(user => RuleHelpers.IsStale(
                user.LastSignInDateTime ?? user.LastNonInteractiveSignInDateTime,
                context.ReferenceTime,
                maxIdleDays))
            .ToList();

        var stalePercent = stale.Count * 100d / members.Count;

        return stalePercent <= tolerancePercent
            ? Pass(context, $"{stale.Count} of {members.Count} enabled member accounts " +
                            $"({stalePercent:F1}%) are dormant, within the {tolerancePercent}% tolerance.")
            : Fail(
                context,
                $"{stale.Count} of {members.Count} enabled member accounts ({stalePercent:F1}%) " +
                $"have not signed in within {maxIdleDays} days.",
                RuleHelpers.Cap(stale.Select(user => RuleHelpers.ForEntraUser(
                    user,
                    user.LastSignInDateTime is null
                        ? "No recorded sign-in"
                        : $"Last sign-in {user.LastSignInDateTime:yyyy-MM-dd}"))));
    }
}

/// <summary>Guest accounts are reviewed and removed when no longer used.</summary>
public sealed class StaleGuestAccountRule : RuleBase
{
    public const string ThresholdName = "entra.guests.maxIdleDays";
    public const string PendingThresholdName = "entra.guests.maxPendingDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-DIR-002",
        version: 1,
        title: "Guest accounts are reviewed and removed",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraDirectoryHygiene,
        severity: RuleSeverity.Medium,
        rationale: "Guest accounts outlive the projects that created them. Each one retains " +
                   "whatever sharing and group membership it accumulated, governed by an identity " +
                   "lifecycle in another organisation entirely.",
        remediation: "Run access reviews over guests, remove those that are unused or whose " +
                     "invitation was never accepted, and set an expiry for external collaboration.",
        evidenceKeys: [EvidenceKeys.EntraUsers, EvidenceKeys.EntraSignInActivity],
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.18", "Review of access rights."),
            (RuleFactory.Iso27001, "A.5.19", "Management of supplier and partner access."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var maxIdleDays = context.Threshold(ThresholdName, 90);
        var maxPendingDays = context.Threshold(PendingThresholdName, 30);

        var guests = evidence.Users
            .Where(user => string.Equals(user.UserType, "Guest", StringComparison.OrdinalIgnoreCase))
            .Where(user => user.AccountEnabled)
            .ToList();

        if (guests.Count == 0)
        {
            return NotApplicable(context, "The tenant contains no enabled guest accounts.");
        }

        var offenders = new List<AffectedObject>();

        foreach (var guest in guests)
        {
            var pending = string.Equals(guest.ExternalUserState, "PendingAcceptance", StringComparison.OrdinalIgnoreCase);
            var threshold = pending ? maxPendingDays : maxIdleDays;
            var reference = pending ? guest.CreatedDateTime : guest.LastSignInDateTime ?? guest.LastNonInteractiveSignInDateTime;

            if (RuleHelpers.IsStale(reference, context.ReferenceTime, threshold))
            {
                offenders.Add(RuleHelpers.ForEntraUser(
                    guest,
                    pending
                        ? $"Invitation pending since {guest.CreatedDateTime:yyyy-MM-dd}"
                        : guest.LastSignInDateTime is null
                            ? "No recorded sign-in"
                            : $"Last sign-in {guest.LastSignInDateTime:yyyy-MM-dd}"));
            }
        }

        return offenders.Count == 0
            ? Pass(context, $"All {guests.Count} enabled guest account(s) are within the review thresholds.")
            : Fail(
                context,
                $"{offenders.Count} of {guests.Count} enabled guest account(s) are dormant or have " +
                "an unaccepted invitation beyond the threshold.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Registered devices are in active use.</summary>
public sealed class StaleDeviceRule : RuleBase
{
    public const string ThresholdName = "entra.devices.maxIdleDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-DIR-003",
        version: 1,
        title: "Registered devices are in active use",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraDirectoryHygiene,
        severity: RuleSeverity.Low,
        rationale: "Stale device objects distort compliance reporting and can satisfy a " +
                   "device-based Conditional Access requirement long after the physical machine " +
                   "was retired or sold.",
        remediation: "Disable and then delete device objects that have not signed in within the " +
                     "review period, using a scheduled cleanup rather than a one-off exercise.",
        evidenceKeys: [EvidenceKeys.EntraDevices],
        mappings: [(RuleFactory.Iso27001, "A.5.9", "Accuracy of the asset inventory.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var maxIdleDays = context.Threshold(ThresholdName, 180);

        var enabled = evidence.Devices.Where(device => device.AccountEnabled).ToList();

        if (enabled.Count == 0)
        {
            return NotApplicable(context, "The tenant has no enabled device objects.");
        }

        var stale = enabled
            .Where(device => RuleHelpers.IsStale(
                device.ApproximateLastSignInDateTime,
                context.ReferenceTime,
                maxIdleDays))
            .ToList();

        return stale.Count == 0
            ? Pass(context, $"All {enabled.Count} enabled device object(s) signed in within {maxIdleDays} days.")
            : Fail(
                context,
                $"{stale.Count} of {enabled.Count} enabled device object(s) have not signed in " +
                $"within {maxIdleDays} days.",
                RuleHelpers.Cap(stale.Select(device => RuleHelpers.ForEntraObject(
                    device.ObjectId,
                    device.DisplayName,
                    "device",
                    device.ApproximateLastSignInDateTime is null
                        ? "No recorded sign-in"
                        : $"Last sign-in {device.ApproximateLastSignInDateTime:yyyy-MM-dd}"))));
    }
}

/// <summary>Disabled accounts are removed once retention has elapsed.</summary>
public sealed class RetainedDisabledAccountRule : RuleBase
{
    public const string ThresholdName = "entra.disabled.maxRetentionDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-DIR-004",
        version: 1,
        title: "Disabled accounts are removed after retention",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraDirectoryHygiene,
        severity: RuleSeverity.Low,
        rationale: "A disabled account can be re-enabled by anyone holding a user administration " +
                   "role, restoring all of its group membership and application access in a single " +
                   "action that looks like routine administration.",
        remediation: "Delete disabled accounts once the retention period has elapsed, after " +
                     "exporting any data the organisation must keep.",
        evidenceKeys: [EvidenceKeys.EntraUsers],
        mappings: [(RuleFactory.Iso27001, "A.5.11", "Return and removal of assets on termination.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var retentionDays = context.Threshold(ThresholdName, 90);

        var disabled = evidence.Users.Where(user => !user.AccountEnabled).ToList();

        if (disabled.Count == 0)
        {
            return Pass(context, "The tenant retains no disabled accounts.");
        }

        var overdue = disabled
            .Where(user => RuleHelpers.IsStale(
                user.LastSignInDateTime ?? user.CreatedDateTime,
                context.ReferenceTime,
                retentionDays))
            .ToList();

        return overdue.Count == 0
            ? Pass(context, $"All {disabled.Count} disabled account(s) are inside the " +
                            $"{retentionDays}-day retention window.")
            : Fail(
                context,
                $"{overdue.Count} of {disabled.Count} disabled account(s) have been retained beyond " +
                $"{retentionDays} days.",
                RuleHelpers.Cap(overdue.Select(user => RuleHelpers.ForEntraUser(user, "Disabled and retained"))));
    }
}

/// <summary>
/// Reports the Microsoft Secure Score as the provider's own metric. The rule is informational and
/// carries no weight, so the provider's score can never move this product's posture score.
/// </summary>
public sealed class SecureScoreAvailabilityRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-SS-001",
        version: 1,
        title: "Microsoft Secure Score is reported separately",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraSecureScore,
        severity: RuleSeverity.Informational,
        rationale: "Microsoft Secure Score measures a different control set with a different " +
                   "weighting. It is shown alongside this assessment as the provider's own metric " +
                   "and is deliberately never blended into the posture score.",
        remediation: "Review Microsoft Secure Score improvement actions in the Microsoft 365 " +
                     "Defender portal alongside the findings in this report.",
        evidenceKeys: [EvidenceKeys.EntraSecureScore],
        permissions: ["SecurityEvents.Read.All"],
        mappings: [(RuleFactory.Iso27001, "A.5.36", "Use of independent measurement of controls.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var snapshot = context.Evidence.Entra!.SecureScore;

        if (snapshot is null)
        {
            return NotCollected(
                context,
                EvidenceAvailability.PermissionDenied,
                "Microsoft Secure Score was not retrieved. It requires a sensitive Microsoft Graph " +
                "permission and an appropriate directory role.");
        }

        return Pass(
            context,
            $"Microsoft Secure Score of {snapshot.CurrentScore:F0} out of {snapshot.MaxScore:F0} " +
            $"({snapshot.Percentage:F1}%) as of {snapshot.CreatedDateTime:yyyy-MM-dd}. This is the " +
            "provider's own metric and is reported separately from the posture score.");
    }
}
