using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Support;

namespace Ipa.Rules.Evaluators.Entra;

/// <summary>Multi-factor authentication is required for all users by policy.</summary>
public sealed class MfaForAllUsersRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-CA-001",
        version: 1,
        title: "Multi-factor authentication is required for all users",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraConditionalAccess,
        severity: RuleSeverity.Critical,
        rationale: "Password-only access to cloud applications is defeated by credential stuffing, " +
                   "phishing and password spraying, all of which are automated and continuous. A " +
                   "tenant-wide multi-factor requirement is the single highest-value control available.",
        remediation: "Create an enabled Conditional Access policy that targets all users and all " +
                     "cloud applications and requires multi-factor authentication or a stronger " +
                     "authentication strength, excluding only documented emergency access accounts.",
        evidenceKeys: [EvidenceKeys.EntraConditionalAccess],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.5", "Secure authentication."),
            (RuleFactory.Iso27001, "A.5.15", "Access control policy implementation."),
        ]);

    /// <summary>Grant controls that satisfy a multi-factor requirement.</summary>
    internal static bool RequiresMultiFactor(ConditionalAccessPolicy policy)
    {
        var controls = policy.GrantControls;
        if (controls is null)
        {
            return false;
        }

        return controls.AuthenticationStrengthPolicyIds.Count > 0
               || controls.BuiltInControls.Any(control =>
                   control.Equals("mfa", StringComparison.OrdinalIgnoreCase));
    }

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        var qualifying = evidence.ConditionalAccessPolicies
            .Where(policy => policy.IsEnabled)
            .Where(policy => policy.TargetsAllUsers && policy.TargetsAllApplications)
            .Where(RequiresMultiFactor)
            .ToList();

        if (qualifying.Count == 0)
        {
            var reportOnly = evidence.ConditionalAccessPolicies
                .Count(policy => policy.IsReportOnly && policy.TargetsAllUsers && RequiresMultiFactor(policy));

            return Fail(
                context,
                "No enabled Conditional Access policy requires multi-factor authentication for all " +
                "users and all applications." +
                (reportOnly > 0
                    ? $" {reportOnly} such polic(ies) exist in report-only mode and are not enforced."
                    : string.Empty));
        }

        return Pass(
            context,
            $"{qualifying.Count} enabled polic(ies) require multi-factor authentication for all " +
            "users and all applications.",
            qualifying.Select(policy => RuleHelpers.ForEntraObject(
                policy.PolicyId,
                policy.DisplayName,
                "conditionalAccessPolicy",
                $"{policy.ExcludeUsers.Count} user exclusion(s)")).ToList());
    }
}

/// <summary>Administrative roles are covered by a multi-factor policy.</summary>
public sealed class MfaForAdministratorsRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-CA-002",
        version: 1,
        title: "Administrative roles are covered by a multi-factor policy",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraConditionalAccess,
        severity: RuleSeverity.Critical,
        rationale: "Administrators are targeted first and are the accounts whose compromise ends " +
                   "the incident immediately. A policy scoped to directory roles keeps its coverage " +
                   "correct as role membership changes.",
        remediation: "Create an enabled Conditional Access policy that targets the privileged " +
                     "directory roles and requires a phishing-resistant authentication strength.",
        evidenceKeys: [EvidenceKeys.EntraConditionalAccess, EvidenceKeys.EntraRoles],
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Additional controls on privileged access.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        var roleScoped = evidence.ConditionalAccessPolicies
            .Where(policy => policy.IsEnabled)
            .Where(MfaForAllUsersRule.RequiresMultiFactor)
            .Where(policy => policy.IncludeRoles.Any(EntraRoleCatalog.IsHighPrivilege))
            .ToList();

        if (roleScoped.Count > 0)
        {
            return Pass(
                context,
                $"{roleScoped.Count} enabled polic(ies) require multi-factor authentication for " +
                "privileged directory roles.",
                roleScoped.Select(policy => RuleHelpers.ForEntraObject(
                    policy.PolicyId,
                    policy.DisplayName,
                    "conditionalAccessPolicy")).ToList());
        }

        // A tenant-wide policy covers administrators too, provided none are excluded.
        var tenantWide = evidence.ConditionalAccessPolicies
            .Where(policy => policy.IsEnabled)
            .Where(policy => policy.TargetsAllUsers && policy.TargetsAllApplications)
            .Where(MfaForAllUsersRule.RequiresMultiFactor)
            .ToList();

        if (tenantWide.Count == 0)
        {
            return Fail(
                context,
                "No enabled policy requires multi-factor authentication for privileged directory " +
                "roles, and no tenant-wide policy covers them either.");
        }

        var privilegedPrincipals = evidence.RoleAssignments
            .Where(assignment => EntraRoleCatalog.IsHighPrivilege(assignment.RoleDefinitionId))
            .Select(assignment => assignment.PrincipalId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var excludedAdmins = tenantWide
            .SelectMany(policy => policy.ExcludeUsers.Select(user => (policy, user)))
            .Where(entry => privilegedPrincipals.Contains(entry.user))
            .ToList();

        return excludedAdmins.Count == 0
            ? Pass(context, "Privileged accounts are covered by a tenant-wide multi-factor policy " +
                            "with no privileged exclusions.")
            : Fail(
                context,
                $"{excludedAdmins.Count} privileged principal(s) are excluded from the tenant-wide " +
                "multi-factor policies that would otherwise cover them.",
                RuleHelpers.Cap(excludedAdmins.Select(entry => RuleHelpers.ForEntraObject(
                    entry.user,
                    entry.user,
                    "principal",
                    $"Excluded from {entry.policy.DisplayName}"))));
    }
}

/// <summary>Conditional Access exclusions are kept small.</summary>
public sealed class ConditionalAccessExclusionRule : RuleBase
{
    public const string ThresholdName = "entra.conditionalAccess.maxExclusionsPerPolicy";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-CA-003",
        version: 1,
        title: "Conditional Access exclusions are limited",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraConditionalAccess,
        severity: RuleSeverity.Medium,
        rationale: "Exclusions accumulate. Each one is an account or group for which the policy " +
                   "does not apply, and a large exclusion list quietly turns a tenant-wide control " +
                   "into a partial one that nobody has re-reviewed.",
        remediation: "Review every exclusion, remove those that are no longer needed, and replace " +
                     "broad group exclusions with narrowly scoped policies where an exception is genuinely required.",
        evidenceKeys: [EvidenceKeys.EntraConditionalAccess],
        mappings: [(RuleFactory.Iso27001, "A.5.15", "Consistency of the access control policy.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var maximum = context.Threshold(ThresholdName, 5);

        var enabled = evidence.ConditionalAccessPolicies.Where(policy => policy.IsEnabled).ToList();

        if (enabled.Count == 0)
        {
            return NotApplicable(context, "The tenant has no enabled Conditional Access policies.");
        }

        var offenders = enabled
            .Select(policy => (Policy: policy, Count: policy.ExcludeUsers.Count + policy.ExcludeGroups.Count))
            .Where(entry => entry.Count > maximum)
            .Select(entry => RuleHelpers.ForEntraObject(
                entry.Policy.PolicyId,
                entry.Policy.DisplayName,
                "conditionalAccessPolicy",
                $"{entry.Count} user or group exclusion(s)"))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {enabled.Count} enabled polic(ies) keep exclusions at or below {maximum}.")
            : Fail(
                context,
                $"{offenders.Count} enabled polic(ies) exclude more than {maximum} users or groups.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Policies are not left indefinitely in report-only mode.</summary>
public sealed class ReportOnlyPolicyRule : RuleBase
{
    public const string ThresholdName = "entra.conditionalAccess.maxReportOnlyDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-CA-004",
        version: 1,
        title: "Report-only policies are not left unenforced indefinitely",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraConditionalAccess,
        severity: RuleSeverity.Low,
        rationale: "Report-only mode is designed for a short evaluation period. A policy left in " +
                   "that state for months provides no protection while giving every dashboard the " +
                   "appearance of a control that exists.",
        remediation: "Review the report-only impact, then either enable the policy or delete it.",
        evidenceKeys: [EvidenceKeys.EntraConditionalAccess],
        mappings: [(RuleFactory.Iso27001, "A.5.15", "Access control policy is actually enforced.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var maxDays = context.Threshold(ThresholdName, 30);

        var reportOnly = evidence.ConditionalAccessPolicies.Where(policy => policy.IsReportOnly).ToList();

        if (reportOnly.Count == 0)
        {
            return Pass(context, "No Conditional Access policy is in report-only mode.");
        }

        var stale = reportOnly
            .Where(policy => RuleHelpers.IsStale(
                policy.ModifiedDateTime ?? policy.CreatedDateTime,
                context.ReferenceTime,
                maxDays))
            .ToList();

        return stale.Count == 0
            ? Pass(context, $"{reportOnly.Count} polic(ies) are in report-only mode, all changed " +
                            $"within the last {maxDays} days.")
            : Fail(
                context,
                $"{stale.Count} polic(ies) have been in report-only mode for more than {maxDays} days.",
                RuleHelpers.Cap(stale.Select(policy => RuleHelpers.ForEntraObject(
                    policy.PolicyId,
                    policy.DisplayName,
                    "conditionalAccessPolicy",
                    policy.ModifiedDateTime is null
                        ? "No recorded modification date"
                        : $"Last changed {policy.ModifiedDateTime:yyyy-MM-dd}"))));
    }
}

/// <summary>Risk-based access policies are configured where the tenant is licensed for them.</summary>
public sealed class RiskBasedPolicyRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-CA-005",
        version: 1,
        title: "Risk-based access policies are configured",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraConditionalAccess,
        severity: RuleSeverity.Medium,
        rationale: "Sign-in and user risk signals detect credential compromise that a static " +
                   "policy cannot: an impossible-travel sign-in with a correct password and a " +
                   "satisfied second factor still looks legitimate to every other control.",
        remediation: "Create policies that require a password change on high user risk and a " +
                     "strong authentication challenge on high sign-in risk.",
        evidenceKeys: [EvidenceKeys.EntraConditionalAccess, EvidenceKeys.EntraTenant],
        applicability: "Applies to tenants licensed for identity protection risk signals.",
        mappings: [(RuleFactory.Iso27001, "A.8.16", "Monitoring and response to anomalous activity.")]);

    /// <summary>Service plans that expose identity protection risk signals.</summary>
    private static readonly string[] RiskCapablePlans =
    [
        "AAD_PREMIUM_P2", "IDENTITY_THREAT_PROTECTION", "AAD_PREMIUM_P2_FACULTY",
    ];

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        var licensed = evidence.Tenant.ServicePlans
            .Any(plan => RiskCapablePlans.Contains(plan, StringComparer.OrdinalIgnoreCase));

        if (!licensed)
        {
            return NotApplicable(
                context,
                "The tenant is not licensed for identity protection risk signals, so risk-based " +
                "policies cannot be configured.");
        }

        var riskPolicies = evidence.ConditionalAccessPolicies
            .Where(policy => policy.IsEnabled)
            .Where(policy => policy.UserRiskLevels.Count > 0 || policy.SignInRiskLevels.Count > 0)
            .ToList();

        return riskPolicies.Count > 0
            ? Pass(
                context,
                $"{riskPolicies.Count} enabled polic(ies) act on user or sign-in risk.",
                riskPolicies.Select(policy => RuleHelpers.ForEntraObject(
                    policy.PolicyId,
                    policy.DisplayName,
                    "conditionalAccessPolicy")).ToList())
            : Fail(context, "The tenant is licensed for risk signals but no enabled policy acts on them.");
    }
}

/// <summary>Access from unmanaged devices is constrained.</summary>
public sealed class DeviceComplianceRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-CA-006",
        version: 1,
        title: "A device requirement constrains access",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraConditionalAccess,
        severity: RuleSeverity.Medium,
        rationale: "Multi-factor authentication proves who is signing in, not what they are " +
                   "signing in from. Without a device requirement, a session established from a " +
                   "compromised personal machine has the same access as one from a managed endpoint.",
        remediation: "Add a Conditional Access policy requiring a compliant or hybrid-joined " +
                     "device for the applications that hold sensitive data.",
        evidenceKeys: [EvidenceKeys.EntraConditionalAccess],
        mappings: [(RuleFactory.Iso27001, "A.8.1", "Control of endpoint devices used for access.")]);

    private static readonly string[] DeviceControls = ["compliantDevice", "domainJoinedDevice"];

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        var deviceScoped = evidence.ConditionalAccessPolicies
            .Where(policy => policy.IsEnabled)
            .Where(policy => policy.GrantControls?.BuiltInControls
                .Any(control => DeviceControls.Contains(control, StringComparer.OrdinalIgnoreCase)) == true)
            .ToList();

        return deviceScoped.Count > 0
            ? Pass(
                context,
                $"{deviceScoped.Count} enabled polic(ies) require a compliant or domain-joined device.",
                deviceScoped.Select(policy => RuleHelpers.ForEntraObject(
                    policy.PolicyId,
                    policy.DisplayName,
                    "conditionalAccessPolicy")).ToList())
            : Fail(context, "No enabled Conditional Access policy requires a compliant or " +
                            "domain-joined device for any application.");
    }
}
