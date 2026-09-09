using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Support;

namespace Ipa.Rules.Evaluators.Entra;

/// <summary>The number of standing Global Administrators is within the recommended range.</summary>
public sealed class GlobalAdministratorCountRule : RuleBase
{
    public const string MinimumThresholdName = "entra.globalAdmin.minimum";
    public const string MaximumThresholdName = "entra.globalAdmin.maximum";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-PRIV-001",
        version: 1,
        title: "Global Administrator count is within the recommended range",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraPrivilegedAccess,
        severity: RuleSeverity.High,
        rationale: "Too few Global Administrators risks losing control of the tenant when the only " +
                   "holder is unavailable. Too many spreads the highest privilege in the tenant " +
                   "across accounts nobody reviews individually.",
        remediation: "Keep a small number of permanently assigned Global Administrators, cover " +
                     "everyday duties with least-privilege roles, and use eligible assignments for " +
                     "the remainder.",
        evidenceKeys: [EvidenceKeys.EntraRoles],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Restriction and allocation of privileged access rights."),
            (RuleFactory.Iso27001, "A.5.18", "Review of access rights."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var minimum = context.Threshold(MinimumThresholdName, 2);
        var maximum = context.Threshold(MaximumThresholdName, 5);

        var permanent = evidence.RoleAssignments
            .Where(assignment => assignment.RoleDefinitionId == EntraRoleCatalog.GlobalAdministrator)
            .Where(assignment => assignment.Kind != RoleAssignmentKind.Eligible)
            .Where(assignment => !string.Equals(assignment.PrincipalType, "servicePrincipal", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (permanent.Count >= minimum && permanent.Count <= maximum)
        {
            return Pass(
                context,
                $"{permanent.Count} standing Global Administrator assignment(s), within the " +
                $"recommended range of {minimum} to {maximum}.");
        }

        return Fail(
            context,
            permanent.Count < minimum
                ? $"Only {permanent.Count} standing Global Administrator assignment(s) exist; at " +
                  $"least {minimum} are recommended so that tenant control survives one account being lost."
                : $"{permanent.Count} standing Global Administrator assignment(s) exist, above the " +
                  $"recommended maximum of {maximum}.",
            RuleHelpers.Cap(permanent.Select(assignment => RuleHelpers.ForEntraObject(
                assignment.PrincipalId,
                assignment.PrincipalDisplayName,
                assignment.PrincipalType,
                "Permanent Global Administrator"))));
    }
}

/// <summary>Privileged roles are held through eligible rather than standing assignments.</summary>
public sealed class JustInTimePrivilegeRule : RuleBase
{
    public const string ThresholdName = "entra.pim.minimumEligiblePercent";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-PRIV-002",
        version: 1,
        title: "Privileged roles are activated just in time",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraPrivilegedAccess,
        severity: RuleSeverity.High,
        rationale: "A standing privileged assignment is exploitable at any moment, including while " +
                   "its owner is asleep. Eligible assignments shrink the window in which stolen " +
                   "credentials carry privilege, and produce an activation record for every use.",
        remediation: "Convert standing assignments of privileged roles to eligible assignments " +
                     "with approval and justification requirements, retaining only the emergency " +
                     "access accounts as permanent.",
        evidenceKeys: [EvidenceKeys.EntraRoles, EvidenceKeys.EntraPrivilegedIdentityManagement],
        applicability: "Applies to tenants licensed for Privileged Identity Management.",
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Time-bound allocation of privileged access.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var minimumPercent = context.Threshold(ThresholdName, 60);

        var privileged = evidence.RoleAssignments
            .Where(assignment => EntraRoleCatalog.IsHighPrivilege(assignment.RoleDefinitionId))
            .Where(assignment => !string.Equals(assignment.PrincipalType, "servicePrincipal", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (privileged.Count == 0)
        {
            return NotApplicable(context, "No privileged directory role assignments were found.");
        }

        var eligible = privileged.Count(assignment => assignment.Kind == RoleAssignmentKind.Eligible);
        var eligiblePercent = eligible * 100d / privileged.Count;

        return eligiblePercent >= minimumPercent
            ? Pass(context, $"{eligible} of {privileged.Count} privileged assignments " +
                            $"({eligiblePercent:F0}%) are eligible rather than standing.")
            : Fail(
                context,
                $"Only {eligible} of {privileged.Count} privileged assignments ({eligiblePercent:F0}%) " +
                $"are eligible; at least {minimumPercent}% is recommended.",
                RuleHelpers.Cap(privileged
                    .Where(assignment => assignment.Kind != RoleAssignmentKind.Eligible)
                    .Select(assignment => RuleHelpers.ForEntraObject(
                        assignment.PrincipalId,
                        assignment.PrincipalDisplayName,
                        assignment.PrincipalType,
                        $"Standing assignment of {assignment.RoleName}"))));
    }
}

/// <summary>Guest accounts do not hold privileged directory roles.</summary>
public sealed class GuestAdministratorRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-PRIV-003",
        version: 1,
        title: "Guest accounts hold no privileged directory role",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraPrivilegedAccess,
        severity: RuleSeverity.Critical,
        rationale: "A guest account is governed by another organisation's identity controls. " +
                   "Granting it a privileged role in this tenant delegates the security of the " +
                   "tenant to whatever authentication and offboarding that organisation happens to run.",
        remediation: "Remove privileged roles from guest accounts. Where external administration " +
                     "is genuinely required, issue a member account in this tenant governed by " +
                     "this organisation's controls.",
        evidenceKeys: [EvidenceKeys.EntraRoles, EvidenceKeys.EntraUsers],
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.19", "Security in supplier relationships."),
            (RuleFactory.Iso27001, "A.8.2", "Restriction of privileged access rights."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        var guestIds = evidence.Users
            .Where(user => string.Equals(user.UserType, "Guest", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(user => user.ObjectId, user => user, StringComparer.OrdinalIgnoreCase);

        var offenders = evidence.RoleAssignments
            .Where(assignment => EntraRoleCatalog.IsHighPrivilege(assignment.RoleDefinitionId))
            .Where(assignment => guestIds.ContainsKey(assignment.PrincipalId))
            .Select(assignment => RuleHelpers.ForEntraObject(
                assignment.PrincipalId,
                guestIds[assignment.PrincipalId].UserPrincipalName,
                "guest",
                $"Holds {assignment.RoleName}"))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No guest account holds a privileged directory role.")
            : Fail(context, $"{offenders.Count} guest account assignment(s) of privileged roles were found.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Privileged accounts are registered for strong authentication.</summary>
public sealed class PrivilegedMfaRegistrationRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-PRIV-004",
        version: 1,
        title: "Privileged accounts are registered for strong authentication",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraPrivilegedAccess,
        severity: RuleSeverity.Critical,
        rationale: "A privileged account without a registered strong authentication method can be " +
                   "taken over with the password alone. Password spraying against administrators " +
                   "is among the most common routes into a tenant.",
        remediation: "Register every privileged account for a phishing-resistant method, and " +
                     "enforce it with a Conditional Access policy that targets directory roles.",
        evidenceKeys: [EvidenceKeys.EntraRoles, EvidenceKeys.EntraUsers, EvidenceKeys.EntraRegistrationDetails],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.5", "Secure authentication for privileged access."),
            (RuleFactory.Iso27001, "A.8.2", "Protection of privileged access rights."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var usersById = evidence.Users.ToDictionary(user => user.ObjectId, user => user, StringComparer.OrdinalIgnoreCase);

        var privilegedUsers = evidence.RoleAssignments
            .Where(assignment => EntraRoleCatalog.IsHighPrivilege(assignment.RoleDefinitionId))
            .Where(assignment => string.Equals(assignment.PrincipalType, "user", StringComparison.OrdinalIgnoreCase))
            .Select(assignment => usersById.GetValueOrDefault(assignment.PrincipalId))
            .Where(user => user is not null)
            .Select(user => user!)
            .Where(user => user.AccountEnabled)
            .DistinctBy(user => user.ObjectId)
            .ToList();

        if (privilegedUsers.Count == 0)
        {
            return NotApplicable(context, "No enabled user accounts hold a privileged directory role.");
        }

        var withoutRegistration = privilegedUsers
            .Where(user => user.Registration is null || !user.Registration.IsMfaRegistered)
            .ToList();

        return withoutRegistration.Count == 0
            ? Pass(context, $"All {privilegedUsers.Count} privileged account(s) are registered for " +
                            "strong authentication.")
            : Fail(
                context,
                $"{withoutRegistration.Count} of {privilegedUsers.Count} privileged account(s) have " +
                "no registered strong authentication method.",
                RuleHelpers.Cap(withoutRegistration.Select(user => RuleHelpers.ForEntraUser(
                    user,
                    "No registered multi-factor method"))));
    }
}

/// <summary>Privileged accounts are in active use.</summary>
public sealed class InactivePrivilegedAccountRule : RuleBase
{
    public const string ThresholdName = "entra.privileged.maxIdleDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-PRIV-005",
        version: 1,
        title: "No dormant privileged accounts",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraPrivilegedAccess,
        severity: RuleSeverity.High,
        rationale: "A privileged account nobody uses is a privileged account nobody monitors, and " +
                   "its owner will not notice a sign-in they did not make.",
        remediation: "Remove privileged roles from accounts that have not signed in within the " +
                     "review period, keeping documented emergency access accounts as the exception.",
        evidenceKeys: [EvidenceKeys.EntraRoles, EvidenceKeys.EntraUsers, EvidenceKeys.EntraSignInActivity],
        mappings: [(RuleFactory.Iso27001, "A.5.18", "Regular review and removal of access rights.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var maxIdleDays = context.Threshold(ThresholdName, 90);
        var usersById = evidence.Users.ToDictionary(user => user.ObjectId, user => user, StringComparer.OrdinalIgnoreCase);

        var privilegedUsers = evidence.RoleAssignments
            .Where(assignment => EntraRoleCatalog.IsHighPrivilege(assignment.RoleDefinitionId))
            .Where(assignment => string.Equals(assignment.PrincipalType, "user", StringComparison.OrdinalIgnoreCase))
            .Select(assignment => usersById.GetValueOrDefault(assignment.PrincipalId))
            .Where(user => user is not null)
            .Select(user => user!)
            .Where(user => user.AccountEnabled)
            .DistinctBy(user => user.ObjectId)
            .ToList();

        if (privilegedUsers.Count == 0)
        {
            return NotApplicable(context, "No enabled user accounts hold a privileged directory role.");
        }

        var dormant = privilegedUsers
            .Where(user => RuleHelpers.IsStale(
                Latest(user.LastSignInDateTime, user.LastNonInteractiveSignInDateTime),
                context.ReferenceTime,
                maxIdleDays))
            .ToList();

        return dormant.Count == 0
            ? Pass(context, $"All {privilegedUsers.Count} privileged account(s) signed in within " +
                            $"the last {maxIdleDays} days.")
            : Fail(
                context,
                $"{dormant.Count} of {privilegedUsers.Count} privileged account(s) have not signed " +
                $"in within {maxIdleDays} days.",
                RuleHelpers.Cap(dormant.Select(user => RuleHelpers.ForEntraUser(
                    user,
                    user.LastSignInDateTime is null
                        ? "No recorded sign-in"
                        : $"Last sign-in {user.LastSignInDateTime:yyyy-MM-dd}"))));
    }

    private static DateTimeOffset? Latest(DateTimeOffset? first, DateTimeOffset? second) =>
        first is null ? second : second is null ? first : first > second ? first : second;
}

/// <summary>The tenant maintains emergency access accounts.</summary>
public sealed class EmergencyAccessAccountRule : RuleBase
{
    public const string ThresholdName = "entra.emergencyAccess.minimumAccounts";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-PRIV-006",
        version: 1,
        title: "Emergency access accounts exist and are excluded from access policy",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraPrivilegedAccess,
        severity: RuleSeverity.High,
        rationale: "A misconfigured Conditional Access policy, an expired federation certificate " +
                   "or a failed authentication service can lock every administrator out of the " +
                   "tenant at once. Emergency access accounts are the documented way back in.",
        remediation: "Maintain at least two cloud-only accounts with permanent Global " +
                     "Administrator rights, excluded from Conditional Access policies, protected " +
                     "with long unique credentials and a phishing-resistant method, stored securely " +
                     "and monitored for use.",
        evidenceKeys: [EvidenceKeys.EntraRoles, EvidenceKeys.EntraUsers, EvidenceKeys.EntraConditionalAccess],
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.29", "Availability of information security during disruption."),
            (RuleFactory.Iso27001, "A.8.2", "Controlled provision of privileged access."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var minimum = context.Threshold(ThresholdName, 2);
        var usersById = evidence.Users.ToDictionary(user => user.ObjectId, user => user, StringComparer.OrdinalIgnoreCase);

        var excludedPrincipals = evidence.ConditionalAccessPolicies
            .Where(policy => policy.IsEnabled)
            .SelectMany(policy => policy.ExcludeUsers)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var candidates = evidence.RoleAssignments
            .Where(assignment => assignment.RoleDefinitionId == EntraRoleCatalog.GlobalAdministrator)
            .Where(assignment => assignment.Kind == RoleAssignmentKind.Permanent)
            .Select(assignment => usersById.GetValueOrDefault(assignment.PrincipalId))
            .Where(user => user is not null)
            .Select(user => user!)
            .Where(user => user.AccountEnabled)
            .Where(user => !user.OnPremisesSyncEnabled)
            .Where(user => excludedPrincipals.Contains(user.ObjectId))
            .DistinctBy(user => user.ObjectId)
            .ToList();

        return candidates.Count >= minimum
            ? Pass(
                context,
                $"{candidates.Count} cloud-only Global Administrator account(s) are excluded from " +
                "Conditional Access and are consistent with emergency access accounts.",
                candidates.Select(user => RuleHelpers.ForEntraUser(user, "Emergency access candidate")).ToList())
            : Fail(
                context,
                $"Only {candidates.Count} cloud-only Global Administrator account(s) are excluded " +
                $"from Conditional Access; at least {minimum} emergency access accounts are recommended. " +
                "Verify the tenant's emergency access arrangements and record them as an exception " +
                "if they take a different form.");
    }
}

/// <summary>Service principals hold no privileged directory role.</summary>
public sealed class PrivilegedServicePrincipalRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-PRIV-007",
        version: 1,
        title: "Service principals hold no high-privilege directory role",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraPrivilegedAccess,
        severity: RuleSeverity.High,
        rationale: "A service principal authenticates with a secret or certificate and is not " +
                   "subject to Conditional Access in the way a user is. A privileged role held by " +
                   "one converts any leak of that credential directly into tenant administration.",
        remediation: "Replace privileged directory roles held by service principals with the " +
                     "narrowest application permissions that meet the need, and move the workload " +
                     "to a managed identity with certificate credentials where possible.",
        evidenceKeys: [EvidenceKeys.EntraRoles, EvidenceKeys.EntraServicePrincipals],
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Restriction of privileged access rights.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var microsoftPublished = evidence.ServicePrincipals
            .Where(principal => principal.IsMicrosoftPublished)
            .Select(principal => principal.ObjectId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var offenders = evidence.RoleAssignments
            .Where(assignment => EntraRoleCatalog.IsHighPrivilege(assignment.RoleDefinitionId))
            .Where(assignment => string.Equals(assignment.PrincipalType, "servicePrincipal", StringComparison.OrdinalIgnoreCase))
            .Where(assignment => !microsoftPublished.Contains(assignment.PrincipalId))
            .Select(assignment => RuleHelpers.ForEntraObject(
                assignment.PrincipalId,
                assignment.PrincipalDisplayName,
                "servicePrincipal",
                $"Holds {assignment.RoleName}"))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No tenant service principal holds a high-privilege directory role.")
            : Fail(
                context,
                $"{offenders.Count} service principal assignment(s) of high-privilege directory " +
                "roles were found.",
                RuleHelpers.Cap(offenders));
    }
}
