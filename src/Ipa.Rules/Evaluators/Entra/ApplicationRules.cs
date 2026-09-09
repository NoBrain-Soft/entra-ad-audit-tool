using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Support;

namespace Ipa.Rules.Evaluators.Entra;

/// <summary>Application credentials are current and short lived.</summary>
public sealed class ApplicationCredentialLifetimeRule : RuleBase
{
    public const string ThresholdName = "entra.app.maxCredentialLifetimeDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-APP-001",
        version: 1,
        title: "Application credentials are current and short lived",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraApplications,
        severity: RuleSeverity.Medium,
        rationale: "A client secret valid for years is a password that survives every staff " +
                   "change and every source-control leak in that period. Expired credentials left " +
                   "in place indicate applications nobody is maintaining.",
        remediation: "Replace long-lived client secrets with certificate credentials or managed " +
                     "identities, cap secret lifetimes, and remove expired credentials.",
        evidenceKeys: [EvidenceKeys.EntraApplications],
        mappings: [(RuleFactory.Iso27001, "A.5.17", "Lifecycle management of authentication information.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var maxLifetimeDays = context.Threshold(ThresholdName, 730);
        var offenders = new List<AffectedObject>();

        foreach (var application in evidence.Applications)
        {
            foreach (var credential in application.Credentials)
            {
                if (credential.EndDateTime is not { } end)
                {
                    continue;
                }

                if (end < context.ReferenceTime)
                {
                    offenders.Add(RuleHelpers.ForEntraObject(
                        application.ObjectId,
                        application.DisplayName,
                        "application",
                        $"{credential.CredentialType} expired {end:yyyy-MM-dd}"));
                    continue;
                }

                if (credential.StartDateTime is { } start && (end - start).TotalDays > maxLifetimeDays)
                {
                    offenders.Add(RuleHelpers.ForEntraObject(
                        application.ObjectId,
                        application.DisplayName,
                        "application",
                        $"{credential.CredentialType} valid for {(end - start).TotalDays:F0} days"));
                }
            }
        }

        var total = evidence.Applications.Sum(application => application.Credentials.Count);

        if (total == 0)
        {
            return NotApplicable(context, "No application registration carries a credential.");
        }

        return offenders.Count == 0
            ? Pass(context, $"All {total} application credential(s) are current and within the " +
                            $"{maxLifetimeDays}-day lifetime limit.")
            : Fail(
                context,
                $"{offenders.Count} of {total} application credential(s) are expired or exceed the " +
                $"{maxLifetimeDays}-day lifetime limit.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Credentials approaching expiry are surfaced before they cause an outage.</summary>
public sealed class ExpiringCredentialRule : RuleBase
{
    public const string ThresholdName = "entra.app.expiryWarningDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-APP-002",
        version: 1,
        title: "No application credential expires imminently",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraApplications,
        severity: RuleSeverity.Low,
        rationale: "An expiring credential on an application that performs authentication or " +
                   "provisioning becomes an outage, and outages are frequently resolved by " +
                   "granting a longer-lived credential under time pressure.",
        remediation: "Rotate credentials that expire inside the warning window, and record renewal " +
                     "dates in the operational calendar.",
        evidenceKeys: [EvidenceKeys.EntraApplications],
        mappings: [(RuleFactory.Iso27001, "A.5.17", "Planned renewal of authentication information.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var warningDays = context.Threshold(ThresholdName, 30);
        var horizon = context.ReferenceTime.AddDays(warningDays);

        var offenders = evidence.Applications
            .SelectMany(application => application.Credentials
                .Where(credential => credential.EndDateTime is { } end
                                     && end >= context.ReferenceTime
                                     && end <= horizon)
                .Select(credential => RuleHelpers.ForEntraObject(
                    application.ObjectId,
                    application.DisplayName,
                    "application",
                    $"{credential.CredentialType} expires {credential.EndDateTime:yyyy-MM-dd}")))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"No application credential expires within {warningDays} days.")
            : Fail(
                context,
                $"{offenders.Count} application credential(s) expire within {warningDays} days.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>High-impact application permissions are not granted to tenant applications.</summary>
public sealed class HighImpactApplicationPermissionRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-APP-003",
        version: 1,
        title: "High-impact application permissions are not broadly granted",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraApplications,
        severity: RuleSeverity.Critical,
        rationale: "An application permission such as directory write or role management applies " +
                   "with no user context and no Conditional Access evaluation. An application " +
                   "holding one is equivalent to a standing administrator whose only credential is " +
                   "a secret stored in a configuration file.",
        remediation: "Replace high-impact application permissions with the narrowest scope that " +
                     "meets the requirement, use role-scoped administrative units where possible, " +
                     "and review the owners and credentials of every application that retains one.",
        evidenceKeys: [EvidenceKeys.EntraServicePrincipals],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Restriction of privileged access rights."),
            (RuleFactory.Iso27001, "A.5.23", "Security of cloud service usage."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        var offenders = evidence.ServicePrincipals
            .Where(principal => !principal.IsMicrosoftPublished)
            .SelectMany(principal => principal.AppRoleGrants
                .Where(grant => EntraRoleCatalog.HighImpactApplicationPermissions.Contains(grant.PermissionValue))
                .Select(grant => RuleHelpers.ForEntraObject(
                    principal.ObjectId,
                    principal.DisplayName,
                    "servicePrincipal",
                    $"{grant.PermissionValue} on {grant.ResourceDisplayName}")))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No tenant application holds a high-impact application permission.")
            : Fail(
                context,
                $"{offenders.Count} high-impact application permission grant(s) are held by tenant " +
                "applications.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Tenant-wide delegated consent is limited to low-impact scopes.</summary>
public sealed class TenantWideConsentRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-APP-004",
        version: 1,
        title: "Tenant-wide consent is limited to low-impact scopes",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraApplications,
        severity: RuleSeverity.High,
        rationale: "Consent granted for all principals applies to every user in the tenant at " +
                   "once, including administrators. A sensitive scope consented this way turns one " +
                   "application compromise into access to everybody's data.",
        remediation: "Revoke tenant-wide consent for sensitive scopes, re-consent per user where " +
                     "the application is genuinely required, and enable an admin consent workflow " +
                     "so future requests are reviewed.",
        evidenceKeys: [EvidenceKeys.EntraServicePrincipals],
        mappings: [(RuleFactory.Iso27001, "A.5.23", "Governance of cloud application access.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        var offenders = evidence.ServicePrincipals
            .Where(principal => !principal.IsMicrosoftPublished)
            .SelectMany(principal => principal.DelegatedGrants
                .Where(grant => string.Equals(grant.ConsentType, "AllPrincipals", StringComparison.OrdinalIgnoreCase))
                .SelectMany(grant => SplitScopes(grant.Scopes)
                    .Where(scope => EntraRoleCatalog.SensitiveDelegatedScopes.Contains(scope))
                    .Select(scope => RuleHelpers.ForEntraObject(
                        principal.ObjectId,
                        principal.DisplayName,
                        "servicePrincipal",
                        $"{scope} consented for all principals on {grant.ResourceDisplayName}"))))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No sensitive delegated scope is consented tenant-wide for a tenant application.")
            : Fail(
                context,
                $"{offenders.Count} sensitive delegated scope(s) are consented for all principals.",
                RuleHelpers.Cap(offenders));
    }

    private static IEnumerable<string> SplitScopes(string scopes) =>
        scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>Application registrations have an accountable owner.</summary>
public sealed class ApplicationOwnerRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-APP-005",
        version: 1,
        title: "Application registrations have an owner",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraApplications,
        severity: RuleSeverity.Low,
        rationale: "An application without an owner has nobody to answer questions about what it " +
                   "does, nobody to rotate its credentials and nobody to authorise its removal, so " +
                   "it stays in the tenant indefinitely.",
        remediation: "Assign at least one accountable owner to each application registration and " +
                     "remove registrations whose purpose can no longer be established.",
        evidenceKeys: [EvidenceKeys.EntraApplications],
        mappings: [(RuleFactory.Iso27001, "A.5.9", "Inventory and ownership of information assets.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        if (evidence.Applications.Count == 0)
        {
            return NotApplicable(context, "The tenant has no application registrations.");
        }

        var offenders = evidence.Applications
            .Where(application => application.OwnerObjectIds.Count == 0)
            .Select(application => RuleHelpers.ForEntraObject(
                application.ObjectId,
                application.DisplayName,
                "application",
                "No owner assigned"))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {evidence.Applications.Count} application registration(s) have an owner.")
            : Fail(
                context,
                $"{offenders.Count} of {evidence.Applications.Count} application registration(s) " +
                "have no owner.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Multi-tenant applications are deliberate rather than accidental.</summary>
public sealed class MultiTenantApplicationRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-APP-006",
        version: 1,
        title: "Application sign-in audience is restricted to this tenant",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraApplications,
        severity: RuleSeverity.Medium,
        rationale: "An application registered for multiple tenants or for personal accounts can be " +
                   "consented to by identities this organisation does not control. When the " +
                   "registration was meant to be internal, that audience is an accident nobody notices.",
        remediation: "Set the sign-in audience of internal applications to this organisational " +
                     "directory only, and document the ones that are intentionally multi-tenant.",
        evidenceKeys: [EvidenceKeys.EntraApplications],
        mappings: [(RuleFactory.Iso27001, "A.5.23", "Governance of cloud application exposure.")]);

    private static readonly string[] BroadAudiences =
    [
        "AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount",
    ];

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        if (evidence.Applications.Count == 0)
        {
            return NotApplicable(context, "The tenant has no application registrations.");
        }

        var offenders = evidence.Applications
            .Where(application => application.SignInAudience is not null
                                  && BroadAudiences.Contains(application.SignInAudience, StringComparer.OrdinalIgnoreCase))
            .Select(application => RuleHelpers.ForEntraObject(
                application.ObjectId,
                application.DisplayName,
                "application",
                $"Sign-in audience {application.SignInAudience}"))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "Every application registration is restricted to this tenant.")
            : Fail(
                context,
                $"{offenders.Count} application registration(s) accept identities from outside this tenant.",
                RuleHelpers.Cap(offenders));
    }
}
