using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;

namespace Ipa.Rules.Evaluators.Entra;

/// <summary>Strong authentication registration covers the member population.</summary>
public sealed class MfaRegistrationCoverageRule : RuleBase
{
    public const string ThresholdName = "entra.mfa.minimumRegisteredPercent";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-AUTH-001",
        version: 1,
        title: "Strong authentication registration covers the member population",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraAuthentication,
        severity: RuleSeverity.High,
        rationale: "Every account without a registered strong method is an account that can be " +
                   "taken over with a password alone, and a gap that must be excluded from any " +
                   "policy that enforces multi-factor authentication.",
        remediation: "Drive registration to completion through a registration campaign, then " +
                     "enforce registration and use with Conditional Access.",
        evidenceKeys: [EvidenceKeys.EntraUsers, EvidenceKeys.EntraRegistrationDetails],
        mappings: [(RuleFactory.Iso27001, "A.8.5", "Secure authentication.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var minimumPercent = context.Threshold(ThresholdName, 95);

        var members = evidence.Users
            .Where(user => user.AccountEnabled)
            .Where(user => string.Equals(user.UserType, "Member", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (members.Count == 0)
        {
            return NotApplicable(context, "The tenant contains no enabled member accounts.");
        }

        var registered = members.Count(user => user.Registration?.IsMfaRegistered == true);
        var percent = registered * 100d / members.Count;

        return percent >= minimumPercent
            ? Pass(context, $"{registered} of {members.Count} enabled member accounts ({percent:F1}%) " +
                            "are registered for strong authentication.")
            : Fail(
                context,
                $"Only {registered} of {members.Count} enabled member accounts ({percent:F1}%) are " +
                $"registered for strong authentication, below the {minimumPercent}% target.",
                RuleHelpers.Cap(members
                    .Where(user => user.Registration?.IsMfaRegistered != true)
                    .Select(user => RuleHelpers.ForEntraUser(user, "Not registered"))));
    }
}

/// <summary>Legacy authentication protocols are blocked by policy.</summary>
public sealed class LegacyAuthenticationBlockedRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-AUTH-002",
        version: 1,
        title: "Legacy authentication is blocked by Conditional Access",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraAuthentication,
        severity: RuleSeverity.Critical,
        rationale: "Legacy authentication clients cannot present a second factor. As long as they " +
                   "are permitted, every multi-factor requirement in the tenant can be bypassed " +
                   "simply by choosing an older protocol.",
        remediation: "Create an enabled Conditional Access policy that blocks the legacy " +
                     "authentication client types for all users, having first identified the " +
                     "remaining legacy clients through the sign-in logs.",
        evidenceKeys: [EvidenceKeys.EntraConditionalAccess],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.5", "Secure authentication."),
            (RuleFactory.Iso27001, "A.8.20", "Security of network services."),
        ]);

    private static readonly string[] LegacyClientTypes = ["exchangeActiveSync", "other"];

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        var blocking = evidence.ConditionalAccessPolicies
            .Where(policy => policy.IsEnabled)
            .Where(policy => policy.TargetsAllUsers)
            .Where(policy => policy.ClientAppTypes.Any(type =>
                LegacyClientTypes.Contains(type, StringComparer.OrdinalIgnoreCase)))
            .Where(policy => policy.GrantControls?.BuiltInControls
                .Contains("block", StringComparer.OrdinalIgnoreCase) == true)
            .ToList();

        return blocking.Count > 0
            ? Pass(
                context,
                $"{blocking.Count} enabled Conditional Access polic(ies) block legacy authentication " +
                "for all users.",
                blocking.Select(policy => RuleHelpers.ForEntraObject(
                    policy.PolicyId,
                    policy.DisplayName,
                    "conditionalAccessPolicy")).ToList())
            : Fail(
                context,
                "No enabled Conditional Access policy blocks legacy authentication client types " +
                "for all users.");
    }
}

/// <summary>Legacy authentication is not observed succeeding in the sign-in logs.</summary>
public sealed class LegacyAuthenticationObservedRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-AUTH-003",
        version: 1,
        title: "No successful legacy authentication is observed",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraAuthentication,
        severity: RuleSeverity.High,
        rationale: "A blocking policy that is scoped too narrowly still leaves legacy sign-ins " +
                   "succeeding. The sign-in record is the evidence that the control is actually " +
                   "in force rather than merely configured.",
        remediation: "Identify the applications and accounts still signing in with legacy " +
                     "protocols, migrate them to modern authentication, and widen the blocking policy.",
        evidenceKeys: [EvidenceKeys.EntraLegacyAuthentication],
        mappings: [(RuleFactory.Iso27001, "A.8.16", "Monitoring of authentication activity.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;

        var successful = evidence.LegacyAuthentication
            .Where(observation => observation.SuccessfulSignInCount > 0)
            .ToList();

        return successful.Count == 0
            ? Pass(context, "No successful legacy authentication sign-in was observed in the " +
                            "collected sign-in activity.")
            : Fail(
                context,
                $"{successful.Sum(observation => observation.SuccessfulSignInCount)} successful " +
                $"legacy authentication sign-in(s) across {successful.Count} client application(s) " +
                "were observed.",
                RuleHelpers.Cap(successful.Select(observation => RuleHelpers.ForEntraObject(
                    observation.ClientApplication,
                    observation.ClientApplication,
                    "clientApplication",
                    $"{observation.SuccessfulSignInCount} successful sign-in(s) by " +
                    $"{observation.DistinctUserCount} account(s)"))));
    }
}

/// <summary>The authentication methods policy enables phishing-resistant methods.</summary>
public sealed class AuthenticationMethodPolicyRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-AUTH-004",
        version: 1,
        title: "Phishing-resistant authentication methods are enabled",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraAuthentication,
        severity: RuleSeverity.Medium,
        rationale: "Text message and voice call methods are interceptable through number porting " +
                   "and network attacks. A tenant that enables no phishing-resistant method cannot " +
                   "require one, however strong its Conditional Access policies are.",
        remediation: "Enable at least one phishing-resistant method, such as a hardware security " +
                     "key or certificate-based authentication, and plan the retirement of text " +
                     "message and voice methods.",
        evidenceKeys: [EvidenceKeys.EntraAuthenticationMethods],
        mappings: [(RuleFactory.Iso27001, "A.8.5", "Secure authentication.")]);

    private static readonly string[] PhishingResistantMethods = ["fido2", "x509Certificate", "windowsHelloForBusiness"];

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var methods = context.Evidence.Entra!.AuthenticationMethods;

        if (methods is null)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "The authentication methods policy was not collected.");
        }

        var enabled = PhishingResistantMethods
            .Where(method => methods.MethodStates.TryGetValue(method, out var state) && state)
            .ToList();

        var weakOnly = methods.MethodStates
            .Where(entry => entry.Value)
            .Where(entry => entry.Key is "sms" or "voice")
            .Select(entry => entry.Key)
            .ToList();

        if (enabled.Count > 0)
        {
            return Pass(
                context,
                $"Phishing-resistant method(s) enabled: {string.Join(", ", enabled)}." +
                (weakOnly.Count > 0
                    ? $" Interceptable method(s) also remain enabled: {string.Join(", ", weakOnly)}."
                    : string.Empty));
        }

        return Fail(
            context,
            "No phishing-resistant authentication method is enabled in the tenant policy." +
            (weakOnly.Count > 0
                ? $" Enabled interceptable method(s): {string.Join(", ", weakOnly)}."
                : string.Empty));
    }
}

/// <summary>The tenant enforces baseline protection through security defaults or policy.</summary>
public sealed class BaselineProtectionRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-AUTH-005",
        version: 1,
        title: "The tenant enforces a baseline authentication control",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraAuthentication,
        severity: RuleSeverity.High,
        rationale: "A tenant with security defaults disabled and no enabled Conditional Access " +
                   "policy enforces nothing beyond the password. That is the weakest possible " +
                   "configuration and it is reached simply by turning security defaults off.",
        remediation: "Either keep security defaults enabled, or replace them with Conditional " +
                     "Access policies that require multi-factor authentication for all users " +
                     "before disabling them.",
        evidenceKeys: [EvidenceKeys.EntraAuthenticationMethods, EvidenceKeys.EntraConditionalAccess],
        mappings: [(RuleFactory.Iso27001, "A.8.5", "Secure authentication.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.Entra!;
        var securityDefaults = evidence.AuthenticationMethods?.SecurityDefaultsEnabled == true;
        var enabledPolicies = evidence.ConditionalAccessPolicies.Count(policy => policy.IsEnabled);

        if (securityDefaults)
        {
            return Pass(context, "Security defaults are enabled for the tenant.");
        }

        return enabledPolicies > 0
            ? Pass(context, $"Security defaults are disabled, and {enabledPolicies} enabled " +
                            "Conditional Access polic(ies) are in force instead.")
            : Fail(context, "Security defaults are disabled and no Conditional Access policy is enabled, " +
                            "so the tenant enforces nothing beyond the password.");
    }
}

/// <summary>Legacy per-user multi-factor state is not in use.</summary>
public sealed class PerUserMfaRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "EID-AUTH-006",
        version: 1,
        title: "Legacy per-user multi-factor state is not in use",
        domain: RuleDomain.Entra,
        group: CheckGroup.EntraAuthentication,
        severity: RuleSeverity.Medium,
        rationale: "Per-user multi-factor state predates Conditional Access and interacts badly " +
                   "with it: the two evaluate independently, so the effective requirement for an " +
                   "account becomes hard to determine and easy to get wrong.",
        remediation: "Convert per-user enforcement to Conditional Access policies, then set every " +
                     "account's legacy state back to disabled.",
        evidenceKeys: [EvidenceKeys.EntraAuthenticationMethods],
        mappings: [(RuleFactory.Iso27001, "A.8.9", "Configuration management of security controls.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var methods = context.Evidence.Entra!.AuthenticationMethods;

        if (methods is null)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "The authentication methods policy was not collected.");
        }

        return methods.LegacyPerUserMfaInUse
            ? Fail(context, "At least one account still carries legacy per-user multi-factor state.")
            : Pass(context, "No account relies on legacy per-user multi-factor state.");
    }
}
