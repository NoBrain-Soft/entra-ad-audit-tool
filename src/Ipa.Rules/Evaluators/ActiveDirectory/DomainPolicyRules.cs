using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;

namespace Ipa.Rules.Evaluators.ActiveDirectory;

/// <summary>Base class for rules that examine each domain's password policy.</summary>
public abstract class DomainPolicyRuleBase : RuleBase
{
    /// <summary>Evaluates one domain policy, returning null when the domain complies.</summary>
    protected abstract string? Check(AdDomain domain, AdPasswordPolicy policy, RuleEvaluationContext context);

    /// <summary>Message describing the compliant state, used when every domain passes.</summary>
    protected abstract string PassMessage(int domainCount);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var withPolicy = evidence.Domains.Where(domain => domain.PasswordPolicy is not null).ToList();

        if (withPolicy.Count == 0)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "No domain password policy was collected, so the setting could not be assessed.");
        }

        var failures = new List<AffectedObject>();

        foreach (var domain in withPolicy)
        {
            var problem = Check(domain, domain.PasswordPolicy!, context);
            if (problem is not null)
            {
                failures.Add(new AffectedObject
                {
                    Identifier = domain.DomainSid,
                    DisplayName = domain.DnsName,
                    ObjectType = "domain",
                    Source = AssessmentSource.ActiveDirectory,
                    Detail = problem,
                    Sensitivity = Sensitivity.Summary,
                });
            }
        }

        return failures.Count == 0
            ? Pass(context, PassMessage(withPolicy.Count))
            : Fail(context, $"{failures.Count} of {withPolicy.Count} domain(s) do not meet the requirement.", failures);
    }
}

/// <summary>Minimum password length meets the configured floor.</summary>
public sealed class MinimumPasswordLengthRule : DomainPolicyRuleBase
{
    public const string ThresholdName = "ad.password.minimumLength";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-POL-001",
        version: 1,
        title: "Minimum password length is sufficient",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDomainPolicy,
        severity: RuleSeverity.Medium,
        rationale: "Short passwords fall to offline attack in minutes once any hash is recovered. " +
                   "Length is the single most effective parameter available in the domain policy.",
        remediation: "Raise the minimum password length in the default domain policy, and use " +
                     "fine-grained password policies where a higher floor is needed for privileged accounts.",
        evidenceKeys: [EvidenceKeys.AdPasswordPolicy, EvidenceKeys.AdDomains],
        mappings: [(RuleFactory.Iso27001, "A.5.17", "Requirements for authentication information.")]);

    protected override string? Check(AdDomain domain, AdPasswordPolicy policy, RuleEvaluationContext context)
    {
        var minimum = context.Threshold(ThresholdName, 14);
        return policy.MinimumPasswordLength >= minimum
            ? null
            : $"Minimum length {policy.MinimumPasswordLength}, required {minimum}";
    }

    protected override string PassMessage(int domainCount) =>
        $"All {domainCount} domain(s) enforce the required minimum password length.";
}

/// <summary>Password complexity is enforced.</summary>
public sealed class PasswordComplexityRule : DomainPolicyRuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-POL-002",
        version: 1,
        title: "Password complexity is enforced",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDomainPolicy,
        severity: RuleSeverity.Medium,
        rationale: "Without the complexity requirement the directory also stops rejecting " +
                   "passwords that contain the account name, which are the first candidates any " +
                   "attacker tries.",
        remediation: "Enable the password complexity requirement in the default domain policy.",
        evidenceKeys: [EvidenceKeys.AdPasswordPolicy, EvidenceKeys.AdDomains],
        mappings: [(RuleFactory.Iso27001, "A.5.17", "Requirements for authentication information.")]);

    protected override string? Check(AdDomain domain, AdPasswordPolicy policy, RuleEvaluationContext context) =>
        policy.ComplexityEnabled ? null : "Complexity requirement disabled";

    protected override string PassMessage(int domainCount) =>
        $"All {domainCount} domain(s) enforce password complexity.";
}

/// <summary>Reversible encryption is disabled.</summary>
public sealed class ReversibleEncryptionRule : DomainPolicyRuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-POL-003",
        version: 1,
        title: "Passwords are not stored with reversible encryption",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDomainPolicy,
        severity: RuleSeverity.High,
        rationale: "Reversible encryption stores passwords in a form that can be decrypted back " +
                   "to plaintext. Anyone who can read the directory database can read every " +
                   "affected password directly.",
        remediation: "Disable reversible password storage in the default domain policy and reset " +
                     "the passwords of accounts that were stored this way.",
        evidenceKeys: [EvidenceKeys.AdPasswordPolicy, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.17", "Protection of stored authentication information."),
            (RuleFactory.Iso27001, "A.8.24", "Appropriate use of cryptography."),
        ]);

    protected override string? Check(AdDomain domain, AdPasswordPolicy policy, RuleEvaluationContext context) =>
        policy.ReversibleEncryptionEnabled ? "Reversible encryption enabled" : null;

    protected override string PassMessage(int domainCount) =>
        $"No domain of the {domainCount} assessed stores passwords with reversible encryption.";
}

/// <summary>Account lockout is configured to slow online guessing.</summary>
public sealed class AccountLockoutRule : DomainPolicyRuleBase
{
    public const string MaxThresholdName = "ad.lockout.maxThreshold";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-POL-004",
        version: 1,
        title: "Account lockout is configured",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDomainPolicy,
        severity: RuleSeverity.Medium,
        rationale: "Without a lockout threshold an attacker can guess passwords indefinitely " +
                   "against every account in the domain, and password spraying succeeds against " +
                   "any user who chose a predictable password.",
        remediation: "Set a lockout threshold that stops sustained guessing while tolerating " +
                     "normal user error, together with a lockout duration and observation window.",
        evidenceKeys: [EvidenceKeys.AdPasswordPolicy, EvidenceKeys.AdDomains],
        mappings: [(RuleFactory.Iso27001, "A.8.5", "Secure authentication controls.")]);

    protected override string? Check(AdDomain domain, AdPasswordPolicy policy, RuleEvaluationContext context)
    {
        var maximum = context.Threshold(MaxThresholdName, 10);

        if (policy.LockoutThreshold == 0)
        {
            return "Lockout threshold not set";
        }

        return policy.LockoutThreshold > maximum
            ? $"Lockout threshold {policy.LockoutThreshold}, maximum {maximum}"
            : null;
    }

    protected override string PassMessage(int domainCount) =>
        $"All {domainCount} domain(s) enforce an account lockout threshold.";
}

/// <summary>Password history prevents immediate reuse.</summary>
public sealed class PasswordHistoryRule : DomainPolicyRuleBase
{
    public const string ThresholdName = "ad.password.minimumHistory";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-POL-005",
        version: 1,
        title: "Password history prevents immediate reuse",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDomainPolicy,
        severity: RuleSeverity.Low,
        rationale: "A short password history lets a user cycle straight back to a password that " +
                   "may already be known, defeating the purpose of any rotation requirement.",
        remediation: "Set the enforced password history to the recommended number of remembered passwords.",
        evidenceKeys: [EvidenceKeys.AdPasswordPolicy, EvidenceKeys.AdDomains],
        mappings: [(RuleFactory.Iso27001, "A.5.17", "Requirements for authentication information.")]);

    protected override string? Check(AdDomain domain, AdPasswordPolicy policy, RuleEvaluationContext context)
    {
        var minimum = context.Threshold(ThresholdName, 24);
        return policy.PasswordHistoryLength >= minimum
            ? null
            : $"History {policy.PasswordHistoryLength}, required {minimum}";
    }

    protected override string PassMessage(int domainCount) =>
        $"All {domainCount} domain(s) enforce the required password history.";
}

/// <summary>The key distribution account's password is rotated.</summary>
public sealed class KrbtgtRotationRule : RuleBase
{
    public const string ThresholdName = "ad.krbtgt.maxAgeDays";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-POL-006",
        version: 1,
        title: "The Kerberos key distribution account is rotated",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDomainPolicy,
        severity: RuleSeverity.High,
        rationale: "The krbtgt key signs every Kerberos ticket in the domain. An attacker who has " +
                   "ever obtained it can forge tickets for any account indefinitely, and only two " +
                   "successive rotations invalidate that capability.",
        remediation: "Rotate the krbtgt password twice, allowing full replication between the two " +
                     "rotations, and repeat on a defined schedule.",
        evidenceKeys: [EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.17", "Lifecycle management of authentication secrets."),
            (RuleFactory.Iso27001, "A.8.24", "Key management for authentication services."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var maxAgeDays = context.Threshold(ThresholdName, 180);

        var known = evidence.Domains.Where(domain => domain.KrbtgtPasswordLastSet is not null).ToList();

        if (known.Count == 0)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "The password age of the key distribution account was not collected for any domain.");
        }

        var offenders = known
            .Where(domain => (context.ReferenceTime - domain.KrbtgtPasswordLastSet!.Value).TotalDays > maxAgeDays)
            .Select(domain => new AffectedObject
            {
                Identifier = domain.DomainSid,
                DisplayName = domain.DnsName,
                ObjectType = "domain",
                Source = AssessmentSource.ActiveDirectory,
                Detail = $"krbtgt password set {domain.KrbtgtPasswordLastSet:yyyy-MM-dd}",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {known.Count} domain(s) rotated the key distribution account " +
                            $"within {maxAgeDays} days.")
            : Fail(
                context,
                $"{offenders.Count} of {known.Count} domain(s) have not rotated the key " +
                $"distribution account within {maxAgeDays} days.",
                offenders);
    }
}

/// <summary>Ordinary users cannot join machines to the domain.</summary>
public sealed class MachineAccountQuotaRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-POL-007",
        version: 1,
        title: "Ordinary users cannot create computer accounts",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDomainPolicy,
        severity: RuleSeverity.Medium,
        rationale: "The default machine account quota lets any authenticated user create computer " +
                   "accounts. Those accounts are the starting point for several privilege " +
                   "escalation techniques, including resource-based delegation abuse.",
        remediation: "Set the machine account quota to zero and delegate machine creation to a " +
                     "dedicated group or provisioning service.",
        evidenceKeys: [EvidenceKeys.AdDomains],
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Restriction of privileged directory operations.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        if (evidence.Domains.Count == 0)
        {
            return NotCollected(context, EvidenceAvailability.Unsupported, "No domains were collected.");
        }

        var offenders = evidence.Domains
            .Where(domain => domain.MachineAccountQuota > 0)
            .Select(domain => new AffectedObject
            {
                Identifier = domain.DomainSid,
                DisplayName = domain.DnsName,
                ObjectType = "domain",
                Source = AssessmentSource.ActiveDirectory,
                Detail = $"Machine account quota {domain.MachineAccountQuota}",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "Every domain sets the machine account quota to zero.")
            : Fail(
                context,
                $"{offenders.Count} domain(s) allow authenticated users to create computer accounts.",
                offenders);
    }
}

/// <summary>Domains run a functional level that still receives directory security features.</summary>
public sealed class DomainFunctionalLevelRule : RuleBase
{
    public const string ThresholdName = "ad.domain.minimumFunctionalLevel";

    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-POL-008",
        version: 1,
        title: "Domain functional level is current",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDomainPolicy,
        severity: RuleSeverity.Medium,
        rationale: "Several directory protections, among them Protected Users and the credential " +
                   "hardening that accompanies it, require a recent domain functional level. An " +
                   "older level silently prevents those controls from taking effect.",
        remediation: "Retire domain controllers running unsupported versions and raise the domain " +
                     "functional level once every controller supports it.",
        evidenceKeys: [EvidenceKeys.AdDomains],
        mappings: [(RuleFactory.Iso27001, "A.8.8", "Management of technical vulnerabilities.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        // Functional level 7 corresponds to Windows Server 2016.
        var minimum = context.Threshold(ThresholdName, 7);

        if (evidence.Domains.Count == 0)
        {
            return NotCollected(context, EvidenceAvailability.Unsupported, "No domains were collected.");
        }

        var offenders = evidence.Domains
            .Where(domain => domain.FunctionalLevel < minimum)
            .Select(domain => new AffectedObject
            {
                Identifier = domain.DomainSid,
                DisplayName = domain.DnsName,
                ObjectType = "domain",
                Source = AssessmentSource.ActiveDirectory,
                Detail = $"Functional level {domain.FunctionalLevel}, required {minimum}",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"All {evidence.Domains.Count} domain(s) run functional level {minimum} or later.")
            : Fail(context, $"{offenders.Count} domain(s) run a functional level below {minimum}.", offenders);
    }
}

/// <summary>The directory recycle bin is enabled so deletions are recoverable.</summary>
public sealed class RecycleBinRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-POL-009",
        version: 1,
        title: "The directory recycle bin is enabled",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdDomainPolicy,
        severity: RuleSeverity.Low,
        rationale: "Without the recycle bin, recovering a deleted object means an authoritative " +
                   "restore from backup. Mass deletion during an incident then becomes an outage " +
                   "rather than an inconvenience.",
        remediation: "Enable the Active Directory recycle bin. The change is forest-wide and cannot " +
                     "be reversed, so confirm the forest functional level requirement first.",
        evidenceKeys: [EvidenceKeys.AdDomains],
        mappings: [(RuleFactory.Iso27001, "A.8.13", "Ability to restore information after deletion.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        if (evidence.Domains.Count == 0)
        {
            return NotCollected(context, EvidenceAvailability.Unsupported, "No domains were collected.");
        }

        return evidence.Domains.All(domain => domain.RecycleBinEnabled)
            ? Pass(context, "The directory recycle bin is enabled.")
            : Fail(context, "The directory recycle bin is not enabled for the forest.");
    }
}
