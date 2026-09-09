using Ipa.Contracts;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Support;

namespace Ipa.Rules.Evaluators.ActiveDirectory;

/// <summary>Group Policy objects are not writable by non-privileged principals.</summary>
public sealed class GpoPermissionRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-GPO-001",
        version: 1,
        title: "Group Policy objects are not writable by non-privileged principals",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdGroupPolicy,
        severity: RuleSeverity.Critical,
        rationale: "Write access to a Group Policy object, in the directory or in SYSVOL, means " +
                   "the ability to run code on every machine the policy applies to. A policy " +
                   "linked at the domain root reaches the domain controllers themselves.",
        remediation: "Remove edit rights over Group Policy objects from principals outside tier " +
                     "zero, in both the directory container and the SYSVOL folder, and review the " +
                     "content of any policy that was writable.",
        evidenceKeys: [EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdGroups, EvidenceKeys.AdUsers, EvidenceKeys.AdDomains],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.2", "Control of configuration paths that grant privilege."),
            (RuleFactory.Iso27001, "A.8.9", "Protection of configuration definitions."),
        ]);

    private static readonly string[] WriteRightNames =
    [
        "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty",
        "FullControl", "Modify", "Write", "CreateFiles", "CreateChild", "DeleteChild",
    ];

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var domainSids = evidence.Domains.Select(domain => domain.DomainSid).ToList();

        var offenders = new List<AffectedObject>();

        foreach (var gpo in evidence.GroupPolicies)
        {
            foreach (var permission in gpo.Permissions)
            {
                if (!WriteRightNames.Any(right =>
                        permission.Rights.Contains(right, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                if (WellKnownSids.IsExpectedPrivilegedTrustee(permission.TrusteeSid, domainSids)
                    || resolver.TierZeroGroupSids.Contains(permission.TrusteeSid))
                {
                    continue;
                }

                // Group Policy Creator Owners is expected to create, not to edit existing policies,
                // but its members are tier zero by convention and are treated as such above.
                offenders.Add(RuleHelpers.ForGpo(
                    gpo,
                    $"{permission.TrusteeName ?? permission.TrusteeSid} holds {permission.Rights} " +
                    $"on {(permission.AppliesToSysvol ? "SYSVOL" : "the directory object")}"));
            }
        }

        return offenders.Count == 0
            ? Pass(context, $"None of the {evidence.GroupPolicies.Count} collected policy object(s) " +
                            "are writable by principals outside tier zero.")
            : Fail(
                context,
                $"{offenders.Count} write grant(s) over Group Policy objects are held by principals " +
                "outside tier zero.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>No Group Policy Preferences file stores a credential.</summary>
public sealed class GpoPreferencePasswordRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-GPO-002",
        version: 1,
        title: "No Group Policy Preferences file stores a credential",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdGroupPolicy,
        severity: RuleSeverity.Critical,
        rationale: "Credentials stored in Group Policy Preferences are encrypted with a key that " +
                   "Microsoft published. Any authenticated user can read the file from SYSVOL and " +
                   "recover the password, which is very often a local administrator account " +
                   "common to every workstation.",
        remediation: "Delete the preference items that carry a stored password, reset the affected " +
                     "accounts, and manage local administrator passwords with an automatic rotation " +
                     "solution instead.",
        evidenceKeys: [EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdSysvol],
        mappings:
        [
            (RuleFactory.Iso27001, "A.5.17", "Protection of stored authentication information."),
            (RuleFactory.Iso27001, "A.8.24", "Appropriate use of cryptography."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        var offenders = evidence.GroupPolicies
            .SelectMany(gpo => gpo.PreferencePasswords.Select(artifact => RuleHelpers.ForGpo(
                gpo,
                $"{artifact.Element} in {artifact.RelativePath}" +
                (artifact.AccountName is null ? string.Empty : $" for account {artifact.AccountName}"))))
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No Group Policy Preferences file in SYSVOL carries a stored credential.")
            : Fail(
                context,
                $"{offenders.Count} Group Policy Preferences item(s) store a recoverable credential " +
                "readable by any authenticated user.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Group Policy objects are linked and internally consistent.</summary>
public sealed class GpoConsistencyRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-GPO-003",
        version: 1,
        title: "Group Policy objects are linked and version consistent",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdGroupPolicy,
        severity: RuleSeverity.Low,
        rationale: "An unlinked policy is dead configuration that still has to be reviewed and " +
                   "still grants whoever can edit it a place to hide changes. A mismatch between " +
                   "the directory version and the SYSVOL version means replication did not finish, " +
                   "so machines apply different settings depending on which controller they reach.",
        remediation: "Remove policies that are no longer linked, and investigate SYSVOL replication " +
                     "for any policy whose directory and file versions disagree.",
        evidenceKeys: [EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdSysvol],
        mappings: [(RuleFactory.Iso27001, "A.8.9", "Configuration management.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        if (evidence.GroupPolicies.Count == 0)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "No Group Policy objects were collected.");
        }

        var offenders = new List<AffectedObject>();

        foreach (var gpo in evidence.GroupPolicies)
        {
            if (gpo.IsUnlinked)
            {
                offenders.Add(RuleHelpers.ForGpo(gpo, "The policy has no enabled link"));
                continue;
            }

            if (gpo.SysvolUnavailable)
            {
                continue;
            }

            if (gpo.DirectoryVersion != gpo.SysvolVersion)
            {
                offenders.Add(RuleHelpers.ForGpo(
                    gpo,
                    $"Directory version {gpo.DirectoryVersion} differs from SYSVOL version {gpo.SysvolVersion}"));
            }
        }

        return offenders.Count == 0
            ? Pass(context, $"All {evidence.GroupPolicies.Count} policy object(s) are linked and version consistent.")
            : Fail(context, $"{offenders.Count} policy object(s) are unlinked or version inconsistent.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>Base class for rules that assert a registry policy value somewhere in the forest.</summary>
public abstract class RegistryPolicyRuleBase : RuleBase
{
    /// <summary>Registry key the setting lives under.</summary>
    protected abstract string KeyPath { get; }

    /// <summary>Registry value name.</summary>
    protected abstract string ValueName { get; }

    /// <summary>Returns true when the observed value satisfies the requirement.</summary>
    protected abstract bool IsCompliant(string value);

    /// <summary>Description of the required state, used in the result rationale.</summary>
    protected abstract string RequiredState { get; }

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;

        var matches = evidence.GroupPolicies
            .SelectMany(gpo => gpo.RegistrySettings.Select(setting => (Gpo: gpo, Setting: setting)))
            .Where(entry => string.Equals(entry.Setting.KeyPath, KeyPath, StringComparison.OrdinalIgnoreCase)
                            && string.Equals(entry.Setting.ValueName, ValueName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matches.Count == 0)
        {
            return Fail(
                context,
                $"No Group Policy object configures {KeyPath}\\{ValueName}. Required: {RequiredState}.");
        }

        var nonCompliant = matches
            .Where(entry => !IsCompliant(entry.Setting.Value))
            .Select(entry => RuleHelpers.ForGpo(
                entry.Gpo,
                $"{ValueName} = {entry.Setting.Value}, required {RequiredState}"))
            .ToList();

        return nonCompliant.Count == 0
            ? Pass(
                context,
                $"{matches.Count} policy object(s) configure {ValueName} to the required state ({RequiredState}).",
                matches.Select(entry => RuleHelpers.ForGpo(entry.Gpo, $"{ValueName} = {entry.Setting.Value}")).ToList())
            : Fail(
                context,
                $"{nonCompliant.Count} of {matches.Count} policy object(s) configure {ValueName} " +
                $"to a non-compliant value. Required: {RequiredState}.",
                RuleHelpers.Cap(nonCompliant));
    }
}

/// <summary>Domain controllers require LDAP signing.</summary>
public sealed class LdapServerSigningRule : RegistryPolicyRuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-GPO-004",
        version: 1,
        title: "Domain controllers require LDAP signing",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdGroupPolicy,
        severity: RuleSeverity.High,
        rationale: "Unsigned LDAP binds can be relayed and modified in transit, allowing an " +
                   "attacker positioned on the network to act as an authenticated directory client.",
        remediation: "Set the domain controller LDAP server signing requirement to require signing " +
                     "in a policy linked to the Domain Controllers organisational unit, after " +
                     "confirming that all clients support it.",
        evidenceKeys: [EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdSysvol],
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.20", "Security of network services."),
            (RuleFactory.Iso27001, "A.8.24", "Cryptographic protection of directory traffic."),
        ]);

    protected override string KeyPath => @"System\CurrentControlSet\Services\NTDS\Parameters";

    protected override string ValueName => "LDAPServerIntegrity";

    protected override string RequiredState => "2 (require signing)";

    protected override bool IsCompliant(string value) =>
        int.TryParse(value, out var parsed) && parsed >= 2;
}

/// <summary>Domain controllers enforce LDAP channel binding.</summary>
public sealed class LdapChannelBindingRule : RegistryPolicyRuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-GPO-005",
        version: 1,
        title: "Domain controllers enforce LDAP channel binding",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdGroupPolicy,
        severity: RuleSeverity.High,
        rationale: "Channel binding ties an authenticated LDAP session to the TLS channel it runs " +
                   "over. Without it, an attacker can relay a captured authentication into an " +
                   "LDAPS session and act as the victim.",
        remediation: "Set the domain controller LDAP channel binding token requirement to always, " +
                     "after verifying client compatibility in audit mode.",
        evidenceKeys: [EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdSysvol],
        mappings: [(RuleFactory.Iso27001, "A.8.20", "Security of network services.")]);

    protected override string KeyPath => @"System\CurrentControlSet\Services\NTDS\Parameters";

    protected override string ValueName => "LdapEnforceChannelBinding";

    protected override string RequiredState => "2 (always enforce)";

    protected override bool IsCompliant(string value) =>
        int.TryParse(value, out var parsed) && parsed >= 2;
}

/// <summary>SMB signing is required.</summary>
public sealed class SmbSigningRule : RegistryPolicyRuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-GPO-006",
        version: 1,
        title: "SMB signing is required on servers",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdGroupPolicy,
        severity: RuleSeverity.High,
        rationale: "Without required SMB signing, an authentication captured on the network can be " +
                   "relayed to another server and used there. Signing is the control that makes " +
                   "such relay fail.",
        remediation: "Require SMB packet signing on servers and clients through Group Policy, " +
                     "confirming that no legacy device depends on unsigned SMB first.",
        evidenceKeys: [EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdSysvol],
        mappings: [(RuleFactory.Iso27001, "A.8.20", "Security of network services.")]);

    protected override string KeyPath => @"System\CurrentControlSet\Services\LanManServer\Parameters";

    protected override string ValueName => "RequireSecuritySignature";

    protected override string RequiredState => "1 (required)";

    protected override bool IsCompliant(string value) =>
        int.TryParse(value, out var parsed) && parsed == 1;
}

/// <summary>Legacy NTLM authentication levels are restricted.</summary>
public sealed class LmCompatibilityRule : RegistryPolicyRuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-GPO-007",
        version: 1,
        title: "Legacy LAN Manager authentication is refused",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdGroupPolicy,
        severity: RuleSeverity.Medium,
        rationale: "Accepting LAN Manager or NTLM version one responses allows authentication " +
                   "material that can be cracked or relayed with far less effort than the modern " +
                   "equivalent.",
        remediation: "Set the LAN Manager authentication level to send NTLMv2 responses only and " +
                     "refuse LM and NTLM, after auditing for legacy clients.",
        evidenceKeys: [EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdSysvol],
        mappings: [(RuleFactory.Iso27001, "A.8.5", "Secure authentication.")]);

    protected override string KeyPath => @"System\CurrentControlSet\Control\Lsa";

    protected override string ValueName => "LmCompatibilityLevel";

    protected override string RequiredState => "5 (NTLMv2 only, refuse LM and NTLM)";

    protected override bool IsCompliant(string value) =>
        int.TryParse(value, out var parsed) && parsed >= 5;
}

/// <summary>SMBv1 is disabled.</summary>
public sealed class SmbV1Rule : RegistryPolicyRuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-GPO-008",
        version: 1,
        title: "SMB version one is disabled",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdGroupPolicy,
        severity: RuleSeverity.High,
        rationale: "SMB version one has no protection against tampering and has carried several " +
                   "wormable remote code execution flaws. It is superseded on every supported " +
                   "Windows release.",
        remediation: "Disable the SMB version one server through Group Policy and remove the " +
                     "corresponding Windows feature from managed systems.",
        evidenceKeys: [EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdSysvol],
        mappings: [(RuleFactory.Iso27001, "A.8.8", "Management of technical vulnerabilities.")]);

    protected override string KeyPath => @"System\CurrentControlSet\Services\LanManServer\Parameters";

    protected override string ValueName => "SMB1";

    protected override string RequiredState => "0 (disabled)";

    protected override bool IsCompliant(string value) =>
        int.TryParse(value, out var parsed) && parsed == 0;
}

/// <summary>Privileged logon rights are restricted to expected principals.</summary>
public sealed class PrivilegedLogonRightsRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-GPO-009",
        version: 1,
        title: "Sensitive privilege rights are restricted",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdGroupPolicy,
        severity: RuleSeverity.Medium,
        rationale: "Rights such as debugging programs, acting as part of the operating system or " +
                   "taking ownership of any object let a holder bypass the access-control model " +
                   "entirely on the machines the policy reaches.",
        remediation: "Grant the sensitive privilege rights only to the built-in Administrators " +
                     "group, and remove every other principal from those assignments.",
        evidenceKeys: [EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdSysvol, EvidenceKeys.AdGroups, EvidenceKeys.AdDomains, EvidenceKeys.AdUsers],
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Restriction of privileged system rights.")]);

    /// <summary>Privilege rights whose holders are checked against tier zero.</summary>
    private static readonly string[] SensitivePrivileges =
    [
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeLoadDriverPrivilege",
        "SeEnableDelegationPrivilege",
    ];

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var resolver = new PrivilegedPrincipalResolver(evidence);
        var domainSids = evidence.Domains.Select(domain => domain.DomainSid).ToList();

        var assignments = evidence.GroupPolicies
            .SelectMany(gpo => gpo.SecuritySettings
                .Where(setting => string.Equals(setting.Section, "Privilege Rights", StringComparison.OrdinalIgnoreCase))
                .Where(setting => SensitivePrivileges.Contains(setting.Name, StringComparer.OrdinalIgnoreCase))
                .Select(setting => (Gpo: gpo, Setting: setting)))
            .ToList();

        if (assignments.Count == 0)
        {
            return NotCollected(
                context,
                EvidenceAvailability.Unsupported,
                "No security template in SYSVOL assigned any of the sensitive privilege rights, so " +
                "the assignment could not be assessed.");
        }

        var offenders = new List<AffectedObject>();

        foreach (var (gpo, setting) in assignments)
        {
            foreach (var trustee in setting.Trustees)
            {
                if (WellKnownSids.IsExpectedPrivilegedTrustee(trustee, domainSids)
                    || resolver.TierZeroGroupSids.Contains(trustee)
                    || string.Equals(trustee, WellKnownSids.BuiltinAdministrators, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                offenders.Add(RuleHelpers.ForGpo(gpo, $"{setting.Name} granted to {trustee}"));
            }
        }

        return offenders.Count == 0
            ? Pass(context, $"All {assignments.Count} sensitive privilege assignment(s) are limited " +
                            "to expected tier-zero principals.")
            : Fail(
                context,
                $"{offenders.Count} sensitive privilege assignment(s) reach principals outside tier zero.",
                RuleHelpers.Cap(offenders));
    }
}
