using Ipa.Contracts;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Support;

namespace Ipa.Rules.Evaluators.ActiveDirectory;

/// <summary>No template lets a requester name the subject of an authentication certificate.</summary>
public sealed class RequesterSuppliedSubjectRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-CS-001",
        version: 1,
        title: "No enrollable template allows a requester-supplied subject for authentication",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdCertificateServices,
        severity: RuleSeverity.Critical,
        rationale: "A template that lets the requester choose the subject, issues a certificate " +
                   "usable for authentication, and does not require approval, allows any principal " +
                   "who can enrol to request a certificate naming a domain administrator and then " +
                   "authenticate as that administrator.",
        remediation: "Require manager approval or authorised signatures on such templates, remove " +
                     "the requester-supplied subject option, or restrict enrolment to a tightly " +
                     "controlled group. Reissue certificates for any account that may have been impersonated.",
        evidenceKeys: [EvidenceKeys.AdCertificateServices, EvidenceKeys.AdGroups, EvidenceKeys.AdUsers, EvidenceKeys.AdDomains],
        applicability: "Applies when Active Directory Certificate Services publishes at least one template.",
        mappings:
        [
            (RuleFactory.Iso27001, "A.8.24", "Management of certificates and cryptographic keys."),
            (RuleFactory.Iso27001, "A.5.17", "Issuance of authentication information."),
        ]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var certificateServices = evidence.CertificateServices;

        if (certificateServices is null || certificateServices.Templates.Count == 0)
        {
            return NotApplicable(
                context,
                "No certificate templates are published in the forest, so certificate template " +
                "weaknesses do not apply.");
        }

        var resolver = new PrivilegedPrincipalResolver(evidence);
        var domainSids = evidence.Domains.Select(domain => domain.DomainSid).ToList();

        var offenders = certificateServices.Templates
            .Where(template => template.EnrolleeSuppliesSubject)
            .Where(template => template.AllowsAuthentication)
            .Where(template => template.NoManagerApproval && template.RaSignaturesRequired == 0)
            .Where(template => IsBroadlyEnrollable(template, resolver, domainSids))
            .Select(template => new AffectedObject
            {
                Identifier = template.DistinguishedName,
                DisplayName = template.DisplayName,
                ObjectType = "certificateTemplate",
                Source = AssessmentSource.ActiveDirectory,
                Detail = "Requester-supplied subject, authentication usage, no approval required",
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, $"None of the {certificateServices.Templates.Count} published template(s) " +
                            "combine a requester-supplied subject with unapproved authentication enrolment.")
            : Fail(
                context,
                $"{offenders.Count} published template(s) allow a requester to obtain an " +
                "authentication certificate for an arbitrary subject without approval.",
                offenders);
    }

    /// <summary>True when a principal outside tier zero holds enrolment rights on the template.</summary>
    internal static bool IsBroadlyEnrollable(
        CertificateTemplate template,
        PrivilegedPrincipalResolver resolver,
        IReadOnlyList<string> domainSids) =>
        template.Permissions
            .Where(ace => !ace.IsDeny)
            .Where(ace => IsEnrolmentRight(ace))
            .Any(ace => !WellKnownSids.IsExpectedPrivilegedTrustee(ace.TrusteeSid, domainSids)
                        && !resolver.TierZeroGroupSids.Contains(ace.TrusteeSid));

    private static bool IsEnrolmentRight(AdAccessControlEntry ace) =>
        ace.Rights.HasFlag(AdAceRight.GenericAll)
        || ace.Rights.HasFlag(AdAceRight.AllExtendedRights)
        || string.Equals(ace.ObjectTypeGuid, ExtendedRights.CertificateEnrollment, StringComparison.OrdinalIgnoreCase)
        || string.Equals(ace.ObjectTypeGuid, ExtendedRights.CertificateAutoEnrollment, StringComparison.OrdinalIgnoreCase);
}

/// <summary>No broadly enrollable template carries an unrestricted or agent extended key usage.</summary>
public sealed class DangerousEkuTemplateRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-CS-002",
        version: 1,
        title: "No broadly enrollable template grants an unrestricted or enrolment-agent usage",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdCertificateServices,
        severity: RuleSeverity.High,
        rationale: "A certificate with the any-purpose usage, or with no usage restriction at all, " +
                   "can be used to authenticate as its subject. A certificate request agent usage " +
                   "lets the holder request certificates on behalf of other users. Either is a " +
                   "direct route to impersonation when broadly enrollable.",
        remediation: "Restrict the extended key usages published on such templates, or limit " +
                     "enrolment to a controlled administrative group and require manager approval.",
        evidenceKeys: [EvidenceKeys.AdCertificateServices, EvidenceKeys.AdGroups, EvidenceKeys.AdUsers, EvidenceKeys.AdDomains],
        applicability: "Applies when Active Directory Certificate Services publishes at least one template.",
        mappings: [(RuleFactory.Iso27001, "A.8.24", "Management of certificates and cryptographic keys.")]);

    /// <summary>Object identifiers whose presence makes a certificate broadly usable for impersonation.</summary>
    private static readonly string[] DangerousUsageOids =
    [
        "2.5.29.37.0",            // Any Purpose
        "1.3.6.1.4.1.311.20.2.1", // Certificate Request Agent
    ];

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var certificateServices = evidence.CertificateServices;

        if (certificateServices is null || certificateServices.Templates.Count == 0)
        {
            return NotApplicable(context, "No certificate templates are published in the forest.");
        }

        var resolver = new PrivilegedPrincipalResolver(evidence);
        var domainSids = evidence.Domains.Select(domain => domain.DomainSid).ToList();

        var offenders = certificateServices.Templates
            .Where(template => template.ExtendedKeyUsages.Count == 0
                               || template.ExtendedKeyUsages.Any(usage => DangerousUsageOids.Contains(usage)))
            .Where(template => RequesterSuppliedSubjectRule.IsBroadlyEnrollable(template, resolver, domainSids))
            .Select(template => new AffectedObject
            {
                Identifier = template.DistinguishedName,
                DisplayName = template.DisplayName,
                ObjectType = "certificateTemplate",
                Source = AssessmentSource.ActiveDirectory,
                Detail = template.ExtendedKeyUsages.Count == 0
                    ? "No extended key usage restriction"
                    : $"Usages: {string.Join(", ", template.ExtendedKeyUsages)}",
            })
            .ToList();

        return offenders.Count == 0
            ? Pass(context, "No broadly enrollable template grants an unrestricted or enrolment-agent usage.")
            : Fail(
                context,
                $"{offenders.Count} broadly enrollable template(s) grant an unrestricted or " +
                "enrolment-agent certificate usage.",
                offenders);
    }
}

/// <summary>Certificate templates and enrolment services are controlled by tier zero.</summary>
public sealed class CertificateObjectControlRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-CS-003",
        version: 1,
        title: "Certificate templates and authorities are controlled by tier zero",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdCertificateServices,
        severity: RuleSeverity.High,
        rationale: "A principal that can modify a certificate template or a certification " +
                   "authority object can make a safe template dangerous, or publish a dangerous " +
                   "one. Control of these objects is equivalent to control of the identities the " +
                   "authority can vouch for.",
        remediation: "Restrict ownership and write access on certificate template and enrolment " +
                     "service objects to tier-zero administrators, and review any template modified " +
                     "by another principal.",
        evidenceKeys: [EvidenceKeys.AdCertificateServices, EvidenceKeys.AdGroups, EvidenceKeys.AdUsers, EvidenceKeys.AdDomains],
        applicability: "Applies when Active Directory Certificate Services is present in the forest.",
        mappings: [(RuleFactory.Iso27001, "A.8.2", "Control of the systems that issue credentials.")]);

    private const AdAceRight ControlRights =
        AdAceRight.GenericAll | AdAceRight.GenericWrite | AdAceRight.WriteDacl |
        AdAceRight.WriteOwner | AdAceRight.WriteProperty;

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var evidence = context.Evidence.ActiveDirectory!;
        var certificateServices = evidence.CertificateServices;

        if (certificateServices is null
            || (certificateServices.Templates.Count == 0 && certificateServices.EnrollmentServices.Count == 0))
        {
            return NotApplicable(context, "Active Directory Certificate Services is not present in the forest.");
        }

        var resolver = new PrivilegedPrincipalResolver(evidence);
        var domainSids = evidence.Domains.Select(domain => domain.DomainSid).ToList();
        var offenders = new List<AffectedObject>();

        void Inspect(string displayName, string identifier, string? ownerSid, IReadOnlyList<AdAccessControlEntry> aces)
        {
            if (ownerSid is not null
                && !WellKnownSids.IsExpectedPrivilegedTrustee(ownerSid, domainSids)
                && !resolver.TierZeroGroupSids.Contains(ownerSid))
            {
                offenders.Add(new AffectedObject
                {
                    Identifier = identifier,
                    DisplayName = displayName,
                    ObjectType = "certificateObject",
                    Source = AssessmentSource.ActiveDirectory,
                    Detail = $"Owned by {ownerSid}",
                });
            }

            foreach (var ace in aces.Where(entry => !entry.IsDeny && (entry.Rights & ControlRights) != AdAceRight.None))
            {
                if (WellKnownSids.IsExpectedPrivilegedTrustee(ace.TrusteeSid, domainSids)
                    || resolver.TierZeroGroupSids.Contains(ace.TrusteeSid))
                {
                    continue;
                }

                offenders.Add(new AffectedObject
                {
                    Identifier = identifier,
                    DisplayName = displayName,
                    ObjectType = "certificateObject",
                    Source = AssessmentSource.ActiveDirectory,
                    Detail = $"{ace.TrusteeName ?? ace.TrusteeSid} holds {ace.Rights}",
                });
            }
        }

        foreach (var template in certificateServices.Templates)
        {
            Inspect(template.DisplayName, template.DistinguishedName, template.OwnerSid, template.Permissions);
        }

        foreach (var service in certificateServices.EnrollmentServices)
        {
            Inspect(service.Name, service.DistinguishedName, service.OwnerSid, service.Permissions);
        }

        return offenders.Count == 0
            ? Pass(context, "Certificate templates and enrolment services are owned and controlled by tier zero.")
            : Fail(
                context,
                $"{offenders.Count} ownership or control grant(s) over certificate objects are held " +
                "by principals outside tier zero.",
                RuleHelpers.Cap(offenders));
    }
}

/// <summary>
/// Records the certificate service checks that are deliberately out of scope. The rule always
/// reports as not collected rather than as a pass, so a report never implies these were verified.
/// </summary>
public sealed class CertificateServiceScopeNoticeRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "AD-CS-900",
        version: 1,
        title: "Certificate authority host checks are outside the read-only scope",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.AdCertificateServices,
        severity: RuleSeverity.Informational,
        rationale: "Some certificate service weaknesses can only be confirmed by probing the " +
                   "authority's web endpoints or reading its host registry. Version one of this " +
                   "product is strictly read-only over directory protocols and does not probe " +
                   "servers, so those checks are reported as unavailable rather than as passing.",
        remediation: "Assess the listed items manually, or with a tool that has authorised access " +
                     "to the certification authority host.",
        evidenceKeys: [EvidenceKeys.AdCertificateServices],
        mappings: [(RuleFactory.Iso27001, "A.8.8", "Completeness of vulnerability assessment.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var certificateServices = context.Evidence.ActiveDirectory!.CertificateServices;
        var items = certificateServices?.OutOfScopeChecks ?? [];

        return NotCollected(
            context,
            EvidenceAvailability.Unsupported,
            "The following certificate service checks require probing the certification authority " +
            "host and are outside the read-only scope of this assessment: " +
            (items.Count == 0 ? "none recorded" : string.Join("; ", items)) + ".");
    }
}
