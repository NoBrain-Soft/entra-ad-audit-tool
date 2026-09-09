using Ipa.Contracts.Compliance;

namespace Ipa.Compliance.Catalogue;

/// <summary>
/// The ISO/IEC 27001:2022 Annex A control set, identified by control number only.
/// </summary>
/// <remarks>
/// The standard's normative text and its own control titles are copyright protected and are not
/// redistributed by this product. What ships here is the control identifier, a short label written
/// by this product to describe the subject area, and guidance written by this product explaining
/// what the assessment examines for that control. An operator who holds a licensed copy of the
/// standard may paste the official text into each control's licensed-text field inside their own
/// project, where it stays within that project's encrypted container.
/// </remarks>
public static class IsoControlCatalogue
{
    /// <summary>Framework identifier used in mappings and reports.</summary>
    public const string Framework = "ISO/IEC 27001:2022";

    /// <summary>Note printed wherever the catalogue is displayed.</summary>
    public const string AuthorshipNote =
        "Control labels and guidance in this catalogue are written by " + Contracts.ProductInfo.Name +
        ". They are not the text of ISO/IEC 27001:2022, which is copyright protected and not " +
        "redistributed. Operators holding a licence may record the official wording in each " +
        "control's licensed-text field.";

    private static readonly (string Id, string Theme, string Label, string Guidance)[] Definitions =
    [
        // A.5 - organisational controls
        ("A.5.1", "Organisational", "Security policy set and approved",
            "Manual. Confirm that an information security policy exists, is approved by management and is communicated."),
        ("A.5.2", "Organisational", "Security roles and responsibilities",
            "Manual. Confirm that security responsibilities are defined and allocated to named people."),
        ("A.5.3", "Organisational", "Separation of conflicting duties",
            "Partly automated. Privileged access findings show where one account can both perform and approve an action."),
        ("A.5.4", "Organisational", "Management responsibilities",
            "Manual. Confirm that management requires staff to apply the security policy."),
        ("A.5.5", "Organisational", "Contact with authorities",
            "Manual. Confirm that contacts with relevant authorities are maintained."),
        ("A.5.6", "Organisational", "Contact with special interest groups",
            "Manual. Confirm participation in relevant professional or sector groups."),
        ("A.5.7", "Organisational", "Threat intelligence",
            "Manual. Confirm that threat information is collected and acted upon."),
        ("A.5.8", "Organisational", "Security in project management",
            "Manual. Confirm that security requirements are addressed in projects."),
        ("A.5.9", "Organisational", "Inventory of assets and ownership",
            "Partly automated. Directory object, device and application inventory findings show where ownership records are stale or absent."),
        ("A.5.10", "Organisational", "Acceptable use of assets",
            "Manual. Confirm that acceptable use rules exist and are acknowledged."),
        ("A.5.11", "Organisational", "Return of assets on leaving",
            "Partly automated. Retained disabled accounts and dormant objects indicate incomplete offboarding."),
        ("A.5.12", "Organisational", "Classification of information",
            "Manual. Confirm that an information classification scheme is defined and applied."),
        ("A.5.13", "Organisational", "Labelling of information",
            "Manual. Confirm that labelling procedures follow the classification scheme."),
        ("A.5.14", "Organisational", "Information transfer rules",
            "Manual. Confirm that rules for transferring information are defined and enforced."),
        ("A.5.15", "Organisational", "Access control policy in force",
            "Automated. Conditional Access coverage, exclusions and directory access findings evidence whether the access control policy is actually enforced."),
        ("A.5.16", "Organisational", "Identity lifecycle management",
            "Automated. Hybrid correlation, duplicate anchors, orphaned objects and stale accounts evidence the integrity of the identity lifecycle."),
        ("A.5.17", "Organisational", "Authentication information management",
            "Automated. Password policy, credential rotation, stored credentials and reversible storage findings evidence how authentication secrets are managed."),
        ("A.5.18", "Organisational", "Access rights review and removal",
            "Automated. Dormant privileged accounts, stale accounts, guest review and residual protected-account status evidence whether rights are reviewed and withdrawn."),
        ("A.5.19", "Organisational", "Security in supplier relationships",
            "Partly automated. Guest administrators, trust configuration and external collaboration findings show supplier and partner exposure."),
        ("A.5.20", "Organisational", "Security in supplier agreements",
            "Manual. Confirm that agreements state the security requirements suppliers must meet."),
        ("A.5.21", "Organisational", "Security in the supply chain",
            "Manual. Confirm that supply chain security requirements are managed."),
        ("A.5.22", "Organisational", "Monitoring of supplier services",
            "Manual. Confirm that supplier service delivery is monitored and reviewed."),
        ("A.5.23", "Organisational", "Security of cloud service use",
            "Automated. Tenant configuration, application permissions, consent grants and cloud administration findings evidence how cloud services are governed."),
        ("A.5.24", "Organisational", "Incident management planning",
            "Manual. Confirm that incident response responsibilities and procedures are defined."),
        ("A.5.25", "Organisational", "Assessment of security events",
            "Manual. Confirm that events are assessed and classified consistently."),
        ("A.5.26", "Organisational", "Response to security incidents",
            "Manual. Confirm that incidents are responded to according to procedure."),
        ("A.5.27", "Organisational", "Learning from incidents",
            "Manual. Confirm that lessons from incidents feed back into controls."),
        ("A.5.28", "Organisational", "Collection of evidence",
            "Manual. Confirm that procedures exist for identifying and preserving evidence."),
        ("A.5.29", "Organisational", "Security during disruption",
            "Partly automated. Emergency access accounts and domain controller redundancy findings evidence continuity of administrative access."),
        ("A.5.30", "Organisational", "Continuity readiness of technology",
            "Manual. Confirm that continuity requirements for technology are defined and tested."),
        ("A.5.31", "Organisational", "Legal and contractual requirements",
            "Manual. Confirm that applicable legal and contractual requirements are identified."),
        ("A.5.32", "Organisational", "Intellectual property rights",
            "Manual. Confirm that intellectual property obligations are met."),
        ("A.5.33", "Organisational", "Protection of records",
            "Manual. Confirm that records are protected against loss and falsification."),
        ("A.5.34", "Organisational", "Privacy and protection of personal data",
            "Manual. Confirm that privacy requirements are identified and met."),
        ("A.5.35", "Organisational", "Independent review of security",
            "Manual. Confirm that the security approach is independently reviewed."),
        ("A.5.36", "Organisational", "Conformance with security policy",
            "Partly automated. Baseline comparison and provider score metrics support review of conformance with defined policy."),
        ("A.5.37", "Organisational", "Documented operating procedures",
            "Manual. Confirm that operating procedures are documented and available."),

        // A.6 - people controls
        ("A.6.1", "People", "Screening before employment",
            "Manual. Confirm that background verification is performed where required."),
        ("A.6.2", "People", "Terms of employment",
            "Manual. Confirm that employment terms state security responsibilities."),
        ("A.6.3", "People", "Security awareness and training",
            "Manual. Confirm that awareness and training are delivered and recorded."),
        ("A.6.4", "People", "Disciplinary process",
            "Manual. Confirm that a disciplinary process for security breaches exists."),
        ("A.6.5", "People", "Responsibilities after leaving",
            "Manual. Confirm that responsibilities that continue after employment are defined."),
        ("A.6.6", "People", "Confidentiality agreements",
            "Manual. Confirm that confidentiality agreements are in place and reviewed."),
        ("A.6.7", "People", "Remote working",
            "Partly automated. Device and location conditions in access policy findings evidence controls over remote access."),
        ("A.6.8", "People", "Reporting of security events",
            "Manual. Confirm that staff have a route to report security events."),

        // A.7 - physical controls
        ("A.7.1", "Physical", "Physical security perimeter",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.2", "Physical", "Physical entry controls",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.3", "Physical", "Securing offices and facilities",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.4", "Physical", "Physical security monitoring",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.5", "Physical", "Protection against physical threats",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.6", "Physical", "Working in secure areas",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.7", "Physical", "Clear desk and clear screen",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.8", "Physical", "Siting and protection of equipment",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.9", "Physical", "Security of off-premises assets",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.10", "Physical", "Storage media",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.11", "Physical", "Supporting utilities",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.12", "Physical", "Cabling security",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.13", "Physical", "Equipment maintenance",
            "Manual. Physical controls are outside the scope of this assessment."),
        ("A.7.14", "Physical", "Secure disposal of equipment",
            "Manual. Physical controls are outside the scope of this assessment."),

        // A.8 - technological controls
        ("A.8.1", "Technological", "User endpoint devices",
            "Partly automated. Device compliance requirements and stale device findings evidence control over endpoints used for access."),
        ("A.8.2", "Technological", "Privileged access rights",
            "Automated. Tier-zero membership, nesting, delegation, replication rights, privileged role assignment and just-in-time findings evidence how privileged access is restricted."),
        ("A.8.3", "Technological", "Information access restriction",
            "Automated. Access-control entry findings on privileged objects evidence whether access to sensitive assets is restricted."),
        ("A.8.4", "Technological", "Access to source code",
            "Manual. Source code repositories are outside the scope of this assessment."),
        ("A.8.5", "Technological", "Secure authentication",
            "Automated. Multi-factor coverage, legacy authentication, authentication method policy and lockout findings evidence the strength of authentication."),
        ("A.8.6", "Technological", "Capacity management",
            "Manual. Capacity planning is outside the scope of this assessment."),
        ("A.8.7", "Technological", "Protection against malware",
            "Manual. Endpoint protection is outside the scope of this assessment."),
        ("A.8.8", "Technological", "Management of technical vulnerabilities",
            "Partly automated. Unsupported operating systems, functional levels and outdated configuration findings evidence exposure to known weaknesses."),
        ("A.8.9", "Technological", "Configuration management",
            "Automated. Group Policy consistency, hardening settings and the imported baseline comparison evidence configuration control."),
        ("A.8.10", "Technological", "Information deletion",
            "Manual. Confirm that information is deleted when no longer required."),
        ("A.8.11", "Technological", "Data masking",
            "Manual. Confirm that masking is applied where required."),
        ("A.8.12", "Technological", "Data leakage prevention",
            "Manual. Confirm that leakage prevention measures are applied."),
        ("A.8.13", "Technological", "Information backup",
            "Partly automated. Directory recycle bin state evidences one recovery capability; wider backup coverage is manual."),
        ("A.8.14", "Technological", "Redundancy of processing facilities",
            "Partly automated. Domain controller redundancy findings evidence availability of the authentication service."),
        ("A.8.15", "Technological", "Logging",
            "Partly automated. Availability of sign-in and audit data during collection evidences whether logging is enabled and retained."),
        ("A.8.16", "Technological", "Monitoring activities",
            "Partly automated. Risk policy configuration and observed legacy authentication evidence monitoring of anomalous activity."),
        ("A.8.17", "Technological", "Clock synchronisation",
            "Manual. Confirm that system clocks are synchronised to an approved source."),
        ("A.8.18", "Technological", "Use of privileged utility programs",
            "Partly automated. Sensitive privilege right assignments evidence control over utilities that bypass access controls."),
        ("A.8.19", "Technological", "Software on operational systems",
            "Manual. Software installation control is outside the scope of this assessment."),
        ("A.8.20", "Technological", "Network security",
            "Automated. LDAP signing, channel binding, SMB signing and legacy protocol findings evidence protection of directory network traffic."),
        ("A.8.21", "Technological", "Security of network services",
            "Automated. Protocol hardening and trust configuration findings evidence the security of directory network services."),
        ("A.8.22", "Technological", "Segregation of networks",
            "Manual. Network segmentation is outside the scope of this assessment."),
        ("A.8.23", "Technological", "Web filtering",
            "Manual. Web filtering is outside the scope of this assessment."),
        ("A.8.24", "Technological", "Use of cryptography",
            "Automated. Certificate template, federation certificate, reversible password storage and key rotation findings evidence cryptographic practice."),
        ("A.8.25", "Technological", "Secure development lifecycle",
            "Manual. Development practices are outside the scope of this assessment."),
        ("A.8.26", "Technological", "Application security requirements",
            "Partly automated. Application registration audience, ownership and permission findings evidence control over tenant applications."),
        ("A.8.27", "Technological", "Secure system architecture",
            "Manual. Confirm that secure architecture principles are applied."),
        ("A.8.28", "Technological", "Secure coding",
            "Manual. Coding practices are outside the scope of this assessment."),
        ("A.8.29", "Technological", "Security testing",
            "Manual. Confirm that security testing is performed during development and acceptance."),
        ("A.8.30", "Technological", "Outsourced development",
            "Manual. Confirm that outsourced development is directed and monitored."),
        ("A.8.31", "Technological", "Separation of environments",
            "Manual. Environment separation is outside the scope of this assessment."),
        ("A.8.32", "Technological", "Change management",
            "Partly automated. Group Policy version consistency and report-only policy findings evidence change control over identity configuration."),
        ("A.8.33", "Technological", "Test information",
            "Manual. Confirm that test data is selected and protected appropriately."),
        ("A.8.34", "Technological", "Protection during audit testing",
            "Automated. This assessment is read-only: it issues no directory or tenant write request, so audit activity does not alter the systems under review."),
    ];

    /// <summary>Every control in the catalogue, in identifier order.</summary>
    public static IReadOnlyList<ControlDefinition> All { get; } = Definitions
        .Select(definition => new ControlDefinition
        {
            Framework = Framework,
            ControlId = definition.Id,
            ToolAuthoredLabel = definition.Label,
            ToolAuthoredGuidance = definition.Guidance,
            Theme = definition.Theme,
        })
        .ToList();

    /// <summary>Controls indexed by identifier.</summary>
    public static IReadOnlyDictionary<string, ControlDefinition> ById { get; } =
        All.ToDictionary(control => control.ControlId, control => control, StringComparer.OrdinalIgnoreCase);

    /// <summary>Returns the controls belonging to one theme.</summary>
    public static IReadOnlyList<ControlDefinition> ByTheme(string theme) =>
        All.Where(control => string.Equals(control.Theme, theme, StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>The themes present in the catalogue, in presentation order.</summary>
    public static IReadOnlyList<string> Themes { get; } =
        ["Organisational", "People", "Physical", "Technological"];
}
