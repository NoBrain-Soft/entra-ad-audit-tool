namespace Ipa.Contracts.Evidence;

/// <summary>
/// A certificate template as published in the configuration partition. Only LDAP-visible
/// attributes are collected; the product never probes CA web endpoints or server registries.
/// </summary>
public sealed record CertificateTemplate
{
    public required string Name { get; init; }
    public required string DisplayName { get; init; }
    public required string DistinguishedName { get; init; }
    public int SchemaVersion { get; init; }

    /// <summary>Raw <c>msPKI-Certificate-Name-Flag</c> value.</summary>
    public int CertificateNameFlags { get; init; }

    /// <summary>Raw <c>msPKI-Enrollment-Flag</c> value.</summary>
    public int EnrollmentFlags { get; init; }

    /// <summary>Number of authorised signatures required for enrolment.</summary>
    public int RaSignaturesRequired { get; init; }

    /// <summary>Extended key usages published on the template.</summary>
    public IReadOnlyList<string> ExtendedKeyUsages { get; init; } = [];

    /// <summary>True when the requester may supply the subject, including subject alternative names.</summary>
    public bool EnrolleeSuppliesSubject { get; init; }

    /// <summary>True when issued certificates do not require manager approval.</summary>
    public bool NoManagerApproval { get; init; }

    /// <summary>True when the template permits client authentication or another logon-capable usage.</summary>
    public bool AllowsAuthentication { get; init; }

    public string? OwnerSid { get; init; }

    /// <summary>Principals holding enrol or auto-enrol rights on the template.</summary>
    public IReadOnlyList<AdAccessControlEntry> Permissions { get; init; } = [];
}

/// <summary>An enrolment service (certification authority) object published in the forest.</summary>
public sealed record CertificateEnrollmentService
{
    public required string Name { get; init; }
    public required string DnsHostName { get; init; }
    public required string DistinguishedName { get; init; }
    public IReadOnlyList<string> PublishedTemplates { get; init; } = [];
    public string? OwnerSid { get; init; }
    public IReadOnlyList<AdAccessControlEntry> Permissions { get; init; } = [];
}

/// <summary>The LDAP-visible slice of Active Directory Certificate Services.</summary>
public sealed record AdCertificateServicesEvidence
{
    public IReadOnlyList<CertificateTemplate> Templates { get; init; } = [];
    public IReadOnlyList<CertificateEnrollmentService> EnrollmentServices { get; init; } = [];

    /// <summary>
    /// Checks that would need CA web-endpoint probing or server registry inspection. They are
    /// reported as unavailable rather than passed, and are listed here for the report.
    /// </summary>
    public IReadOnlyList<string> OutOfScopeChecks { get; init; } =
    [
        "Web enrolment endpoint authentication (NTLM relay exposure)",
        "CA server registry flags such as EDITF_ATTRIBUTESUBJECTALTNAME2",
        "Certificate authority audit and role separation configuration",
    ];
}
