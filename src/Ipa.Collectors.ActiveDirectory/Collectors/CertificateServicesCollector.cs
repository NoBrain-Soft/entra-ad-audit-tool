using System.DirectoryServices.Protocols;
using Ipa.Collectors.ActiveDirectory.Connection;
using Ipa.Collectors.ActiveDirectory.Discovery;
using Ipa.Collectors.ActiveDirectory.Normalisation;
using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects the LDAP-visible slice of Active Directory Certificate Services: published templates,
/// enrolment services, and the ownership and permissions on both.
/// </summary>
/// <remarks>
/// Checks that would need the certification authority's web endpoints or host registry are out of
/// scope for a read-only, directory-only assessment. They are recorded as unavailable so that a
/// report never implies they were verified.
/// </remarks>
public sealed class CertificateServicesCollector : ICollector
{
    private readonly DirectorySession _session;

    public CertificateServicesCollector(DirectorySession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        _session = session;
    }

    /// <inheritdoc />
    public string CollectorId => "ad.certificateServices";

    /// <inheritdoc />
    public string DisplayName => "Certificate templates and enrolment services";

    /// <inheritdoc />
    public AssessmentSource Source => AssessmentSource.ActiveDirectory;

    /// <inheritdoc />
    public IReadOnlyList<CollectorPrerequisite> Prerequisites { get; } =
    [
        new("Configuration partition access", "Read access to the public key services container."),
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> RequiredPermissions { get; } =
    [
        "Read access to CN=Public Key Services in the configuration partition",
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> ProducedEvidenceKeys { get; } = [EvidenceKeys.AdCertificateServices];

    /// <inheritdoc />
    public IReadOnlyList<CheckGroup> SupportedGroups { get; } = [CheckGroup.AdCertificateServices];

    /// <inheritdoc />
    public bool AppliesTo(CollectionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.SelectedGroups.Contains(CheckGroup.AdCertificateServices);
    }

    /// <inheritdoc />
    public Task<CollectionResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var builder = new CollectorResultBuilder(CollectorId, Source, context);

        try
        {
            var servicesContainer = $"CN=Public Key Services,CN=Services,{_session.ConfigurationNamingContext}";

            builder.Progress("Certificate services", "Reading published certificate templates");
            var templates = CollectTemplates(servicesContainer, builder, cancellationToken);

            builder.Progress("Certificate services", "Reading enrolment services");
            var services = CollectEnrollmentServices(servicesContainer, builder, cancellationToken);

            var evidence = new AdCertificateServicesEvidence
            {
                Templates = templates,
                EnrollmentServices = services,
            };

            builder.MarkCollected(EvidenceKeys.AdCertificateServices);
            builder.AddRecord(
                "ad.certificateServices",
                EvidenceKind.DirectoryQuery,
                $"{templates.Count} certificate template(s) and {services.Count} enrolment service(s). " +
                "Checks needing the certification authority host are outside this assessment's scope.");

            var existing = context.PreviousEvidence?.ActiveDirectory;

            var fragment = existing is null
                ? new EvidenceFragment()
                : new EvidenceFragment { ActiveDirectory = existing with { CertificateServices = evidence } };

            return Task.FromResult(builder.Build(CollectionOutcome.Succeeded, fragment));
        }
        catch (OperationCanceledException)
        {
            builder.Log(DiagnosticSeverity.Information, "Collection was cancelled by the operator.", "Cancelled");
            return Task.FromResult(builder.Build(CollectionOutcome.Cancelled, new EvidenceFragment()));
        }
        catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.NoSuchObject)
        {
            builder.Log(
                DiagnosticSeverity.Information,
                "The public key services container is absent, so the forest has no certificate services.",
                "NoCertificateServices");

            builder.MarkCollected(EvidenceKeys.AdCertificateServices);

            var existing = context.PreviousEvidence?.ActiveDirectory;

            var fragment = existing is null
                ? new EvidenceFragment()
                : new EvidenceFragment
                {
                    ActiveDirectory = existing with { CertificateServices = new AdCertificateServicesEvidence() },
                };

            return Task.FromResult(builder.Build(CollectionOutcome.Succeeded, fragment));
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Error,
                $"Certificate services collection failed: {LdapDirectoryReader.DescribeFailure(ex)}",
                "CollectionFailed",
                ex);

            builder.MarkUnavailable(
                EvidenceKeys.AdCertificateServices,
                EvidenceAvailability.Error,
                "Certificate services could not be read.");

            return Task.FromResult(builder.Build(CollectionOutcome.Failed, new EvidenceFragment()));
        }
    }

    private List<CertificateTemplate> CollectTemplates(
        string servicesContainer,
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        // msPKI-Certificate-Name-Flag: bit 0 lets the requester supply the subject.
        const int enrolleeSuppliesSubject = 0x00000001;

        // msPKI-Enrollment-Flag: bit 1 requires certificate manager approval.
        const int pendAllRequests = 0x00000002;

        var entries = _session.Reader.Search(
            $"CN=Certificate Templates,{servicesContainer}",
            "(objectClass=pKICertificateTemplate)",
            [
                "cn", "displayName", "distinguishedName", "msPKI-Template-Schema-Version",
                "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
                "pKIExtendedKeyUsage", "nTSecurityDescriptor",
            ],
            cancellationToken,
            SearchScope.OneLevel,
            includeSecurityDescriptor: true);

        var templates = new List<CertificateTemplate>(entries.Count);

        foreach (var entry in entries)
        {
            var nameFlags = AttributeReader.GetInt32(entry, "msPKI-Certificate-Name-Flag") ?? 0;
            var enrollmentFlags = AttributeReader.GetInt32(entry, "msPKI-Enrollment-Flag") ?? 0;
            var usages = AttributeReader.GetStrings(entry, "pKIExtendedKeyUsage");
            var name = AttributeReader.GetString(entry, "cn") ?? "unknown";

            templates.Add(new CertificateTemplate
            {
                Name = name,
                DisplayName = AttributeReader.GetString(entry, "displayName") ?? name,
                DistinguishedName = AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName,
                SchemaVersion = AttributeReader.GetInt32(entry, "msPKI-Template-Schema-Version") ?? 1,
                CertificateNameFlags = nameFlags,
                EnrollmentFlags = enrollmentFlags,
                RaSignaturesRequired = AttributeReader.GetInt32(entry, "msPKI-RA-Signature") ?? 0,
                ExtendedKeyUsages = usages,
                EnrolleeSuppliesSubject = (nameFlags & enrolleeSuppliesSubject) != 0,
                NoManagerApproval = (enrollmentFlags & pendAllRequests) == 0,
                AllowsAuthentication = AllowsAuthentication(usages),
                OwnerSid = DirectoryObjectNormaliser.ReadOwnerSid(entry),
                Permissions = DirectoryObjectNormaliser.ToAccessControlEntries(entry, "pKICertificateTemplate"),
            });
        }

        builder.Log(
            DiagnosticSeverity.Information,
            $"Read {templates.Count} published certificate template(s).",
            "CertificateTemplates");

        return templates;
    }

    private List<CertificateEnrollmentService> CollectEnrollmentServices(
        string servicesContainer,
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        var entries = _session.Reader.Search(
            $"CN=Enrollment Services,{servicesContainer}",
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName", "distinguishedName", "certificateTemplates", "nTSecurityDescriptor"],
            cancellationToken,
            SearchScope.OneLevel,
            includeSecurityDescriptor: true);

        var services = entries
            .Select(entry => new CertificateEnrollmentService
            {
                Name = AttributeReader.GetString(entry, "cn") ?? "unknown",
                DnsHostName = AttributeReader.GetString(entry, "dNSHostName") ?? string.Empty,
                DistinguishedName = AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName,
                PublishedTemplates = AttributeReader.GetStrings(entry, "certificateTemplates"),
                OwnerSid = DirectoryObjectNormaliser.ReadOwnerSid(entry),
                Permissions = DirectoryObjectNormaliser.ToAccessControlEntries(entry, "pKIEnrollmentService"),
            })
            .ToList();

        builder.Log(
            DiagnosticSeverity.Information,
            $"Read {services.Count} enrolment service(s).",
            "EnrollmentServices");

        return services;
    }

    /// <summary>
    /// True when a template's extended key usages permit authentication. An empty list means the
    /// certificate is unrestricted, which also permits authentication.
    /// </summary>
    public static bool AllowsAuthentication(IReadOnlyCollection<string> extendedKeyUsages)
    {
        ArgumentNullException.ThrowIfNull(extendedKeyUsages);

        if (extendedKeyUsages.Count == 0)
        {
            return true;
        }

        string[] authenticationOids =
        [
            "1.3.6.1.5.5.7.3.2",       // Client Authentication
            "1.3.6.1.5.2.3.4",         // PKINIT Client Authentication
            "1.3.6.1.4.1.311.20.2.2",  // Smart Card Logon
            "2.5.29.37.0",             // Any Purpose
        ];

        return extendedKeyUsages.Any(usage => authenticationOids.Contains(usage));
    }
}
