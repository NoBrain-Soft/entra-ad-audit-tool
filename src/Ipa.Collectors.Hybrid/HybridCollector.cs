using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.Hybrid;

/// <summary>
/// Derives the hybrid view from evidence the Active Directory and Entra collectors already
/// produced. The collector performs no network access of its own: correlation is a pure function of
/// the two normalised directories, so it produces identical results wherever it runs.
/// </summary>
public sealed class HybridCollector : ICollector
{
    private readonly HybridCorrelator _correlator = new();

    /// <inheritdoc />
    public string CollectorId => "hybrid.correlation";

    /// <inheritdoc />
    public string DisplayName => "Hybrid identity correlation";

    /// <inheritdoc />
    public AssessmentSource Source => AssessmentSource.Hybrid;

    /// <inheritdoc />
    public IReadOnlyList<CollectorPrerequisite> Prerequisites { get; } =
    [
        new("Both sources", "An Active Directory forest and an Entra tenant collected in this assessment."),
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> RequiredPermissions { get; } = [];

    /// <inheritdoc />
    public IReadOnlyList<string> ProducedEvidenceKeys { get; } =
    [
        EvidenceKeys.HybridMatches, EvidenceKeys.HybridSync, EvidenceKeys.HybridFederation,
    ];

    /// <inheritdoc />
    public IReadOnlyList<CheckGroup> SupportedGroups { get; } =
    [
        CheckGroup.HybridIdentityCorrelation, CheckGroup.HybridPrivilegeExposure, CheckGroup.HybridSynchronisation,
    ];

    /// <inheritdoc />
    public bool AppliesTo(CollectionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.SelectedGroups.Any(SupportedGroups.Contains)
               && context.PreviousEvidence?.ActiveDirectory is not null
               && context.PreviousEvidence?.Entra is not null;
    }

    /// <inheritdoc />
    public Task<CollectionResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var builder = new CollectorResultBuilder(CollectorId, Source, context);

        var activeDirectory = context.PreviousEvidence?.ActiveDirectory;
        var entra = context.PreviousEvidence?.Entra;

        if (activeDirectory is null || entra is null)
        {
            var missing = activeDirectory is null ? "Active Directory" : "Microsoft Entra";

            foreach (var key in ProducedEvidenceKeys)
            {
                builder.MarkUnavailable(
                    key,
                    EvidenceAvailability.NotSelected,
                    $"{missing} evidence is not present in this assessment, so hybrid correlation " +
                    "was not performed and the hybrid score is disabled.");
            }

            builder.Log(
                DiagnosticSeverity.Information,
                $"Hybrid correlation was skipped because {missing} was not collected.",
                "SingleSourceAssessment");

            return Task.FromResult(builder.Build(CollectionOutcome.Skipped, new EvidenceFragment()));
        }

        try
        {
            builder.Progress("Hybrid", "Correlating on-premises and cloud identities");
            var correlation = _correlator.Correlate(activeDirectory, entra);

            builder.Progress("Hybrid", "Identifying synchronisation accounts and federation");
            var syncAccounts = FindSyncServiceAccounts(activeDirectory, entra);
            var federation = BuildFederation(entra);
            var privilegedSynchronised = FindPrivilegedSynchronised(activeDirectory, entra, correlation);

            var evidence = new HybridEvidence
            {
                Matches = correlation.Matches,
                ReviewItems = correlation.ReviewItems,
                SyncServiceAccounts = syncAccounts,
                Federation = federation,
                PrivilegedSynchronisedAccountSids = privilegedSynchronised,
                OrphanedCloudObjectIds = correlation.OrphanedCloudObjectIds,
                DuplicateAnchors = correlation.DuplicateAnchors,
                LastDirectorySyncTime = entra.Tenant.LastDirectorySyncTime,
                ReferenceTime = context.ReferenceTime,
            };

            builder.MarkCollected(EvidenceKeys.HybridMatches);
            builder.MarkCollected(EvidenceKeys.HybridSync);
            builder.MarkCollected(EvidenceKeys.HybridFederation);

            builder.AddRecord(
                "hybrid.correlation",
                EvidenceKind.Correlation,
                $"{correlation.Matches.Count} identity match(es), {correlation.ReviewItems.Count} " +
                $"review item(s), {correlation.DuplicateAnchors.Count} duplicate anchor(s)");

            return Task.FromResult(builder.Build(
                CollectionOutcome.Succeeded,
                new EvidenceFragment { Hybrid = evidence }));
        }
        catch (OperationCanceledException)
        {
            builder.Log(DiagnosticSeverity.Information, "Correlation was cancelled by the operator.", "Cancelled");
            return Task.FromResult(builder.Build(CollectionOutcome.Cancelled, new EvidenceFragment()));
        }
        catch (Exception ex)
        {
            builder.Log(DiagnosticSeverity.Error, $"Hybrid correlation failed: {ex.Message}", "CorrelationFailed", ex);

            foreach (var key in ProducedEvidenceKeys)
            {
                builder.MarkUnavailable(key, EvidenceAvailability.Error, "Hybrid correlation failed.");
            }

            return Task.FromResult(builder.Build(CollectionOutcome.Failed, new EvidenceFragment()));
        }
    }

    /// <summary>
    /// Identifies directory synchronisation service accounts. The cloud side is recognised by the
    /// account name pattern the synchronisation service creates and by the directory
    /// synchronisation role; the on-premises side by the accounts that hold replication rights.
    /// </summary>
    public static IReadOnlyList<SyncServiceAccount> FindSyncServiceAccounts(
        ActiveDirectoryEvidence activeDirectory,
        EntraEvidence entra)
    {
        ArgumentNullException.ThrowIfNull(activeDirectory);
        ArgumentNullException.ThrowIfNull(entra);

        var accounts = new List<SyncServiceAccount>();

        var excludedPrincipals = entra.ConditionalAccessPolicies
            .Where(policy => policy.IsEnabled)
            .SelectMany(policy => policy.ExcludeUsers)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var user in entra.Users)
        {
            var isSyncAccount = user.UserPrincipalName.StartsWith("Sync_", StringComparison.OrdinalIgnoreCase)
                                || user.UserPrincipalName.StartsWith("ADToAADSyncServiceAccount", StringComparison.OrdinalIgnoreCase)
                                || entra.RoleAssignments.Any(assignment =>
                                    string.Equals(assignment.PrincipalId, user.ObjectId, StringComparison.OrdinalIgnoreCase)
                                    && assignment.RoleName.Contains("Directory Synchronization", StringComparison.OrdinalIgnoreCase));

            if (!isSyncAccount)
            {
                continue;
            }

            accounts.Add(new SyncServiceAccount
            {
                Identifier = user.ObjectId,
                Source = AssessmentSource.Entra,
                DisplayName = user.UserPrincipalName,
                Privileges = entra.RoleAssignments
                    .Where(assignment => string.Equals(assignment.PrincipalId, user.ObjectId, StringComparison.OrdinalIgnoreCase))
                    .Select(assignment => assignment.RoleName)
                    .ToList(),
                ExcludedFromConditionalAccess = excludedPrincipals.Contains(user.ObjectId),
                MfaRegistered = user.Registration?.IsMfaRegistered ?? false,
                LastSignIn = user.LastSignInDateTime,
            });
        }

        // On premises, the synchronisation account is the one granted directory replication rights.
        var replicationTrustees = activeDirectory.AccessControlEntries
            .Where(ace => !ace.IsDeny)
            .Where(ace => ExtendedRights.IsReplicationRight(ace.ObjectTypeGuid))
            .Select(ace => ace.TrusteeSid)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var sid in replicationTrustees)
        {
            var principal = activeDirectory.Users.FirstOrDefault(user =>
                string.Equals(user.Sid, sid, StringComparison.OrdinalIgnoreCase));

            if (principal is null)
            {
                continue;
            }

            accounts.Add(new SyncServiceAccount
            {
                Identifier = principal.Sid,
                Source = AssessmentSource.ActiveDirectory,
                DisplayName = principal.SamAccountName,
                Privileges = ["Directory replication rights"],
                LastSignIn = principal.LastLogonTimestamp,
            });
        }

        return accounts;
    }

    /// <summary>Builds the federation view from the tenant's verified domains.</summary>
    public static IReadOnlyList<FederationConfiguration> BuildFederation(EntraEvidence entra)
    {
        ArgumentNullException.ThrowIfNull(entra);

        return entra.Tenant.Domains
            .Where(domain => domain.IsVerified)
            .Select(domain => new FederationConfiguration
            {
                DomainName = domain.Name,
                AuthenticationType = domain.AuthenticationType,
                IssuerUri = domain.FederationIssuerUri,
                SigningCertificateExpiry = ParseExpiry(domain.FederationSigningCertificateExpiry),
                SupportsMfa = domain.FederatedSignOnSupportsMfa,
            })
            .ToList();
    }

    /// <summary>
    /// Returns the on-premises identifiers of synchronised accounts that hold a privileged cloud
    /// role, which is the exposure hybrid assessment exists to find.
    /// </summary>
    public static IReadOnlyList<string> FindPrivilegedSynchronised(
        ActiveDirectoryEvidence activeDirectory,
        EntraEvidence entra,
        CorrelationResult correlation)
    {
        ArgumentNullException.ThrowIfNull(correlation);
        ArgumentNullException.ThrowIfNull(entra);

        var privilegedPrincipals = entra.RoleAssignments
            .Where(assignment => IsPrivilegedRole(assignment.RoleName))
            .Select(assignment => assignment.PrincipalId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return correlation.Matches
            .Where(match => privilegedPrincipals.Contains(match.EntraObjectId))
            .Select(match => match.AdSid)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// True when a role name denotes tenant-wide administrative control. The check is by name so
    /// that a tenant using custom role names still resolves the well-known administrative roles.
    /// </summary>
    private static bool IsPrivilegedRole(string roleName)
    {
        string[] privileged =
        [
            "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
            "Application Administrator", "Cloud Application Administrator", "User Administrator",
            "Authentication Administrator", "Conditional Access Administrator", "Security Administrator",
            "Exchange Administrator", "SharePoint Administrator", "Intune Administrator",
            "Hybrid Identity Administrator", "Domain Name Administrator",
        ];

        return privileged.Any(name => roleName.Contains(name, StringComparison.OrdinalIgnoreCase));
    }

    private static DateTimeOffset? ParseExpiry(string? value) =>
        DateTimeOffset.TryParse(
            value,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : null;
}
