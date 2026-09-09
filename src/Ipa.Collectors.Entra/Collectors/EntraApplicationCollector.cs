using System.Text.Json;
using Ipa.Collectors.Entra.Graph;
using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Security;

namespace Ipa.Collectors.Entra.Collectors;

/// <summary>
/// Collects application registrations, service principals and the permissions granted to them.
/// Credential metadata is collected; credential values are never requested and Graph never returns
/// them.
/// </summary>
public sealed class EntraApplicationCollector : ICollector
{
    private readonly GraphReadClient _graph;

    /// <summary>Application identifier of the Microsoft Graph service principal.</summary>
    private const string GraphAppId = "00000003-0000-0000-c000-000000000000";

    public EntraApplicationCollector(GraphReadClient graph)
    {
        ArgumentNullException.ThrowIfNull(graph);
        _graph = graph;
    }

    /// <inheritdoc />
    public string CollectorId => "entra.applications";

    /// <inheritdoc />
    public string DisplayName => "Application registrations, service principals and consent";

    /// <inheritdoc />
    public AssessmentSource Source => AssessmentSource.Entra;

    /// <inheritdoc />
    public IReadOnlyList<CollectorPrerequisite> Prerequisites { get; } =
    [
        new("Application read consent", "Consent for Application.Read.All in the customer's tenant."),
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> RequiredPermissions { get; } = ["Application.Read.All", "Directory.Read.All"];

    /// <inheritdoc />
    public IReadOnlyList<string> ProducedEvidenceKeys { get; } =
    [
        EvidenceKeys.EntraApplications, EvidenceKeys.EntraServicePrincipals,
    ];

    /// <inheritdoc />
    public IReadOnlyList<CheckGroup> SupportedGroups { get; } =
    [
        CheckGroup.EntraApplications, CheckGroup.EntraPrivilegedAccess,
    ];

    /// <inheritdoc />
    public bool AppliesTo(CollectionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.SelectedGroups.Any(SupportedGroups.Contains);
    }

    /// <inheritdoc />
    public async Task<CollectionResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var builder = new CollectorResultBuilder(CollectorId, Source, context);

        try
        {
            builder.Progress("Applications", "Reading application registrations");
            var applications = await CollectApplicationsAsync(builder, cancellationToken).ConfigureAwait(false);

            builder.Progress("Service principals", "Reading service principals and granted permissions");
            var principals = await CollectServicePrincipalsAsync(builder, cancellationToken).ConfigureAwait(false);

            var existing = context.PreviousEvidence?.Entra;

            var fragment = existing is null
                ? new EvidenceFragment()
                : new EvidenceFragment
                {
                    Entra = existing with
                    {
                        Applications = applications,
                        ServicePrincipals = principals,
                    },
                };

            return builder.Build(builder.DetermineOutcome(), fragment);
        }
        catch (OperationCanceledException)
        {
            builder.Log(DiagnosticSeverity.Information, "Collection was cancelled by the operator.", "Cancelled");
            return builder.Build(CollectionOutcome.Cancelled, new EvidenceFragment());
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Error,
                $"Application collection failed: {Redaction.Scrub(ex.Message)}",
                "CollectionFailed",
                ex);

            foreach (var key in ProducedEvidenceKeys)
            {
                builder.MarkUnavailable(key, EvidenceAvailability.Error, "Application collection failed.");
            }

            return builder.Build(CollectionOutcome.Failed, new EvidenceFragment());
        }
    }

    private async Task<List<EntraApplication>> CollectApplicationsAsync(
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        const string path =
            "applications?$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials," +
            "keyCredentials,requiredResourceAccess,web,publicClient&$top=999";

        var (items, failure) = await _graph.TryEnumerateAsync(path, cancellationToken).ConfigureAwait(false);

        if (failure is not null && items.Count == 0)
        {
            builder.MarkUnavailable(
                EvidenceKeys.EntraApplications,
                EntraDirectoryCollector.Classify(failure),
                failure.Message);

            return [];
        }

        var applications = new List<EntraApplication>(items.Count);

        foreach (var item in items)
        {
            var objectId = GraphJson.String(item, "id");
            if (objectId is null)
            {
                continue;
            }

            var application = new EntraApplication
            {
                ObjectId = objectId,
                AppId = GraphJson.String(item, "appId") ?? string.Empty,
                DisplayName = GraphJson.String(item, "displayName") ?? objectId,
                SignInAudience = GraphJson.String(item, "signInAudience"),
                CreatedDateTime = GraphJson.Timestamp(item, "createdDateTime"),
                Credentials = ReadCredentials(item),
                RequestedPermissions = ReadRequestedPermissions(item),
                RedirectUris = ReadRedirectUris(item),
            };

            applications.Add(application);
        }

        // Owners are read separately because the collection is not expandable in bulk.
        for (var index = 0; index < applications.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var (owners, ownerFailure) = await _graph
                .TryEnumerateAsync($"applications/{applications[index].ObjectId}/owners?$select=id", cancellationToken)
                .ConfigureAwait(false);

            if (ownerFailure is not null)
            {
                continue;
            }

            applications[index] = applications[index] with
            {
                OwnerObjectIds = owners
                    .Select(owner => GraphJson.String(owner, "id"))
                    .Where(id => id is not null)
                    .Select(id => id!)
                    .ToList(),
            };
        }

        builder.MarkCollected(EvidenceKeys.EntraApplications);
        builder.AddRecord(
            "entra.applications",
            EvidenceKind.DirectoryQuery,
            $"{applications.Count} application registration(s) with " +
            $"{applications.Sum(application => application.Credentials.Count)} credential(s)");

        return applications;
    }

    private async Task<List<EntraServicePrincipal>> CollectServicePrincipalsAsync(
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        const string path =
            "servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled," +
            "appRoleAssignmentRequired,passwordCredentials,keyCredentials,tags,appOwnerOrganizationId&$top=999";

        var (items, failure) = await _graph.TryEnumerateAsync(path, cancellationToken).ConfigureAwait(false);

        if (failure is not null && items.Count == 0)
        {
            builder.MarkUnavailable(
                EvidenceKeys.EntraServicePrincipals,
                EntraDirectoryCollector.Classify(failure),
                failure.Message);

            return [];
        }

        // Microsoft's own first-party service principals are published by a well-known tenant.
        const string microsoftTenantId = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";

        var principals = new List<EntraServicePrincipal>(items.Count);
        var appIdToDisplayName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in items)
        {
            var objectId = GraphJson.String(item, "id");
            if (objectId is null)
            {
                continue;
            }

            var appId = GraphJson.String(item, "appId") ?? string.Empty;
            var displayName = GraphJson.String(item, "displayName") ?? objectId;

            if (appId.Length > 0)
            {
                appIdToDisplayName[appId] = displayName;
            }

            var ownerTenant = GraphJson.String(item, "appOwnerOrganizationId");

            principals.Add(new EntraServicePrincipal
            {
                ObjectId = objectId,
                AppId = appId,
                DisplayName = displayName,
                ServicePrincipalType = GraphJson.String(item, "servicePrincipalType"),
                AccountEnabled = GraphJson.Boolean(item, "accountEnabled") ?? true,
                AppRoleAssignmentRequired = GraphJson.Boolean(item, "appRoleAssignmentRequired") ?? false,
                Credentials = ReadCredentials(item),
                Tags = GraphJson.Strings(item, "tags"),
                IsMicrosoftPublished = string.Equals(ownerTenant, microsoftTenantId, StringComparison.OrdinalIgnoreCase),
            });
        }

        var permissionNames = await ReadGraphPermissionNamesAsync(cancellationToken).ConfigureAwait(false);

        // Only tenant-published principals are inspected for grants: enumerating grants for every
        // Microsoft principal would multiply the request count without changing any finding.
        var inspect = principals.Where(principal => !principal.IsMicrosoftPublished).ToList();
        var index2 = 0;

        foreach (var principal in inspect)
        {
            cancellationToken.ThrowIfCancellationRequested();
            builder.Progress("Service principals", "Reading granted permissions", ++index2, inspect.Count);

            var listIndex = principals.IndexOf(principal);

            var (appRoles, appRoleFailure) = await _graph
                .TryEnumerateAsync($"servicePrincipals/{principal.ObjectId}/appRoleAssignments", cancellationToken)
                .ConfigureAwait(false);

            var (delegated, delegatedFailure) = await _graph
                .TryEnumerateAsync(
                    $"oauth2PermissionGrants?$filter=clientId eq '{principal.ObjectId}'",
                    cancellationToken)
                .ConfigureAwait(false);

            if (appRoleFailure is not null && delegatedFailure is not null)
            {
                continue;
            }

            principals[listIndex] = principal with
            {
                AppRoleGrants = appRoles
                    .Select(grant => new GrantedAppRole
                    {
                        ResourceAppId = GraphJson.String(grant, "resourceId") ?? string.Empty,
                        ResourceDisplayName = GraphJson.String(grant, "resourceDisplayName") ?? "unknown",
                        PermissionValue = ResolvePermission(grant, permissionNames),
                        CreatedDateTime = GraphJson.Timestamp(grant, "createdDateTime"),
                    })
                    .ToList(),

                DelegatedGrants = delegated
                    .Select(grant => new DelegatedGrant
                    {
                        ResourceAppId = GraphJson.String(grant, "resourceId") ?? string.Empty,
                        ResourceDisplayName = appIdToDisplayName.GetValueOrDefault(
                            GraphJson.String(grant, "resourceId") ?? string.Empty,
                            "unknown"),
                        Scopes = GraphJson.String(grant, "scope")?.Trim() ?? string.Empty,
                        ConsentType = GraphJson.String(grant, "consentType") ?? "Principal",
                        PrincipalId = GraphJson.String(grant, "principalId"),
                    })
                    .ToList(),
            };
        }

        builder.MarkCollected(EvidenceKeys.EntraServicePrincipals);
        builder.AddRecord(
            "entra.servicePrincipals",
            EvidenceKind.DirectoryQuery,
            $"{principals.Count} service principal(s), of which {inspect.Count} are published by this tenant");

        return principals;
    }

    /// <summary>
    /// Reads the identifier-to-name map of Microsoft Graph application permissions, so that a
    /// grant recorded by identifier can be reported by the name an operator recognises.
    /// </summary>
    private async Task<Dictionary<string, string>> ReadGraphPermissionNamesAsync(CancellationToken cancellationToken)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var (document, failure) = await _graph
            .TryGetAsync($"servicePrincipals(appId='{GraphAppId}')?$select=appRoles", cancellationToken)
            .ConfigureAwait(false);

        if (failure is not null || document is null)
        {
            return names;
        }

        foreach (var role in GraphJson.Objects(document.Value, "appRoles"))
        {
            var id = GraphJson.String(role, "id");
            var value = GraphJson.String(role, "value");

            if (id is not null && value is not null)
            {
                names[id] = value;
            }
        }

        return names;
    }

    private static string ResolvePermission(JsonElement grant, IReadOnlyDictionary<string, string> permissionNames)
    {
        var appRoleId = GraphJson.String(grant, "appRoleId");

        return appRoleId is not null && permissionNames.TryGetValue(appRoleId, out var name)
            ? name
            : appRoleId ?? "unknown";
    }

    private static IReadOnlyList<DirectoryCredential> ReadCredentials(JsonElement item)
    {
        var credentials = new List<DirectoryCredential>();

        foreach (var password in GraphJson.Objects(item, "passwordCredentials"))
        {
            credentials.Add(new DirectoryCredential
            {
                KeyId = GraphJson.String(password, "keyId") ?? Guid.NewGuid().ToString("n"),
                CredentialType = "password",
                DisplayName = GraphJson.String(password, "displayName"),
                StartDateTime = GraphJson.Timestamp(password, "startDateTime"),
                EndDateTime = GraphJson.Timestamp(password, "endDateTime"),
            });
        }

        foreach (var key in GraphJson.Objects(item, "keyCredentials"))
        {
            credentials.Add(new DirectoryCredential
            {
                KeyId = GraphJson.String(key, "keyId") ?? Guid.NewGuid().ToString("n"),
                CredentialType = "certificate",
                DisplayName = GraphJson.String(key, "displayName"),
                StartDateTime = GraphJson.Timestamp(key, "startDateTime"),
                EndDateTime = GraphJson.Timestamp(key, "endDateTime"),
            });
        }

        return credentials;
    }

    private static IReadOnlyList<RequestedPermission> ReadRequestedPermissions(JsonElement item)
    {
        var permissions = new List<RequestedPermission>();

        foreach (var resource in GraphJson.Objects(item, "requiredResourceAccess"))
        {
            var resourceAppId = GraphJson.String(resource, "resourceAppId") ?? string.Empty;

            foreach (var access in GraphJson.Objects(resource, "resourceAccess"))
            {
                permissions.Add(new RequestedPermission
                {
                    ResourceAppId = resourceAppId,
                    PermissionId = GraphJson.String(access, "id") ?? string.Empty,
                    PermissionKind = GraphJson.String(access, "type") ?? "Scope",
                });
            }
        }

        return permissions;
    }

    private static IReadOnlyList<string> ReadRedirectUris(JsonElement item)
    {
        var uris = new List<string>();

        if (GraphJson.Object(item, "web") is { } web)
        {
            uris.AddRange(GraphJson.Strings(web, "redirectUris"));
        }

        if (GraphJson.Object(item, "publicClient") is { } publicClient)
        {
            uris.AddRange(GraphJson.Strings(publicClient, "redirectUris"));
        }

        return uris;
    }
}
