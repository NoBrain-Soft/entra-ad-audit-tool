using System.Text.Json;
using Ipa.Collectors.Entra.Graph;
using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Security;

namespace Ipa.Collectors.Entra.Collectors;

/// <summary>
/// Collects the tenant, its users, groups, devices and directory role assignments from Microsoft
/// Graph. Every request is a read: the client type exposes no write method.
/// </summary>
public sealed class EntraDirectoryCollector : ICollector
{
    private readonly GraphReadClient _graph;

    public EntraDirectoryCollector(GraphReadClient graph)
    {
        ArgumentNullException.ThrowIfNull(graph);
        _graph = graph;
    }

    /// <inheritdoc />
    public string CollectorId => "entra.directory";

    /// <inheritdoc />
    public string DisplayName => "Entra tenant, users, groups, devices and roles";

    /// <inheritdoc />
    public AssessmentSource Source => AssessmentSource.Entra;

    /// <inheritdoc />
    public IReadOnlyList<CollectorPrerequisite> Prerequisites { get; } =
    [
        new("Signed-in session", "An interactive sign-in to the customer's tenant."),
        new("Administrator consent", "Consent for the read-only permissions the selected groups need."),
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> RequiredPermissions { get; } =
    [
        "Directory.Read.All", "RoleManagement.Read.Directory", "AuditLog.Read.All", "Reports.Read.All",
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> ProducedEvidenceKeys { get; } =
    [
        EvidenceKeys.EntraTenant, EvidenceKeys.EntraUsers, EvidenceKeys.EntraGroups,
        EvidenceKeys.EntraDevices, EvidenceKeys.EntraRoles, EvidenceKeys.EntraSignInActivity,
        EvidenceKeys.EntraRegistrationDetails, EvidenceKeys.EntraPrivilegedIdentityManagement,
    ];

    /// <inheritdoc />
    public IReadOnlyList<CheckGroup> SupportedGroups { get; } =
    [
        CheckGroup.EntraPrivilegedAccess, CheckGroup.EntraDirectoryHygiene, CheckGroup.EntraAuthentication,
        CheckGroup.HybridIdentityCorrelation, CheckGroup.HybridPrivilegeExposure, CheckGroup.HybridSynchronisation,
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
        _graph.Diagnostic += message => builder.Log(DiagnosticSeverity.Information, message, "GraphThrottling");

        try
        {
            builder.Progress("Tenant", "Reading tenant organisation and verified domains");
            var tenant = await CollectTenantAsync(builder, cancellationToken).ConfigureAwait(false);

            builder.Progress("Users", "Reading directory users");
            var users = await CollectUsersAsync(builder, cancellationToken).ConfigureAwait(false);

            builder.Progress("Registration", "Reading authentication method registration");
            users = await ApplyRegistrationAsync(users, builder, cancellationToken).ConfigureAwait(false);

            builder.Progress("Groups", "Reading directory groups");
            var groups = await CollectGroupsAsync(builder, cancellationToken).ConfigureAwait(false);

            builder.Progress("Devices", "Reading registered devices");
            var devices = await CollectDevicesAsync(builder, cancellationToken).ConfigureAwait(false);

            builder.Progress("Roles", "Reading directory role assignments");
            var roles = await CollectRoleAssignmentsAsync(groups, builder, cancellationToken).ConfigureAwait(false);

            var evidence = new EntraEvidence
            {
                Tenant = tenant,
                Users = users,
                Groups = groups,
                Devices = devices,
                RoleAssignments = roles,
                ReferenceTime = context.ReferenceTime,
            };

            return builder.Build(builder.DetermineOutcome(), new EvidenceFragment { Entra = evidence });
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
                $"Entra directory collection failed: {Redaction.Scrub(ex.Message)}",
                "CollectionFailed",
                ex);

            foreach (var key in ProducedEvidenceKeys)
            {
                builder.MarkUnavailable(key, EvidenceAvailability.Error, "Entra directory collection failed.");
            }

            return builder.Build(CollectionOutcome.Failed, new EvidenceFragment());
        }
    }

    private async Task<EntraTenant> CollectTenantAsync(CollectorResultBuilder builder, CancellationToken cancellationToken)
    {
        var (organisation, organisationFailure) = await _graph
            .TryGetAsync("organization", cancellationToken)
            .ConfigureAwait(false);

        if (organisationFailure is not null || organisation is null)
        {
            builder.MarkUnavailable(
                EvidenceKeys.EntraTenant,
                Classify(organisationFailure),
                organisationFailure?.Message ?? "The tenant organisation could not be read.");

            throw new InvalidOperationException("The tenant organisation could not be read.");
        }

        var record = organisation.Value.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().FirstOrDefault()
            : organisation.Value;

        var (domains, domainFailure) = await _graph
            .TryEnumerateAsync("domains", cancellationToken)
            .ConfigureAwait(false);

        if (domainFailure is not null)
        {
            builder.Log(
                DiagnosticSeverity.Warning,
                $"Verified domains could not be read: {domainFailure.Code}.",
                "Domains");
        }

        var plans = GraphJson.Objects(record, "assignedPlans")
            .Select(plan => GraphJson.String(plan, "service"))
            .Where(service => service is not null)
            .Select(service => service!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var tenant = new EntraTenant
        {
            TenantId = GraphJson.String(record, "id") ?? "unknown",
            DisplayName = GraphJson.String(record, "displayName") ?? "unknown",
            Domains = domains.Select(ToDomain).ToList(),
            ServicePlans = plans,
            OnPremisesSyncEnabled = GraphJson.Boolean(record, "onPremisesSyncEnabled") ?? false,
            LastDirectorySyncTime = GraphJson.Timestamp(record, "onPremisesLastSyncDateTime"),
        };

        builder.MarkCollected(EvidenceKeys.EntraTenant);
        builder.AddRecord(
            "entra.tenant",
            EvidenceKind.DirectoryQuery,
            $"Tenant {tenant.DisplayName} with {tenant.Domains.Count} domain(s); directory " +
            $"synchronisation {(tenant.OnPremisesSyncEnabled ? "enabled" : "disabled")}");

        return tenant;
    }

    private static EntraDomain ToDomain(JsonElement element) => new()
    {
        Name = GraphJson.String(element, "id") ?? "unknown",
        IsVerified = GraphJson.Boolean(element, "isVerified") ?? false,
        IsDefault = GraphJson.Boolean(element, "isDefault") ?? false,
        IsInitial = GraphJson.Boolean(element, "isInitial") ?? false,
        AuthenticationType = GraphJson.String(element, "authenticationType") ?? "Managed",
    };

    private async Task<List<EntraUser>> CollectUsersAsync(CollectorResultBuilder builder, CancellationToken cancellationToken)
    {
        const string path =
            "users?$select=id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime," +
            "signInActivity,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesSecurityIdentifier," +
            "onPremisesDistinguishedName,onPremisesSamAccountName,assignedLicenses,externalUserState&$top=999";

        var (items, failure) = await _graph.TryEnumerateAsync(path, cancellationToken).ConfigureAwait(false);

        if (failure is not null && items.Count == 0)
        {
            builder.MarkUnavailable(EvidenceKeys.EntraUsers, Classify(failure), failure.Message);
            builder.MarkUnavailable(EvidenceKeys.EntraSignInActivity, Classify(failure), failure.Message);
            return [];
        }

        var signInActivityAvailable = items.Any(item => item.TryGetProperty("signInActivity", out var activity)
                                                        && activity.ValueKind == JsonValueKind.Object);

        var users = items.Select(item => new EntraUser
        {
            ObjectId = GraphJson.String(item, "id") ?? string.Empty,
            UserPrincipalName = GraphJson.String(item, "userPrincipalName") ?? string.Empty,
            DisplayName = GraphJson.String(item, "displayName"),
            AccountEnabled = GraphJson.Boolean(item, "accountEnabled") ?? true,
            UserType = GraphJson.String(item, "userType") ?? "Member",
            CreatedDateTime = GraphJson.Timestamp(item, "createdDateTime"),
            LastSignInDateTime = ReadSignInActivity(item, "lastSignInDateTime"),
            LastNonInteractiveSignInDateTime = ReadSignInActivity(item, "lastNonInteractiveSignInDateTime"),
            OnPremisesSyncEnabled = GraphJson.Boolean(item, "onPremisesSyncEnabled") ?? false,
            OnPremisesImmutableId = GraphJson.String(item, "onPremisesImmutableId"),
            OnPremisesSecurityIdentifier = GraphJson.String(item, "onPremisesSecurityIdentifier"),
            OnPremisesDistinguishedName = GraphJson.String(item, "onPremisesDistinguishedName"),
            OnPremisesSamAccountName = GraphJson.String(item, "onPremisesSamAccountName"),
            ExternalUserState = GraphJson.String(item, "externalUserState"),
        })
        .Where(user => user.ObjectId.Length > 0)
        .ToList();

        builder.MarkCollected(EvidenceKeys.EntraUsers);

        if (signInActivityAvailable)
        {
            builder.MarkCollected(EvidenceKeys.EntraSignInActivity);
        }
        else
        {
            builder.MarkUnavailable(
                EvidenceKeys.EntraSignInActivity,
                EvidenceAvailability.PermissionDenied,
                "Sign-in activity was not returned. It requires the audit log permission and a " +
                "premium licence; checks that depend on it report as not collected.");
        }

        builder.AddRecord(
            "entra.users",
            EvidenceKind.DirectoryQuery,
            $"{users.Count} user(s), of which {users.Count(user => user.UserType == "Guest")} are guests");

        return users;
    }

    private async Task<List<EntraUser>> ApplyRegistrationAsync(
        List<EntraUser> users,
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        if (users.Count == 0)
        {
            return users;
        }

        var (items, failure) = await _graph
            .TryEnumerateAsync("reports/authenticationMethods/userRegistrationDetails?$top=999", cancellationToken)
            .ConfigureAwait(false);

        if (failure is not null && items.Count == 0)
        {
            builder.MarkUnavailable(EvidenceKeys.EntraRegistrationDetails, Classify(failure), failure.Message);
            return users;
        }

        var registrationById = items
            .Where(item => GraphJson.String(item, "id") is not null)
            .ToDictionary(
                item => GraphJson.String(item, "id")!,
                item => new MfaRegistrationState
                {
                    IsMfaRegistered = GraphJson.Boolean(item, "isMfaRegistered") ?? false,
                    IsMfaCapable = GraphJson.Boolean(item, "isMfaCapable") ?? false,
                    IsPasswordlessCapable = GraphJson.Boolean(item, "isPasswordlessCapable") ?? false,
                    IsSsprRegistered = GraphJson.Boolean(item, "isSsprRegistered") ?? false,
                    Methods = GraphJson.Strings(item, "methodsRegistered"),
                },
                StringComparer.OrdinalIgnoreCase);

        builder.MarkCollected(EvidenceKeys.EntraRegistrationDetails);
        builder.AddRecord(
            "entra.registration",
            EvidenceKind.DirectoryQuery,
            $"Registration details for {registrationById.Count} account(s)");

        return users
            .Select(user => registrationById.TryGetValue(user.ObjectId, out var registration)
                ? user with { Registration = registration }
                : user)
            .ToList();
    }

    private async Task<List<EntraGroup>> CollectGroupsAsync(CollectorResultBuilder builder, CancellationToken cancellationToken)
    {
        const string path =
            "groups?$select=id,displayName,securityEnabled,isAssignableToRole,onPremisesSyncEnabled," +
            "onPremisesSecurityIdentifier,membershipRule&$top=999";

        var (items, failure) = await _graph.TryEnumerateAsync(path, cancellationToken).ConfigureAwait(false);

        if (failure is not null && items.Count == 0)
        {
            builder.MarkUnavailable(EvidenceKeys.EntraGroups, Classify(failure), failure.Message);
            return [];
        }

        var groups = new List<EntraGroup>(items.Count);

        foreach (var item in items)
        {
            var id = GraphJson.String(item, "id");
            if (id is null)
            {
                continue;
            }

            groups.Add(new EntraGroup
            {
                ObjectId = id,
                DisplayName = GraphJson.String(item, "displayName") ?? id,
                SecurityEnabled = GraphJson.Boolean(item, "securityEnabled") ?? false,
                IsAssignableToRole = GraphJson.Boolean(item, "isAssignableToRole") ?? false,
                OnPremisesSyncEnabled = GraphJson.Boolean(item, "onPremisesSyncEnabled") ?? false,
                OnPremisesSecurityIdentifier = GraphJson.String(item, "onPremisesSecurityIdentifier"),
                MembershipRule = GraphJson.String(item, "membershipRule"),
            });
        }

        // Membership is read only for role-assignable groups, because those are the ones whose
        // members inherit directory privilege.
        foreach (var group in groups.Where(group => group.IsAssignableToRole).ToList())
        {
            cancellationToken.ThrowIfCancellationRequested();

            var (members, memberFailure) = await _graph
                .TryEnumerateAsync($"groups/{group.ObjectId}/members?$select=id&$top=999", cancellationToken)
                .ConfigureAwait(false);

            if (memberFailure is not null)
            {
                builder.Log(
                    DiagnosticSeverity.Warning,
                    $"Membership of a role-assignable group could not be read: {memberFailure.Code}.",
                    "GroupMembers");

                continue;
            }

            var index = groups.IndexOf(group);
            groups[index] = group with
            {
                MemberObjectIds = members
                    .Select(member => GraphJson.String(member, "id"))
                    .Where(id => id is not null)
                    .Select(id => id!)
                    .ToList(),
            };
        }

        builder.MarkCollected(EvidenceKeys.EntraGroups);
        builder.AddRecord("entra.groups", EvidenceKind.DirectoryQuery, $"{groups.Count} group(s)");

        return groups;
    }

    private async Task<List<EntraDevice>> CollectDevicesAsync(CollectorResultBuilder builder, CancellationToken cancellationToken)
    {
        const string path =
            "devices?$select=id,displayName,accountEnabled,trustType,operatingSystem,operatingSystemVersion," +
            "isCompliant,isManaged,approximateLastSignInDateTime,registrationDateTime&$top=999";

        var (items, failure) = await _graph.TryEnumerateAsync(path, cancellationToken).ConfigureAwait(false);

        if (failure is not null && items.Count == 0)
        {
            builder.MarkUnavailable(EvidenceKeys.EntraDevices, Classify(failure), failure.Message);
            return [];
        }

        var devices = items
            .Where(item => GraphJson.String(item, "id") is not null)
            .Select(item => new EntraDevice
            {
                ObjectId = GraphJson.String(item, "id")!,
                DisplayName = GraphJson.String(item, "displayName") ?? "unknown",
                AccountEnabled = GraphJson.Boolean(item, "accountEnabled") ?? true,
                TrustType = GraphJson.String(item, "trustType"),
                OperatingSystem = GraphJson.String(item, "operatingSystem"),
                OperatingSystemVersion = GraphJson.String(item, "operatingSystemVersion"),
                IsCompliant = GraphJson.Boolean(item, "isCompliant"),
                IsManaged = GraphJson.Boolean(item, "isManaged"),
                ApproximateLastSignInDateTime = GraphJson.Timestamp(item, "approximateLastSignInDateTime"),
                RegistrationDateTime = GraphJson.Timestamp(item, "registrationDateTime"),
            })
            .ToList();

        builder.MarkCollected(EvidenceKeys.EntraDevices);
        builder.AddRecord("entra.devices", EvidenceKind.DirectoryQuery, $"{devices.Count} device object(s)");

        return devices;
    }

    private async Task<List<EntraRoleAssignment>> CollectRoleAssignmentsAsync(
        IReadOnlyCollection<EntraGroup> groups,
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        var assignments = new List<EntraRoleAssignment>();

        var (definitions, definitionFailure) = await _graph
            .TryEnumerateAsync("roleManagement/directory/roleDefinitions?$select=id,displayName,templateId", cancellationToken)
            .ConfigureAwait(false);

        if (definitionFailure is not null)
        {
            builder.MarkUnavailable(EvidenceKeys.EntraRoles, Classify(definitionFailure), definitionFailure.Message);
            builder.MarkUnavailable(
                EvidenceKeys.EntraPrivilegedIdentityManagement,
                Classify(definitionFailure),
                definitionFailure.Message);

            return assignments;
        }

        var roleNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var templateByDefinition = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var definition in definitions)
        {
            var id = GraphJson.String(definition, "id");
            var templateId = GraphJson.String(definition, "templateId") ?? id;
            var name = GraphJson.String(definition, "displayName");

            if (id is null || templateId is null)
            {
                continue;
            }

            templateByDefinition[id] = templateId;
            roleNames[templateId] = name ?? templateId;
        }

        var (active, activeFailure) = await _graph
            .TryEnumerateAsync(
                "roleManagement/directory/roleAssignments?$expand=principal($select=id,displayName)&$top=999",
                cancellationToken)
            .ConfigureAwait(false);

        if (activeFailure is not null && active.Count == 0)
        {
            builder.MarkUnavailable(EvidenceKeys.EntraRoles, Classify(activeFailure), activeFailure.Message);
        }
        else
        {
            assignments.AddRange(active.Select(item => ToAssignment(
                item,
                templateByDefinition,
                roleNames,
                groups,
                RoleAssignmentKind.Permanent)));

            builder.MarkCollected(EvidenceKeys.EntraRoles);
        }

        var (eligible, eligibleFailure) = await _graph
            .TryEnumerateAsync(
                "roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal($select=id,displayName)&$top=999",
                cancellationToken)
            .ConfigureAwait(false);

        if (eligibleFailure is not null)
        {
            builder.MarkUnavailable(
                EvidenceKeys.EntraPrivilegedIdentityManagement,
                Classify(eligibleFailure),
                "Eligible role assignments were not returned. Privileged Identity Management is " +
                "licence gated, so the checks that need it report as not collected.");
        }
        else
        {
            assignments.AddRange(eligible.Select(item => ToAssignment(
                item,
                templateByDefinition,
                roleNames,
                groups,
                RoleAssignmentKind.Eligible)));

            builder.MarkCollected(EvidenceKeys.EntraPrivilegedIdentityManagement);
        }

        builder.AddRecord(
            "entra.roleAssignments",
            EvidenceKind.DirectoryQuery,
            $"{assignments.Count} directory role assignment(s), of which " +
            $"{assignments.Count(assignment => assignment.Kind == RoleAssignmentKind.Eligible)} are eligible");

        return assignments;
    }

    private static EntraRoleAssignment ToAssignment(
        JsonElement item,
        IReadOnlyDictionary<string, string> templateByDefinition,
        IReadOnlyDictionary<string, string> roleNames,
        IReadOnlyCollection<EntraGroup> groups,
        RoleAssignmentKind kind)
    {
        var definitionId = GraphJson.String(item, "roleDefinitionId") ?? string.Empty;
        var templateId = templateByDefinition.GetValueOrDefault(definitionId, definitionId);
        var principalId = GraphJson.String(item, "principalId") ?? string.Empty;
        var principal = GraphJson.Object(item, "principal");

        var displayName = principal is null ? principalId : GraphJson.String(principal.Value, "displayName") ?? principalId;

        var principalType = principal is not null && principal.Value.TryGetProperty("@odata.type", out var type)
            ? NormalisePrincipalType(type.GetString())
            : groups.Any(group => string.Equals(group.ObjectId, principalId, StringComparison.OrdinalIgnoreCase))
                ? "group"
                : "user";

        return new EntraRoleAssignment
        {
            RoleDefinitionId = templateId,
            RoleName = roleNames.GetValueOrDefault(templateId, templateId),
            PrincipalId = principalId,
            PrincipalDisplayName = displayName,
            PrincipalType = principalType,
            Kind = kind,
            Scope = GraphJson.String(item, "directoryScopeId") ?? "/",
            AssignedDateTime = GraphJson.Timestamp(item, "startDateTime"),
            ExpiresDateTime = GraphJson.Timestamp(item, "endDateTime"),
        };
    }

    private static string NormalisePrincipalType(string? odataType) => odataType switch
    {
        "#microsoft.graph.user" => "user",
        "#microsoft.graph.group" => "group",
        "#microsoft.graph.servicePrincipal" => "servicePrincipal",
        _ => "user",
    };

    private static DateTimeOffset? ReadSignInActivity(JsonElement user, string property)
    {
        var activity = GraphJson.Object(user, "signInActivity");
        return activity is null ? null : GraphJson.Timestamp(activity.Value, property);
    }

    /// <summary>Maps a Graph failure onto the availability reason a rule reports.</summary>
    internal static EvidenceAvailability Classify(GraphRequestException? failure) => failure switch
    {
        null => EvidenceAvailability.Error,
        { IsAuthorisationFailure: true } => EvidenceAvailability.PermissionDenied,
        { StatusCode: System.Net.HttpStatusCode.NotFound } => EvidenceAvailability.Unsupported,
        { StatusCode: System.Net.HttpStatusCode.NotImplemented } => EvidenceAvailability.Unsupported,
        _ => EvidenceAvailability.Error,
    };
}
