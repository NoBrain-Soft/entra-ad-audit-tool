using System.Text.Json;
using Ipa.Collectors.Entra.Graph;
using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Security;

namespace Ipa.Collectors.Entra.Collectors;

/// <summary>
/// Collects Conditional Access policies, the authentication methods policy, security defaults and
/// the sign-in observations used to detect legacy authentication.
/// </summary>
public sealed class EntraPolicyCollector : ICollector
{
    private readonly GraphReadClient _graph;

    public EntraPolicyCollector(GraphReadClient graph)
    {
        ArgumentNullException.ThrowIfNull(graph);
        _graph = graph;
    }

    /// <inheritdoc />
    public string CollectorId => "entra.policy";

    /// <inheritdoc />
    public string DisplayName => "Conditional Access and authentication policy";

    /// <inheritdoc />
    public AssessmentSource Source => AssessmentSource.Entra;

    /// <inheritdoc />
    public IReadOnlyList<CollectorPrerequisite> Prerequisites { get; } =
    [
        new("Policy read consent", "Consent for Policy.Read.All in the customer's tenant."),
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> RequiredPermissions { get; } = ["Policy.Read.All", "AuditLog.Read.All"];

    /// <inheritdoc />
    public IReadOnlyList<string> ProducedEvidenceKeys { get; } =
    [
        EvidenceKeys.EntraConditionalAccess, EvidenceKeys.EntraAuthenticationMethods,
        EvidenceKeys.EntraLegacyAuthentication,
    ];

    /// <inheritdoc />
    public IReadOnlyList<CheckGroup> SupportedGroups { get; } =
    [
        CheckGroup.EntraConditionalAccess, CheckGroup.EntraAuthentication,
        CheckGroup.EntraPrivilegedAccess, CheckGroup.HybridPrivilegeExposure,
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
            builder.Progress("Conditional Access", "Reading Conditional Access policies");
            var policies = await CollectConditionalAccessAsync(builder, cancellationToken).ConfigureAwait(false);

            builder.Progress("Authentication", "Reading the authentication methods policy");
            var methods = await CollectAuthenticationMethodsAsync(builder, cancellationToken).ConfigureAwait(false);

            builder.Progress("Sign-in activity", "Sampling sign-ins for legacy authentication");
            var legacy = await CollectLegacyAuthenticationAsync(builder, context, cancellationToken).ConfigureAwait(false);

            var existing = context.PreviousEvidence?.Entra;

            var fragment = existing is null
                ? new EvidenceFragment()
                : new EvidenceFragment
                {
                    Entra = existing with
                    {
                        ConditionalAccessPolicies = policies,
                        AuthenticationMethods = methods,
                        LegacyAuthentication = legacy,
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
                $"Policy collection failed: {Redaction.Scrub(ex.Message)}",
                "CollectionFailed",
                ex);

            foreach (var key in ProducedEvidenceKeys)
            {
                builder.MarkUnavailable(key, EvidenceAvailability.Error, "Policy collection failed.");
            }

            return builder.Build(CollectionOutcome.Failed, new EvidenceFragment());
        }
    }

    private async Task<List<ConditionalAccessPolicy>> CollectConditionalAccessAsync(
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        var (items, failure) = await _graph
            .TryEnumerateAsync("identity/conditionalAccess/policies", cancellationToken)
            .ConfigureAwait(false);

        if (failure is not null && items.Count == 0)
        {
            builder.MarkUnavailable(
                EvidenceKeys.EntraConditionalAccess,
                EntraDirectoryCollector.Classify(failure),
                failure.Message);

            return [];
        }

        var policies = items.Select(ToPolicy).ToList();

        builder.MarkCollected(EvidenceKeys.EntraConditionalAccess);
        builder.AddRecord(
            "entra.conditionalAccess",
            EvidenceKind.PolicyDocument,
            $"{policies.Count} policy object(s): {policies.Count(policy => policy.IsEnabled)} enabled, " +
            $"{policies.Count(policy => policy.IsReportOnly)} report only");

        return policies;
    }

    private static ConditionalAccessPolicy ToPolicy(JsonElement item)
    {
        var conditions = GraphJson.Object(item, "conditions");
        var users = conditions is null ? null : GraphJson.Object(conditions.Value, "users");
        var applications = conditions is null ? null : GraphJson.Object(conditions.Value, "applications");
        var platforms = conditions is null ? null : GraphJson.Object(conditions.Value, "platforms");
        var locations = conditions is null ? null : GraphJson.Object(conditions.Value, "locations");
        var grant = GraphJson.Object(item, "grantControls");
        var session = GraphJson.Object(item, "sessionControls");

        return new ConditionalAccessPolicy
        {
            PolicyId = GraphJson.String(item, "id") ?? string.Empty,
            DisplayName = GraphJson.String(item, "displayName") ?? "unnamed policy",
            State = GraphJson.String(item, "state") ?? "disabled",
            IncludeUsers = users is null ? [] : GraphJson.Strings(users.Value, "includeUsers"),
            ExcludeUsers = users is null ? [] : GraphJson.Strings(users.Value, "excludeUsers"),
            IncludeGroups = users is null ? [] : GraphJson.Strings(users.Value, "includeGroups"),
            ExcludeGroups = users is null ? [] : GraphJson.Strings(users.Value, "excludeGroups"),
            IncludeRoles = users is null ? [] : GraphJson.Strings(users.Value, "includeRoles"),
            ExcludeRoles = users is null ? [] : GraphJson.Strings(users.Value, "excludeRoles"),
            IncludeApplications = applications is null ? [] : GraphJson.Strings(applications.Value, "includeApplications"),
            ExcludeApplications = applications is null ? [] : GraphJson.Strings(applications.Value, "excludeApplications"),
            IncludeUserActions = applications is null ? [] : GraphJson.Strings(applications.Value, "includeUserActions"),
            ClientAppTypes = conditions is null ? [] : GraphJson.Strings(conditions.Value, "clientAppTypes"),
            IncludePlatforms = platforms is null ? [] : GraphJson.Strings(platforms.Value, "includePlatforms"),
            ExcludePlatforms = platforms is null ? [] : GraphJson.Strings(platforms.Value, "excludePlatforms"),
            IncludeLocations = locations is null ? [] : GraphJson.Strings(locations.Value, "includeLocations"),
            ExcludeLocations = locations is null ? [] : GraphJson.Strings(locations.Value, "excludeLocations"),
            UserRiskLevels = conditions is null ? [] : GraphJson.Strings(conditions.Value, "userRiskLevels"),
            SignInRiskLevels = conditions is null ? [] : GraphJson.Strings(conditions.Value, "signInRiskLevels"),
            GrantControls = grant is null
                ? null
                : new ConditionalAccessGrantControls
                {
                    Operator = GraphJson.String(grant.Value, "operator") ?? "OR",
                    BuiltInControls = GraphJson.Strings(grant.Value, "builtInControls"),
                    AuthenticationStrengthPolicyIds = ReadAuthenticationStrength(grant.Value),
                },
            SessionControls = session is null
                ? []
                : session.Value.EnumerateObject()
                    .Where(property => property.Value.ValueKind == JsonValueKind.Object)
                    .Select(property => property.Name)
                    .ToList(),
            CreatedDateTime = GraphJson.Timestamp(item, "createdDateTime"),
            ModifiedDateTime = GraphJson.Timestamp(item, "modifiedDateTime"),
        };
    }

    private static IReadOnlyList<string> ReadAuthenticationStrength(JsonElement grantControls)
    {
        var strength = GraphJson.Object(grantControls, "authenticationStrength");

        if (strength is null)
        {
            return [];
        }

        var id = GraphJson.String(strength.Value, "id");
        return id is null ? [] : [id];
    }

    private async Task<AuthenticationMethodsConfiguration?> CollectAuthenticationMethodsAsync(
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        var (policy, policyFailure) = await _graph
            .TryGetAsync("policies/authenticationMethodsPolicy", cancellationToken)
            .ConfigureAwait(false);

        var (defaults, defaultsFailure) = await _graph
            .TryGetAsync("policies/identitySecurityDefaultsEnforcementPolicy", cancellationToken)
            .ConfigureAwait(false);

        if (policy is null && defaults is null)
        {
            builder.MarkUnavailable(
                EvidenceKeys.EntraAuthenticationMethods,
                EntraDirectoryCollector.Classify(policyFailure ?? defaultsFailure),
                (policyFailure ?? defaultsFailure)?.Message ?? "The authentication policy could not be read.");

            return null;
        }

        var states = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        if (policy is { } document)
        {
            foreach (var configuration in GraphJson.Objects(document, "authenticationMethodConfigurations"))
            {
                var id = GraphJson.String(configuration, "id");
                var state = GraphJson.String(configuration, "state");

                if (id is not null)
                {
                    states[id] = string.Equals(state, "enabled", StringComparison.OrdinalIgnoreCase);
                }
            }
        }

        var configurationResult = new AuthenticationMethodsConfiguration
        {
            MethodStates = states,
            PolicyMigrationState = policy is null ? null : GraphJson.String(policy.Value, "policyMigrationState"),
            SecurityDefaultsEnabled = defaults is not null && (GraphJson.Boolean(defaults.Value, "isEnabled") ?? false),
            LegacyPerUserMfaInUse = false,
        };

        builder.MarkCollected(EvidenceKeys.EntraAuthenticationMethods);
        builder.AddRecord(
            "entra.authenticationMethods",
            EvidenceKind.PolicyDocument,
            $"{states.Count(state => state.Value)} authentication method(s) enabled; security defaults " +
            $"{(configurationResult.SecurityDefaultsEnabled ? "enabled" : "disabled")}");

        return configurationResult;
    }

    private async Task<List<LegacyAuthenticationObservation>> CollectLegacyAuthenticationAsync(
        CollectorResultBuilder builder,
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        // The sign-in log is sampled over the retention window rather than read in full: the
        // question is whether legacy authentication succeeds at all, not how often.
        var since = context.ReferenceTime.AddDays(-30).UtcDateTime.ToString("o");
        var path =
            "auditLogs/signIns?$filter=createdDateTime ge " + since +
            " and (clientAppUsed eq 'Other clients' or clientAppUsed eq 'IMAP4' or clientAppUsed eq 'POP3' " +
            "or clientAppUsed eq 'SMTP' or clientAppUsed eq 'MAPI Over HTTP' or clientAppUsed eq 'Exchange ActiveSync')" +
            "&$select=clientAppUsed,userPrincipalName,createdDateTime,status&$top=1000";

        var (items, failure) = await _graph
            .TryEnumerateAsync(path, cancellationToken, maxItems: 20_000)
            .ConfigureAwait(false);

        if (failure is not null && items.Count == 0)
        {
            builder.MarkUnavailable(
                EvidenceKeys.EntraLegacyAuthentication,
                EntraDirectoryCollector.Classify(failure),
                "Sign-in logs were not readable, so legacy authentication could not be observed. " +
                "The report requires the audit log permission and a premium licence.");

            return [];
        }

        var byClient = new Dictionary<string, (int Total, int Successful, HashSet<string> Users, DateTimeOffset? Last)>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var item in items)
        {
            var client = GraphJson.String(item, "clientAppUsed") ?? "unknown";
            var user = GraphJson.String(item, "userPrincipalName") ?? string.Empty;
            var timestamp = GraphJson.Timestamp(item, "createdDateTime");

            var status = GraphJson.Object(item, "status");
            var errorCode = status is null ? 0 : (int)(GraphJson.Number(status.Value, "errorCode") ?? 0);
            var succeeded = errorCode == 0;

            if (!byClient.TryGetValue(client, out var entry))
            {
                entry = (0, 0, new HashSet<string>(StringComparer.OrdinalIgnoreCase), null);
            }

            entry.Total++;

            if (succeeded)
            {
                entry.Successful++;
            }

            if (user.Length > 0)
            {
                entry.Users.Add(user);
            }

            if (timestamp is not null && (entry.Last is null || timestamp > entry.Last))
            {
                entry.Last = timestamp;
            }

            byClient[client] = entry;
        }

        var observations = byClient
            .Select(entry => new LegacyAuthenticationObservation
            {
                ClientApplication = entry.Key,
                SignInCount = entry.Value.Total,
                SuccessfulSignInCount = entry.Value.Successful,
                DistinctUserCount = entry.Value.Users.Count,
                LastObserved = entry.Value.Last,
            })
            .OrderByDescending(observation => observation.SuccessfulSignInCount)
            .ToList();

        builder.MarkCollected(EvidenceKeys.EntraLegacyAuthentication);
        builder.AddRecord(
            "entra.legacyAuthentication",
            EvidenceKind.DirectoryQuery,
            observations.Count == 0
                ? "No legacy authentication sign-in was observed in the sampled window"
                : $"{observations.Sum(observation => observation.SuccessfulSignInCount)} successful " +
                  $"legacy sign-in(s) across {observations.Count} client application(s)");

        return observations;
    }
}
