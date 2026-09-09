using System.Text.Json;
using Ipa.Collectors.Entra.Authentication;
using Ipa.Collectors.Entra.Graph;
using Ipa.Collectors.Entra.Permissions;
using Ipa.Contracts;

namespace Ipa.Collectors.Entra.Preflight;

/// <summary>How serious a preflight observation is for the assessment about to run.</summary>
public enum PreflightSeverity
{
    /// <summary>Everything the check group needs is present.</summary>
    Ready,

    /// <summary>The assessment can run, but some checks will report as not collected.</summary>
    Degraded,

    /// <summary>The assessment cannot run at all in this configuration.</summary>
    Blocking,
}

/// <summary>One observation from the preflight.</summary>
public sealed record PreflightFinding
{
    public required PreflightSeverity Severity { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }

    /// <summary>Check groups this observation affects.</summary>
    public IReadOnlyList<CheckGroup> AffectedGroups { get; init; } = [];

    /// <summary>What the operator should do before running the assessment.</summary>
    public string? Remedy { get; init; }
}

/// <summary>The complete preflight report shown before collection starts.</summary>
public sealed record PreflightReport
{
    public required IReadOnlyList<PreflightFinding> Findings { get; init; }
    public required string PermissionManifestVersion { get; init; }
    public IReadOnlyList<string> GrantedScopes { get; init; } = [];
    public IReadOnlyList<string> DetectedServicePlans { get; init; } = [];
    public string? TenantDisplayName { get; init; }
    public string? CloudInstance { get; init; }

    /// <summary>True when nothing blocks the assessment from running.</summary>
    public bool CanProceed => Findings.All(finding => finding.Severity != PreflightSeverity.Blocking);

    /// <summary>Check groups that will produce incomplete results.</summary>
    public IReadOnlyList<CheckGroup> DegradedGroups => Findings
        .Where(finding => finding.Severity != PreflightSeverity.Ready)
        .SelectMany(finding => finding.AffectedGroups)
        .Distinct()
        .ToList();
}

/// <summary>
/// Verifies before collection that consent, directory roles, tenant licensing and endpoint
/// availability are sufficient for the selected check groups, so that missing prerequisites are
/// reported up front rather than appearing as unexplained gaps in the results.
/// </summary>
public sealed class EntraPreflight
{
    private readonly GraphReadClient _graph;

    public EntraPreflight(GraphReadClient graph)
    {
        ArgumentNullException.ThrowIfNull(graph);
        _graph = graph;
    }

    /// <summary>Runs the preflight for the selected check groups.</summary>
    public async Task<PreflightReport> RunAsync(
        AppRegistrationProfile profile,
        AuthenticationOutcome authentication,
        IReadOnlyCollection<CheckGroup> groups,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(groups);

        var findings = new List<PreflightFinding>();

        if (!authentication.Succeeded)
        {
            findings.Add(new PreflightFinding
            {
                Severity = PreflightSeverity.Blocking,
                Title = "Sign-in did not complete",
                Detail = authentication.FailureMessage ?? "No access token was obtained.",
                AffectedGroups = groups.ToList(),
                Remedy = "Sign in again, and confirm the application registration allows public client flows.",
            });

            return new PreflightReport
            {
                Findings = findings,
                PermissionManifestVersion = PermissionManifest.Version,
            };
        }

        CheckCloudInstance(profile, findings, groups);
        CheckConsent(authentication, groups, findings);

        var (organisation, organisationFailure) = await _graph
            .TryGetAsync("organization", cancellationToken)
            .ConfigureAwait(false);

        string? tenantName = null;
        var servicePlans = new List<string>();

        if (organisationFailure is not null)
        {
            findings.Add(new PreflightFinding
            {
                Severity = PreflightSeverity.Blocking,
                Title = "The tenant could not be read",
                Detail = $"Reading the organisation failed: {organisationFailure.Code}. " +
                         organisationFailure.Message,
                AffectedGroups = groups.ToList(),
                Remedy = organisationFailure.IsAuthorisationFailure
                    ? "Grant administrator consent for the read-only permissions this assessment requests."
                    : "Confirm network access to Microsoft Graph and try again.",
            });
        }
        else if (organisation is { } document)
        {
            (tenantName, servicePlans) = ReadOrganisation(document);
            CheckLicensing(servicePlans, groups, findings);
        }

        await CheckRoleSensitiveEndpointsAsync(groups, findings, cancellationToken).ConfigureAwait(false);

        if (findings.Count == 0)
        {
            findings.Add(new PreflightFinding
            {
                Severity = PreflightSeverity.Ready,
                Title = "All prerequisites are satisfied",
                Detail = "Consent, directory roles and tenant licensing cover every selected check group.",
                AffectedGroups = groups.ToList(),
            });
        }

        return new PreflightReport
        {
            Findings = findings,
            PermissionManifestVersion = PermissionManifest.Version,
            GrantedScopes = authentication.GrantedScopes,
            DetectedServicePlans = servicePlans,
            TenantDisplayName = tenantName,
            CloudInstance = "global",
        };
    }

    private static void CheckCloudInstance(
        AppRegistrationProfile profile,
        List<PreflightFinding> findings,
        IReadOnlyCollection<CheckGroup> groups)
    {
        if (profile.AuthorityHost.Contains("login.microsoftonline.com", StringComparison.OrdinalIgnoreCase)
            && profile.GraphEndpoint.Contains("graph.microsoft.com", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        findings.Add(new PreflightFinding
        {
            Severity = PreflightSeverity.Blocking,
            Title = "The tenant is not in the global Microsoft cloud",
            Detail = "Version one supports the global Microsoft cloud only. Sovereign and national " +
                     "clouds use different authority and Graph endpoints and are not yet supported.",
            AffectedGroups = groups.ToList(),
            Remedy = "Assess this tenant with a release that supports its cloud instance.",
        });
    }

    private static void CheckConsent(
        AuthenticationOutcome authentication,
        IReadOnlyCollection<CheckGroup> groups,
        List<PreflightFinding> findings)
    {
        foreach (var missing in authentication.MissingScopes)
        {
            var affected = PermissionManifest.GroupsRequiring(missing)
                .Where(groups.Contains)
                .ToList();

            if (affected.Count == 0)
            {
                continue;
            }

            findings.Add(new PreflightFinding
            {
                Severity = PreflightSeverity.Degraded,
                Title = $"Consent is missing for {missing}",
                Detail = $"The identity platform did not grant {missing}. Checks that depend on it " +
                         "will report as not collected and will reduce collection coverage.",
                AffectedGroups = affected,
                Remedy = "Ask a Global Administrator to grant administrator consent for this " +
                         "permission on the application registration.",
            });
        }
    }

    private static void CheckLicensing(
        IReadOnlyCollection<string> servicePlans,
        IReadOnlyCollection<CheckGroup> groups,
        List<PreflightFinding> findings)
    {
        var hasPremiumP1 = servicePlans.Any(plan =>
            plan.Contains("AAD_PREMIUM", StringComparison.OrdinalIgnoreCase));

        var hasPremiumP2 = servicePlans.Any(plan =>
            plan.Contains("AAD_PREMIUM_P2", StringComparison.OrdinalIgnoreCase)
            || plan.Contains("IDENTITY_THREAT_PROTECTION", StringComparison.OrdinalIgnoreCase));

        if (!hasPremiumP1 && groups.Contains(CheckGroup.EntraConditionalAccess))
        {
            findings.Add(new PreflightFinding
            {
                Severity = PreflightSeverity.Degraded,
                Title = "Conditional Access requires a premium licence",
                Detail = "No premium identity service plan was detected. Conditional Access policies " +
                         "may be unavailable, in which case those checks report as not collected.",
                AffectedGroups = [CheckGroup.EntraConditionalAccess],
                Remedy = "Confirm the tenant's licensing, or deselect the Conditional Access group.",
            });
        }

        if (!hasPremiumP2 && groups.Contains(CheckGroup.EntraPrivilegedAccess))
        {
            findings.Add(new PreflightFinding
            {
                Severity = PreflightSeverity.Degraded,
                Title = "Privileged Identity Management data may be unavailable",
                Detail = "No premium plan two service plan was detected. Eligible role assignments " +
                         "and risk signals are licence gated; the checks that need them will report " +
                         "as not collected rather than as passing.",
                AffectedGroups = [CheckGroup.EntraPrivilegedAccess],
                Remedy = "No action is required if the tenant does not license these features.",
            });
        }
    }

    private async Task CheckRoleSensitiveEndpointsAsync(
        IReadOnlyCollection<CheckGroup> groups,
        List<PreflightFinding> findings,
        CancellationToken cancellationToken)
    {
        if (groups.Contains(CheckGroup.EntraSecureScore))
        {
            var (_, failure) = await _graph
                .TryGetAsync("security/secureScores?$top=1", cancellationToken)
                .ConfigureAwait(false);

            if (failure is not null)
            {
                findings.Add(new PreflightFinding
                {
                    Severity = PreflightSeverity.Degraded,
                    Title = "Microsoft Secure Score is not readable",
                    Detail = $"Reading Secure Score failed: {failure.Code}. Retrieval needs a " +
                             "sensitive permission and a directory role such as Security Reader.",
                    AffectedGroups = [CheckGroup.EntraSecureScore],
                    Remedy = "Grant the signed-in account a Security Reader role, or deselect the " +
                             "Secure Score group.",
                });
            }
        }

        if (groups.Contains(CheckGroup.EntraAuthentication) || groups.Contains(CheckGroup.EntraDirectoryHygiene))
        {
            var (_, failure) = await _graph
                .TryGetAsync("reports/authenticationMethods/userRegistrationDetails?$top=1", cancellationToken)
                .ConfigureAwait(false);

            if (failure is not null)
            {
                findings.Add(new PreflightFinding
                {
                    Severity = PreflightSeverity.Degraded,
                    Title = "Authentication method registration details are not readable",
                    Detail = $"Reading the registration report failed: {failure.Code}. The report " +
                             "requires the reports permission and a reader role.",
                    AffectedGroups = [CheckGroup.EntraAuthentication],
                    Remedy = "Grant the signed-in account a Reports Reader or Global Reader role.",
                });
            }
        }
    }

    private static (string? TenantName, List<string> ServicePlans) ReadOrganisation(JsonElement document)
    {
        var organisation = document.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().FirstOrDefault()
            : document;

        if (organisation.ValueKind != JsonValueKind.Object)
        {
            return (null, []);
        }

        var name = organisation.TryGetProperty("displayName", out var displayName)
            ? displayName.GetString()
            : null;

        var plans = new List<string>();

        if (organisation.TryGetProperty("assignedPlans", out var assigned) && assigned.ValueKind == JsonValueKind.Array)
        {
            foreach (var plan in assigned.EnumerateArray())
            {
                if (plan.TryGetProperty("service", out var service) && service.GetString() is { } serviceName)
                {
                    plans.Add(serviceName);
                }
            }
        }

        return (name, plans.Distinct(StringComparer.OrdinalIgnoreCase).ToList());
    }
}
