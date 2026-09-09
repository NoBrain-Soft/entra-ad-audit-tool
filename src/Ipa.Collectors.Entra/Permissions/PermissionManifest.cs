using Ipa.Contracts;

namespace Ipa.Collectors.Entra.Permissions;

/// <summary>One Microsoft Graph permission the product may request.</summary>
/// <param name="Scope">Delegated permission name, for example <c>Directory.Read.All</c>.</param>
/// <param name="Purpose">Operator-facing explanation of what the permission is used for.</param>
/// <param name="IsSensitive">
/// True for permissions that expose security data and normally need a privileged directory role
/// in addition to consent.
/// </param>
public sealed record GraphPermission(string Scope, string Purpose, bool IsSensitive = false);

/// <summary>
/// The versioned manifest of Microsoft Graph permissions. Only the scopes required by the check
/// groups the operator selected are requested, so an assessment that skips a group never asks the
/// tenant for the permission that group would need.
/// </summary>
/// <remarks>
/// Every permission in the manifest is read-only. The product requests no write scope of any kind,
/// which is what makes "no tenant write requests" verifiable rather than merely intended.
/// </remarks>
public static class PermissionManifest
{
    /// <summary>Manifest version, recorded with the assessment so a report is reproducible.</summary>
    public const string Version = "2026.09.1";

    private static readonly Dictionary<CheckGroup, GraphPermission[]> ByGroup = new()
    {
        [CheckGroup.EntraPrivilegedAccess] =
        [
            new("Directory.Read.All", "Read directory objects, roles and their assignments."),
            new("RoleManagement.Read.Directory", "Read directory role definitions and assignments."),
            new("AuditLog.Read.All", "Read sign-in activity used to detect dormant privileged accounts.", true),
        ],

        [CheckGroup.EntraAuthentication] =
        [
            new("Policy.Read.All", "Read the authentication methods policy and security defaults."),
            new("Reports.Read.All", "Read authentication method registration reports.", true),
            new("AuditLog.Read.All", "Read sign-in activity used to detect legacy authentication.", true),
        ],

        [CheckGroup.EntraConditionalAccess] =
        [
            new("Policy.Read.All", "Read Conditional Access policies and their conditions."),
            new("Directory.Read.All", "Resolve the users, groups and roles a policy targets."),
        ],

        [CheckGroup.EntraApplications] =
        [
            new("Application.Read.All", "Read application registrations, service principals and credentials."),
            new("Directory.Read.All", "Resolve application owners and granted permissions."),
        ],

        [CheckGroup.EntraDirectoryHygiene] =
        [
            new("Directory.Read.All", "Read users, groups and devices."),
            new("AuditLog.Read.All", "Read sign-in activity used to detect dormant objects.", true),
        ],

        [CheckGroup.EntraSecureScore] =
        [
            new("SecurityEvents.Read.All", "Read the Microsoft Secure Score snapshot.", true),
        ],

        [CheckGroup.HybridIdentityCorrelation] =
        [
            new("Directory.Read.All", "Read the synchronisation attributes used to correlate identities."),
        ],

        [CheckGroup.HybridPrivilegeExposure] =
        [
            new("Directory.Read.All", "Read synchronised accounts and their directory roles."),
            new("RoleManagement.Read.Directory", "Read the roles held by synchronised accounts."),
        ],

        [CheckGroup.HybridSynchronisation] =
        [
            new("Directory.Read.All", "Read tenant synchronisation state and verified domains."),
            new("Policy.Read.All", "Read federation configuration for verified domains."),
        ],
    };

    /// <summary>Every permission the manifest can request, ordered for display.</summary>
    public static IReadOnlyList<GraphPermission> All { get; } = ByGroup.Values
        .SelectMany(permissions => permissions)
        .DistinctBy(permission => permission.Scope, StringComparer.OrdinalIgnoreCase)
        .OrderBy(permission => permission.Scope, StringComparer.Ordinal)
        .ToList();

    /// <summary>Returns the permissions needed by the supplied check groups, without duplicates.</summary>
    public static IReadOnlyList<GraphPermission> For(IEnumerable<CheckGroup> groups)
    {
        ArgumentNullException.ThrowIfNull(groups);

        return groups
            .Where(ByGroup.ContainsKey)
            .SelectMany(group => ByGroup[group])
            .DistinctBy(permission => permission.Scope, StringComparer.OrdinalIgnoreCase)
            .OrderBy(permission => permission.Scope, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>Returns the scope strings to request from the identity platform.</summary>
    public static string[] ScopesFor(IEnumerable<CheckGroup> groups) =>
        For(groups).Select(permission => permission.Scope).ToArray();

    /// <summary>Returns the check groups that a given permission enables.</summary>
    public static IReadOnlyList<CheckGroup> GroupsRequiring(string scope)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);

        return ByGroup
            .Where(entry => entry.Value.Any(permission =>
                string.Equals(permission.Scope, scope, StringComparison.OrdinalIgnoreCase)))
            .Select(entry => entry.Key)
            .ToList();
    }

    /// <summary>
    /// Verifies that no scope in the manifest grants write access. The check runs in the test suite
    /// so that a future edit cannot introduce a write permission unnoticed.
    /// </summary>
    public static bool IsReadOnly(string scope) =>
        !scope.Contains("Write", StringComparison.OrdinalIgnoreCase)
        && !scope.Contains("Manage", StringComparison.OrdinalIgnoreCase)
        && !scope.Contains("full_access", StringComparison.OrdinalIgnoreCase);
}
