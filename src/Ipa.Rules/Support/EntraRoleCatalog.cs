namespace Ipa.Rules.Support;

/// <summary>
/// Directory roles treated as privileged by the rule pack, identified by their built-in template
/// identifier so that a renamed role is still recognised.
/// </summary>
public static class EntraRoleCatalog
{
    /// <summary>Template identifier of the Global Administrator role.</summary>
    public const string GlobalAdministrator = "62e90394-69f5-4237-9190-012177145e10";

    /// <summary>Template identifier of the Privileged Role Administrator role.</summary>
    public const string PrivilegedRoleAdministrator = "e8611ab8-c189-46e8-94e1-60213ab1f814";

    /// <summary>
    /// Roles whose holders can grant themselves further privilege, read all directory data, or
    /// control authentication. Compromise of any of these is treated as tenant compromise.
    /// </summary>
    private static readonly Dictionary<string, string> HighPrivilegeRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        [GlobalAdministrator] = "Global Administrator",
        [PrivilegedRoleAdministrator] = "Privileged Role Administrator",
        ["9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"] = "Application Administrator",
        ["158c047a-c907-4556-b7ef-446551a6b5f7"] = "Cloud Application Administrator",
        ["c4e39bd9-1100-46d3-8c65-fb160da0071f"] = "Authentication Administrator",
        ["7be44c8a-adaf-4e2a-84d6-ab2649e08a13"] = "Privileged Authentication Administrator",
        ["29232cdf-9323-42fd-ade2-1d097af3e4de"] = "Exchange Administrator",
        ["f28a1f50-f6e7-4571-818b-6a12f2af6b6c"] = "SharePoint Administrator",
        ["fe930be7-5e62-47db-91af-98c3a49a38b1"] = "User Administrator",
        ["729827e3-9c14-49f7-bb1b-9608f156bbb8"] = "Helpdesk Administrator",
        ["194ae4cb-b126-40b2-bd5b-6091b380977d"] = "Security Administrator",
        ["e3973bdf-4987-49ae-837a-ba8e231c7286"] = "Azure DevOps Administrator",
        ["3a2c62db-5318-420d-8d74-23affee5d9d5"] = "Intune Administrator",
        ["17315797-102d-40b4-93e0-432062caca18"] = "Compliance Administrator",
        ["b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"] = "Conditional Access Administrator",
        ["966707d0-3269-4727-9be2-8c3a10f19b9d"] = "Password Administrator",
        ["8329153b-31d0-4727-b945-745eb3bc5f31"] = "Domain Name Administrator",
        ["e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477"] = "External Identity Provider Administrator",
        ["be2f45a1-457d-42af-a067-6ec1fa63bc45"] = "External Identity Provider Administrator (legacy)",
    };

    /// <summary>True when the role identifier is one of the high-privilege directory roles.</summary>
    public static bool IsHighPrivilege(string roleDefinitionId) =>
        HighPrivilegeRoles.ContainsKey(roleDefinitionId);

    /// <summary>Returns the well-known name of a privileged role, or null when it is not one.</summary>
    public static string? Name(string roleDefinitionId) =>
        HighPrivilegeRoles.TryGetValue(roleDefinitionId, out var name) ? name : null;

    /// <summary>
    /// Microsoft Graph application permissions that grant tenant-wide control or bulk access to
    /// sensitive data. Granting any of these to a non-Microsoft application is a finding.
    /// </summary>
    public static IReadOnlySet<string> HighImpactApplicationPermissions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Directory.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "AppRoleAssignment.ReadWrite.All",
            "Application.ReadWrite.All",
            "Group.ReadWrite.All",
            "GroupMember.ReadWrite.All",
            "User.ReadWrite.All",
            "Policy.ReadWrite.ConditionalAccess",
            "Policy.ReadWrite.AuthenticationMethod",
            "PrivilegedAccess.ReadWrite.AzureAD",
            "Mail.ReadWrite",
            "Mail.Send",
            "Files.ReadWrite.All",
            "Sites.FullControl.All",
            "full_access_as_app",
            "UserAuthenticationMethod.ReadWrite.All",
        };

    /// <summary>Delegated scopes that grant broad access when consented for all principals.</summary>
    public static IReadOnlySet<string> SensitiveDelegatedScopes { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Directory.ReadWrite.All",
            "Directory.AccessAsUser.All",
            "Files.ReadWrite.All",
            "Mail.ReadWrite",
            "Mail.Send",
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Sites.FullControl.All",
            "RoleManagement.ReadWrite.Directory",
        };
}
