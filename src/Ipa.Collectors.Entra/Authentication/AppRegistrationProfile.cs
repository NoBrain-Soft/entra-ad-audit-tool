using System.Text;
using Ipa.Contracts;

namespace Ipa.Collectors.Entra.Authentication;

/// <summary>
/// The customer-owned public-client application registration this product signs in through. The
/// registration belongs to the customer's tenant, so the customer controls which permissions are
/// consented and can revoke access without involving the vendor.
/// </summary>
public sealed record AppRegistrationProfile
{
    /// <summary>Tenant identifier, either the directory identifier or a verified domain name.</summary>
    public required string TenantId { get; init; }

    /// <summary>Application (client) identifier of the customer's registration.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// Redirect address for the authorisation code flow. A loopback address is used so that no
    /// registration needs a hosted reply endpoint.
    /// </summary>
    public string RedirectUri { get; init; } = "http://localhost";

    /// <summary>Authority host. Only the global Microsoft cloud is supported in version one.</summary>
    public string AuthorityHost { get; init; } = "https://login.microsoftonline.com";

    /// <summary>Microsoft Graph endpoint for the selected cloud.</summary>
    public string GraphEndpoint { get; init; } = "https://graph.microsoft.com";

    /// <summary>Authority used by the identity library.</summary>
    public string Authority => $"{AuthorityHost.TrimEnd('/')}/{TenantId}";

    /// <summary>Validates the profile, returning the problems an operator must correct.</summary>
    public IReadOnlyList<string> Validate()
    {
        var problems = new List<string>();

        if (string.IsNullOrWhiteSpace(TenantId))
        {
            problems.Add("A tenant identifier or verified domain name is required.");
        }

        if (!Guid.TryParse(ClientId, out _))
        {
            problems.Add("The application (client) identifier must be a globally unique identifier.");
        }

        if (!Uri.TryCreate(RedirectUri, UriKind.Absolute, out var redirect))
        {
            problems.Add("The redirect address must be an absolute address.");
        }
        else if (!redirect.IsLoopback)
        {
            problems.Add(
                "The redirect address must be a loopback address so that no hosted reply endpoint " +
                "is required and no authorisation code leaves the operator's machine.");
        }

        if (!AuthorityHost.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            problems.Add("The authority host must use HTTPS.");
        }

        return problems;
    }

    /// <summary>
    /// Builds the administrator consent address for the selected check groups. The operator hands
    /// this to a Global Administrator, who grants consent in the customer's own tenant.
    /// </summary>
    public string BuildAdminConsentUrl(IEnumerable<CheckGroup> groups)
    {
        ArgumentNullException.ThrowIfNull(groups);

        var scopes = Permissions.PermissionManifest.ScopesFor(groups);
        var scopeParameter = Uri.EscapeDataString(string.Join(' ', scopes));

        var builder = new StringBuilder(256);
        builder.Append(AuthorityHost.TrimEnd('/'))
            .Append('/').Append(Uri.EscapeDataString(TenantId))
            .Append("/v2.0/adminconsent?client_id=").Append(Uri.EscapeDataString(ClientId))
            .Append("&scope=").Append(scopeParameter)
            .Append("&redirect_uri=").Append(Uri.EscapeDataString(RedirectUri));

        return builder.ToString();
    }

    /// <summary>Steps shown by the setup wizard for creating the registration.</summary>
    public static IReadOnlyList<string> SetupInstructions { get; } =
    [
        "In the customer's tenant, register a new application under Microsoft Entra ID, " +
        "App registrations, New registration.",
        "Choose 'Accounts in this organizational directory only' as the supported account type.",
        "Under Authentication, add a Mobile and desktop applications platform and the redirect " +
        "address http://localhost.",
        "Enable 'Allow public client flows' so that the desktop authorisation code and device code " +
        "flows can be used. Do not create a client secret: this product never uses one.",
        "Under API permissions, add the delegated Microsoft Graph permissions this assessment " +
        "requires, then ask a Global Administrator to grant admin consent.",
        "Copy the Directory (tenant) ID and the Application (client) ID into this wizard.",
    ];
}
