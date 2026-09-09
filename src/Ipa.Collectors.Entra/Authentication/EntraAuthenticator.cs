using Ipa.Contracts;
using Ipa.Contracts.Security;
using Microsoft.Identity.Client;

namespace Ipa.Collectors.Entra.Authentication;

/// <summary>The outcome of an interactive sign-in.</summary>
public sealed record AuthenticationOutcome
{
    /// <summary>True when a token was obtained.</summary>
    public required bool Succeeded { get; init; }

    /// <summary>Scopes the identity platform actually granted.</summary>
    public IReadOnlyList<string> GrantedScopes { get; init; } = [];

    /// <summary>Scopes requested but not granted, which the preflight reports as missing consent.</summary>
    public IReadOnlyList<string> MissingScopes { get; init; } = [];

    /// <summary>Signed-in account, used only for display and for the report's methodology section.</summary>
    public string? AccountDisplayName { get; init; }

    /// <summary>Tenant the token was issued for.</summary>
    public string? TenantId { get; init; }

    /// <summary>Expiry of the access token held in memory.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }

    /// <summary>Operator-facing failure message, already scrubbed of any token material.</summary>
    public string? FailureMessage { get; init; }
}

/// <summary>
/// Signs in to Microsoft Graph as a public client.
/// </summary>
/// <remarks>
/// Authentication uses the authorisation code flow with proof key for code exchange through the
/// system browser, and falls back to the device code flow when a loopback listener cannot be
/// opened. No token cache is serialised: access and refresh tokens live only in memory for the
/// lifetime of the process and are never written to the session database, a saved project or a log.
/// </remarks>
public sealed class EntraAuthenticator : IAsyncDisposable
{
    private readonly AppRegistrationProfile _profile;
    private readonly IPublicClientApplication _application;
    private IAccount? _account;
    private string[] _grantedScopes = [];

    public EntraAuthenticator(AppRegistrationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var problems = profile.Validate();
        if (problems.Count > 0)
        {
            throw new ArgumentException(
                $"The application registration profile is not usable: {string.Join(" ", problems)}",
                nameof(profile));
        }

        _profile = profile;

        _application = PublicClientApplicationBuilder
            .Create(profile.ClientId)
            .WithAuthority(profile.Authority)
            .WithRedirectUri(profile.RedirectUri)
            // The token cache is deliberately left in its default in-memory form. Nothing is
            // registered to serialise it, so no token reaches disk.
            .Build();
    }

    /// <summary>Scopes granted by the last successful sign-in.</summary>
    public IReadOnlyList<string> GrantedScopes => _grantedScopes;

    /// <summary>
    /// Signs in interactively for the scopes the selected check groups need, falling back to the
    /// device code flow when the system browser or the loopback listener is unavailable.
    /// </summary>
    public async Task<AuthenticationOutcome> SignInAsync(
        IReadOnlyCollection<CheckGroup> groups,
        Func<string, Task>? deviceCodePrompt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(groups);

        var requested = Permissions.PermissionManifest.ScopesFor(groups);

        if (requested.Length == 0)
        {
            return new AuthenticationOutcome
            {
                Succeeded = false,
                FailureMessage = "No Microsoft Entra check group was selected, so no sign-in is required.",
            };
        }

        try
        {
            var result = await _application
                .AcquireTokenInteractive(requested)
                .WithUseEmbeddedWebView(false)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            return Capture(result, requested);
        }
        catch (MsalClientException ex) when (
            ex.ErrorCode is MsalError.LoopbackRedirectUri
                or MsalError.LinuxXdgOpen
                or MsalError.LoopbackResponseUriMismatch
                or MsalError.WebviewUnavailable)
        {
            if (deviceCodePrompt is null)
            {
                return Failure(
                    "The system browser could not be opened for sign-in, and no device code prompt " +
                    "was available to fall back to.");
            }

            return await SignInWithDeviceCodeAsync(requested, deviceCodePrompt, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (MsalException ex)
        {
            return Failure(Describe(ex));
        }
    }

    /// <summary>Signs in using the device code flow, for hosts without a usable browser.</summary>
    public async Task<AuthenticationOutcome> SignInWithDeviceCodeAsync(
        string[] scopes,
        Func<string, Task> prompt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(prompt);

        try
        {
            var result = await _application
                .AcquireTokenWithDeviceCode(scopes, code => prompt(code.Message))
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            return Capture(result, scopes);
        }
        catch (MsalException ex)
        {
            return Failure(Describe(ex));
        }
    }

    /// <summary>
    /// Returns a valid access token, refreshing silently when the cached one has expired. The token
    /// is returned to the caller for the lifetime of one request and is never stored.
    /// </summary>
    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        if (_account is null)
        {
            throw new InvalidOperationException("Sign in before requesting an access token.");
        }

        var result = await _application
            .AcquireTokenSilent(_grantedScopes, _account)
            .ExecuteAsync(cancellationToken)
            .ConfigureAwait(false);

        return result.AccessToken;
    }

    /// <summary>Signs out and removes the in-memory account, discarding cached tokens.</summary>
    public async Task SignOutAsync()
    {
        var accounts = await _application.GetAccountsAsync().ConfigureAwait(false);

        foreach (var account in accounts)
        {
            await _application.RemoveAsync(account).ConfigureAwait(false);
        }

        _account = null;
        _grantedScopes = [];
    }

    private AuthenticationOutcome Capture(AuthenticationResult result, string[] requested)
    {
        _account = result.Account;
        _grantedScopes = result.Scopes.ToArray();

        var granted = new HashSet<string>(_grantedScopes, StringComparer.OrdinalIgnoreCase);

        // The identity platform returns scopes with a resource prefix; compare on the trailing name.
        var missing = requested
            .Where(scope => !granted.Any(value =>
                value.EndsWith(scope, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        return new AuthenticationOutcome
        {
            Succeeded = true,
            GrantedScopes = _grantedScopes,
            MissingScopes = missing,
            AccountDisplayName = result.Account?.Username,
            TenantId = result.TenantId ?? _profile.TenantId,
            ExpiresOn = result.ExpiresOn,
        };
    }

    private static AuthenticationOutcome Failure(string message) => new()
    {
        Succeeded = false,
        FailureMessage = Redaction.Scrub(message),
    };

    private static string Describe(MsalException exception) => exception.ErrorCode switch
    {
        "invalid_client" =>
            "The application registration was not accepted. Confirm the client identifier and that " +
            "public client flows are enabled on the registration.",

        "unauthorized_client" =>
            "The registration is not authorised for this flow. Enable public client flows under " +
            "Authentication on the registration.",

        "consent_required" or "interaction_required" =>
            "Administrator consent has not been granted for the requested permissions.",

        "access_denied" =>
            "Sign-in was refused. The account may lack the directory role the requested permissions need.",

        _ => Redaction.Scrub($"Sign-in failed ({exception.ErrorCode}): {exception.Message}"),
    };

    /// <inheritdoc />
    public async ValueTask DisposeAsync() => await SignOutAsync().ConfigureAwait(false);
}
