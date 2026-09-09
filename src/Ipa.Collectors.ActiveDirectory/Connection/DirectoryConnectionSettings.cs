using System.Net;

namespace Ipa.Collectors.ActiveDirectory.Connection;

/// <summary>How the collector authenticates to the directory.</summary>
public enum DirectoryAuthenticationMode
{
    /// <summary>
    /// The signed-in Windows identity, negotiated with signing and sealing. Available on Windows
    /// only; on Linux the operator must supply explicit credentials over TLS.
    /// </summary>
    WindowsIntegrated,

    /// <summary>
    /// Explicit credentials. Permitted only over a validated LDAPS or StartTLS channel: the
    /// factory refuses to send a credential over an unprotected connection.
    /// </summary>
    ExplicitCredentials,
}

/// <summary>Transport security required of the directory connection.</summary>
public enum DirectoryTransportSecurity
{
    /// <summary>LDAP over TLS on port 636.</summary>
    Ldaps,

    /// <summary>LDAP on port 389 upgraded with the StartTLS extended operation.</summary>
    StartTls,

    /// <summary>
    /// Kerberos signing and sealing over port 389 without TLS. Permitted only with Windows
    /// integrated authentication, which never transmits a reusable secret.
    /// </summary>
    SignAndSeal,
}

/// <summary>
/// An operator-approved exception to certificate validation. Accepting a private authority or a
/// pinned certificate always requires an explicit decision, and the exception is recorded so it
/// appears in the report rather than silently weakening the assessment.
/// </summary>
public sealed record CertificateTrustException
{
    /// <summary>SHA-256 thumbprint of the certificate or issuing authority the operator accepted.</summary>
    public required string Sha256Thumbprint { get; init; }

    /// <summary>Subject of the accepted certificate, shown in the report.</summary>
    public required string Subject { get; init; }

    /// <summary>Why the operator accepted it. Printed in the report's exceptions section.</summary>
    public required string Justification { get; init; }

    public required DateTimeOffset AcceptedAt { get; init; }

    /// <summary>Name of the operator who accepted the exception.</summary>
    public required string AcceptedBy { get; init; }
}

/// <summary>
/// Credentials for an explicit bind. The password is held only for the lifetime of the connection
/// and is never written to the session database, a saved project, a log or a report.
/// </summary>
public sealed class DirectoryCredential : IDisposable
{
    private readonly System.Security.SecureString? _password;

    public DirectoryCredential(string userName, string domain, System.Security.SecureString password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentNullException.ThrowIfNull(password);

        UserName = userName;
        Domain = domain;
        _password = password;
    }

    /// <summary>Account name used for the bind.</summary>
    public string UserName { get; }

    /// <summary>Domain of the account, which may be empty for a user principal name bind.</summary>
    public string Domain { get; }

    /// <summary>Builds the network credential handed to the directory library.</summary>
    public NetworkCredential ToNetworkCredential() =>
        new(UserName, _password ?? new System.Security.SecureString(), Domain);

    public void Dispose() => _password?.Dispose();
}

/// <summary>Settings describing how to reach and authenticate to one directory server.</summary>
public sealed record DirectoryConnectionSettings
{
    /// <summary>Fully qualified name of the server, or the domain name for automatic discovery.</summary>
    public required string Server { get; init; }

    /// <summary>Port. Defaults follow the transport: 636 for LDAPS, otherwise 389.</summary>
    public int? Port { get; init; }

    public DirectoryAuthenticationMode AuthenticationMode { get; init; } =
        DirectoryAuthenticationMode.WindowsIntegrated;

    public DirectoryTransportSecurity TransportSecurity { get; init; } = DirectoryTransportSecurity.Ldaps;

    /// <summary>Explicit credentials, required when the authentication mode calls for them.</summary>
    public DirectoryCredential? Credential { get; init; }

    /// <summary>Operator-approved certificate exception, when one was granted.</summary>
    public CertificateTrustException? TrustException { get; init; }

    /// <summary>Connection and search timeout.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Page size used for paged directory searches.</summary>
    public int PageSize { get; init; } = 500;

    /// <summary>Effective port for the configured transport.</summary>
    public int EffectivePort => Port ?? (TransportSecurity == DirectoryTransportSecurity.Ldaps ? 636 : 389);

    /// <summary>
    /// Validates the combination of authentication mode and transport. Explicit credentials over
    /// an unprotected channel are refused outright rather than downgraded.
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Server))
        {
            throw new InvalidOperationException("A directory server or domain name is required.");
        }

        if (AuthenticationMode == DirectoryAuthenticationMode.ExplicitCredentials)
        {
            if (Credential is null)
            {
                throw new InvalidOperationException(
                    "Explicit credentials were selected but no credential was supplied.");
            }

            if (TransportSecurity == DirectoryTransportSecurity.SignAndSeal)
            {
                throw new InvalidOperationException(
                    "Explicit credentials require LDAPS or StartTLS. This assessment never sends a " +
                    "reusable credential over an unencrypted connection, and never silently " +
                    "downgrades to an unsigned bind.");
            }
        }

        if (AuthenticationMode == DirectoryAuthenticationMode.WindowsIntegrated
            && !OperatingSystem.IsWindows())
        {
            throw new InvalidOperationException(
                "Windows integrated authentication is available only on Windows. On Linux, supply " +
                "explicit credentials over LDAPS or StartTLS.");
        }
    }
}
