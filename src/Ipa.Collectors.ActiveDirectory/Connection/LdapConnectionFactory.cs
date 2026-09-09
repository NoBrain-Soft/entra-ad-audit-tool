using System.DirectoryServices.Protocols;
using System.Security.Cryptography.X509Certificates;

namespace Ipa.Collectors.ActiveDirectory.Connection;

/// <summary>
/// Creates directory connections that satisfy the product's transport rules: signing and sealing
/// for integrated authentication, and a validated TLS channel before any explicit credential is
/// transmitted. There is no code path that downgrades to an unsigned, unencrypted simple bind.
/// </summary>
public sealed class LdapConnectionFactory
{
    /// <summary>Opens a connection, applying the configured transport protection.</summary>
    public LdapConnection Create(DirectoryConnectionSettings settings, out CertificateValidator validator)
    {
        ArgumentNullException.ThrowIfNull(settings);
        settings.Validate();

        validator = new CertificateValidator(settings.TrustException);
        var capturedValidator = validator;

        var identifier = new LdapDirectoryIdentifier(
            settings.Server,
            settings.EffectivePort,
            fullyQualifiedDnsHostName: true,
            connectionless: false);

        var connection = new LdapConnection(identifier)
        {
            AuthType = settings.AuthenticationMode == DirectoryAuthenticationMode.WindowsIntegrated
                ? AuthType.Negotiate
                : AuthType.Basic,
            Timeout = settings.Timeout,
        };

        try
        {
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            connection.SessionOptions.VerifyServerCertificate =
                (_, certificate) => VerifyCertificate(capturedValidator, certificate);

            switch (settings.TransportSecurity)
            {
                case DirectoryTransportSecurity.Ldaps:
                    connection.SessionOptions.SecureSocketLayer = true;
                    break;

                case DirectoryTransportSecurity.StartTls:
                    connection.SessionOptions.StartTransportLayerSecurity(null);
                    break;

                case DirectoryTransportSecurity.SignAndSeal:
                    // Kerberos signing and sealing protects integrity and confidentiality without
                    // TLS, and is permitted only for integrated authentication.
                    connection.SessionOptions.Signing = true;
                    connection.SessionOptions.Sealing = true;
                    break;

                default:
                    throw new InvalidOperationException(
                        $"Unsupported transport security {settings.TransportSecurity}.");
            }

            if (settings.AuthenticationMode == DirectoryAuthenticationMode.ExplicitCredentials)
            {
                connection.Bind(settings.Credential!.ToNetworkCredential());
            }
            else
            {
                connection.Bind();
            }

            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static bool VerifyCertificate(CertificateValidator validator, X509Certificate certificate)
    {
        using var certificate2 = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        using var chain = new X509Chain();

        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        var built = chain.Build(certificate2);
        var errors = built
            ? System.Net.Security.SslPolicyErrors.None
            : System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors;

        return validator.Validate(certificate2, chain, errors);
    }
}
