using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Ipa.Collectors.ActiveDirectory.Connection;

/// <summary>
/// Validates the certificate presented by a directory server. Validation never silently accepts a
/// failure: a private authority or a self-signed certificate is honoured only when the operator
/// has explicitly recorded a trust exception, and the decision is surfaced in the report.
/// </summary>
public sealed class CertificateValidator
{
    private readonly CertificateTrustException? _exception;
    private readonly List<string> _observations = [];

    public CertificateValidator(CertificateTrustException? trustException) => _exception = trustException;

    /// <summary>Human-readable notes recorded while validating, for the collection diagnostics.</summary>
    public IReadOnlyList<string> Observations => _observations;

    /// <summary>The certificate the server presented, captured for the trust prompt.</summary>
    public X509Certificate2? PresentedCertificate { get; private set; }

    /// <summary>Chain errors observed on the last validation attempt.</summary>
    public SslPolicyErrors LastErrors { get; private set; } = SslPolicyErrors.None;

    /// <summary>
    /// Verifies a server certificate. Returns true only when the chain validates, or when it fails
    /// and the operator's recorded exception pins exactly this certificate.
    /// </summary>
    public bool Validate(X509Certificate2 certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        PresentedCertificate = certificate;
        LastErrors = errors;

        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        var thumbprint = ComputeSha256Thumbprint(certificate);
        _observations.Add($"Certificate validation reported {errors} for subject '{certificate.Subject}'.");

        if (chain is not null)
        {
            foreach (var status in chain.ChainStatus)
            {
                _observations.Add($"Chain status: {status.Status} - {status.StatusInformation.Trim()}");
            }
        }

        if (_exception is null)
        {
            _observations.Add(
                "No operator exception is recorded for this certificate, so the connection was refused.");
            return false;
        }

        if (!string.Equals(_exception.Sha256Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            _observations.Add(
                "The recorded exception pins a different certificate, so the connection was refused.");
            return false;
        }

        // A name mismatch is never covered by a pinned-certificate exception: pinning attests to
        // the identity of the certificate, not to the server being the one the operator intended.
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            _observations.Add(
                "The certificate name does not match the requested server. A pinned certificate " +
                "exception does not cover a name mismatch, so the connection was refused.");
            return false;
        }

        _observations.Add(
            $"Accepted under the operator exception recorded on {_exception.AcceptedAt:yyyy-MM-dd} " +
            $"by {_exception.AcceptedBy}. This exception is reported with the assessment.");

        return true;
    }

    /// <summary>Computes the SHA-256 thumbprint used to pin a certificate.</summary>
    public static string ComputeSha256Thumbprint(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant();
    }
}
