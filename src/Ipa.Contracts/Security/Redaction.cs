using System.Text.RegularExpressions;

namespace Ipa.Contracts.Security;

/// <summary>
/// Removes credentials, tokens and other secrets from text before it reaches a log, a diagnostic
/// entry or a report. The product never persists Active Directory passwords, Microsoft Graph
/// access or refresh tokens, or project passphrases; this class is the last line of defence for
/// values that reach free-text messages.
/// </summary>
public static class Redaction
{
    /// <summary>Placeholder written in place of a redacted value.</summary>
    public const string Placeholder = "[redacted]";

    private static readonly (Regex Pattern, string Replacement)[] Patterns =
    [
        // JSON Web Tokens (Graph access and id tokens).
        (new Regex(@"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), Placeholder),

        // Bearer / authorization headers.
        (new Regex(@"(?i)\b(bearer|authorization\s*[:=])\s+\S+",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "$1 " + Placeholder),

        // Refresh tokens and secrets carried as query or form values.
        (new Regex(@"(?i)\b(refresh_token|access_token|id_token|client_secret|code_verifier|assertion)\s*[=:]\s*[^\s&""',;]+",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "$1=" + Placeholder),

        // Password-like assignments, including LDAP simple bind material.
        (new Regex(@"(?i)\b(password|passwd|pwd|passphrase|unicodePwd|dBCSPwd|lmPwdHistory|ntPwdHistory|supplementalCredentials)\s*[=:]\s*[^\s&""',;]+",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "$1=" + Placeholder),

        // LDAP simple bind lines captured from protocol traces.
        (new Regex(@"(?i)\b(simpleBind|bindPassword)\s*\(\s*[^)]*\)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "$1(" + Placeholder + ")"),
    ];

    /// <summary>Attribute names whose raw values are never written to logs or default reports.</summary>
    private static readonly HashSet<string> SensitiveAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "unicodePwd",
        "dBCSPwd",
        "lmPwdHistory",
        "ntPwdHistory",
        "supplementalCredentials",
        "msDS-ManagedPassword",
        "msDS-ManagedPasswordPreviousId",
        "ms-Mcs-AdmPwd",
        "msLAPS-Password",
        "msLAPS-EncryptedPassword",
        "userPassword",
        "trustAuthIncoming",
        "trustAuthOutgoing",
        "currentValue",
        "priorValue",
        "pekList",
        "clientSecret",
        "secretText",
    };

    /// <summary>Returns the text with every recognised secret replaced by a placeholder.</summary>
    public static string Scrub(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var result = text;
        foreach (var (pattern, replacement) in Patterns)
        {
            result = pattern.Replace(result, replacement);
        }

        return result;
    }

    /// <summary>True when an attribute must never have its raw value recorded.</summary>
    public static bool IsSensitiveAttribute(string attributeName) =>
        !string.IsNullOrWhiteSpace(attributeName) && SensitiveAttributes.Contains(attributeName);

    /// <summary>
    /// Returns a safe representation of an attribute value: sensitive attributes collapse to a
    /// placeholder that records only whether a value was present.
    /// </summary>
    public static string SafeAttributeValue(string attributeName, string? value)
    {
        if (IsSensitiveAttribute(attributeName))
        {
            return value is null ? "[absent]" : Placeholder;
        }

        return Scrub(value);
    }
}
