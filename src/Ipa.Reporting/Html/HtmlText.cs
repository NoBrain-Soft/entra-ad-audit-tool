using System.Text;

namespace Ipa.Reporting.Html;

/// <summary>
/// Escapes every value that reaches the report.
/// </summary>
/// <remarks>
/// Report content originates in directory and tenant objects that an attacker may be able to name,
/// so a display name containing markup must never become markup. Every interpolation in the
/// composer goes through this class; there is no path that writes an untrusted value unescaped.
/// </remarks>
public static class HtmlText
{
    /// <summary>Escapes text for an element body or an attribute value.</summary>
    public static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length + 16);

        foreach (var character in value)
        {
            switch (character)
            {
                case '&':
                    builder.Append("&amp;");
                    break;

                case '<':
                    builder.Append("&lt;");
                    break;

                case '>':
                    builder.Append("&gt;");
                    break;

                case '"':
                    builder.Append("&quot;");
                    break;

                case '\'':
                    builder.Append("&#39;");
                    break;

                default:
                    // Control characters are dropped rather than escaped: they carry no meaning in a
                    // report and can confuse a renderer.
                    if (!char.IsControl(character) || character is '\n' or '\t')
                    {
                        builder.Append(character);
                    }

                    break;
            }
        }

        return builder.ToString();
    }

    /// <summary>Escapes a value for use inside a CSS declaration, rejecting anything unexpected.</summary>
    public static string CssColor(string? value, string fallback)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        var trimmed = value.Trim();

        // Only a hexadecimal colour is accepted: anything else could close the declaration and
        // inject further style rules.
        if (trimmed.Length is not (4 or 7) || trimmed[0] != '#')
        {
            return fallback;
        }

        return trimmed.Skip(1).All(Uri.IsHexDigit) ? trimmed : fallback;
    }

    /// <summary>Builds a data URI for an embedded image, rejecting an unexpected media type.</summary>
    public static string? DataUri(byte[]? bytes, string? mediaType)
    {
        if (bytes is null || bytes.Length == 0)
        {
            return null;
        }

        var type = mediaType?.Trim().ToLowerInvariant();

        // Only raster formats a renderer handles natively are embedded. Scalable vector graphics
        // are excluded deliberately: they can carry script.
        if (type is not ("image/png" or "image/jpeg" or "image/gif" or "image/webp"))
        {
            return null;
        }

        return $"data:{type};base64,{Convert.ToBase64String(bytes)}";
    }
}
