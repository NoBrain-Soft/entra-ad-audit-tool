using System.Text;

namespace Ipa.Contracts.Text;

/// <summary>
/// Turns identifiers into the text a reader sees.
/// </summary>
/// <remarks>
/// Shared deliberately: the report, the interface and the generated rule catalogue have to name
/// the same thing the same way, and a second copy of this drifts from the first.
/// </remarks>
public static class DisplayText
{
    /// <summary>
    /// Abbreviations that must not be read as ordinary words. "Ad" is the important one: a report
    /// that names a check group "Ad privileged access" reads as though it were about advertising.
    /// </summary>
    private static readonly Dictionary<string, string> Abbreviations =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["ad"] = "AD",
            ["acl"] = "ACL",
            ["iso"] = "ISO",
        };

    /// <summary>
    /// Splits a Pascal-cased identifier into words, keeping known abbreviations in capitals.
    /// </summary>
    public static string Humanise(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var builder = new StringBuilder(value.Length + 8);

        for (var index = 0; index < value.Length; index++)
        {
            if (index > 0 && char.IsUpper(value[index]) && !char.IsUpper(value[index - 1]))
            {
                builder.Append(' ');
                builder.Append(char.ToLowerInvariant(value[index]));
                continue;
            }

            builder.Append(value[index]);
        }

        var words = builder.ToString().Split(' ');

        for (var index = 0; index < words.Length; index++)
        {
            if (Abbreviations.TryGetValue(words[index], out var abbreviation))
            {
                words[index] = abbreviation;
            }
        }

        return string.Join(' ', words);
    }
}
