using System.Text;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.GroupPolicy;

/// <summary>
/// Parses a security template (<c>GptTmpl.inf</c>) into normalised settings. Templates are INI
/// files, usually encoded as UTF-16 little-endian with a byte order mark, and the parser accepts
/// UTF-8 as well so that baselines exported by other tooling still load.
/// </summary>
public static class SecurityTemplateParser
{
    /// <summary>Largest template the parser will accept, guarding against hostile input.</summary>
    public const int MaxFileBytes = 8 * 1024 * 1024;

    /// <summary>Sections whose values name trustees rather than scalar settings.</summary>
    private static readonly HashSet<string> TrusteeSections = new(StringComparer.OrdinalIgnoreCase)
    {
        "Privilege Rights",
        "Group Membership",
    };

    /// <summary>Result of parsing one template.</summary>
    public readonly record struct ParseResult(
        IReadOnlyList<SecurityTemplateSetting> Settings,
        IReadOnlyList<string> Notes);

    /// <summary>Parses a security template from raw bytes, detecting the text encoding.</summary>
    public static ParseResult Parse(ReadOnlySpan<byte> content)
    {
        if (content.Length > MaxFileBytes)
        {
            return new ParseResult([], [$"The security template exceeds the {MaxFileBytes} byte limit."]);
        }

        return Parse(DecodeText(content));
    }

    /// <summary>Parses a security template from decoded text.</summary>
    public static ParseResult Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var settings = new List<SecurityTemplateSetting>();
        var notes = new List<string>();
        var section = string.Empty;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim().Trim('\r');

            if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim();
                continue;
            }

            var separator = line.IndexOf('=');
            if (separator <= 0)
            {
                notes.Add($"Skipped a line in section '{section}' that is not a key and value pair.");
                continue;
            }

            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();

            settings.Add(new SecurityTemplateSetting
            {
                Section = section,
                Name = name,
                Value = value,
                Trustees = TrusteeSections.Contains(section) ? ParseTrustees(value) : [],
            });
        }

        return new ParseResult(settings, notes);
    }

    /// <summary>
    /// Splits a trustee list. Entries are comma separated, and a leading asterisk marks a security
    /// identifier: <c>*S-1-5-32-544</c> becomes <c>S-1-5-32-544</c> while named principals are kept
    /// verbatim for the operator to resolve.
    /// </summary>
    public static IReadOnlyList<string> ParseTrustees(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length == 0)
        {
            return [];
        }

        return value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(entry => entry.StartsWith('*') ? entry[1..] : entry)
            .Where(entry => entry.Length > 0)
            .ToList();
    }

    /// <summary>Decodes template bytes, honouring a byte order mark and defaulting to UTF-16.</summary>
    private static string DecodeText(ReadOnlySpan<byte> content)
    {
        if (content.Length >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(content[3..]);
        }

        if (content.Length >= 2 && content[0] == 0xFF && content[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(content[2..]);
        }

        if (content.Length >= 2 && content[0] == 0xFE && content[1] == 0xFF)
        {
            return Encoding.BigEndianUnicode.GetString(content[2..]);
        }

        // Templates written without a byte order mark are still usually UTF-16 little-endian:
        // a high proportion of zero bytes in the odd positions is a reliable indicator.
        if (LooksLikeUtf16(content))
        {
            return Encoding.Unicode.GetString(content);
        }

        return Encoding.UTF8.GetString(content);
    }

    private static bool LooksLikeUtf16(ReadOnlySpan<byte> content)
    {
        var sampleLength = Math.Min(content.Length, 512);
        if (sampleLength < 4)
        {
            return false;
        }

        var zeros = 0;
        for (var index = 1; index < sampleLength; index += 2)
        {
            if (content[index] == 0)
            {
                zeros++;
            }
        }

        return zeros > sampleLength / 4;
    }
}
