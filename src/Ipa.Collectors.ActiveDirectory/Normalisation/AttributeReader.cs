using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Text;
using Ipa.Contracts.Security;

namespace Ipa.Collectors.ActiveDirectory.Discovery;

/// <summary>
/// Reads attributes from a directory search result into normalised .NET types. Attribute values
/// that carry credential material are never returned in raw form: the reader consults the
/// redaction list before producing any string.
/// </summary>
public static class AttributeReader
{
    /// <summary>Windows file-time value meaning "never".</summary>
    public const long NeverFileTime = 0x7FFFFFFFFFFFFFFF;

    /// <summary>Returns a single string attribute, or null when it is absent or sensitive.</summary>
    public static string? GetString(SearchResultEntry entry, string attributeName)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (Redaction.IsSensitiveAttribute(attributeName))
        {
            return entry.Attributes.Contains(attributeName) ? Redaction.Placeholder : null;
        }

        if (!entry.Attributes.Contains(attributeName))
        {
            return null;
        }

        var attribute = entry.Attributes[attributeName];
        return attribute.Count == 0 ? null : attribute[0] as string ?? DecodeUtf8(attribute[0]);
    }

    /// <summary>Returns every value of a multi-valued string attribute.</summary>
    public static IReadOnlyList<string> GetStrings(SearchResultEntry entry, string attributeName)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (Redaction.IsSensitiveAttribute(attributeName) || !entry.Attributes.Contains(attributeName))
        {
            return [];
        }

        var attribute = entry.Attributes[attributeName];
        var values = new List<string>(attribute.Count);

        for (var index = 0; index < attribute.Count; index++)
        {
            var value = attribute[index] as string ?? DecodeUtf8(attribute[index]);
            if (value is not null)
            {
                values.Add(value);
            }
        }

        return values;
    }

    /// <summary>Returns an integer attribute, or null when it is absent or unparsable.</summary>
    public static int? GetInt32(SearchResultEntry entry, string attributeName) =>
        int.TryParse(GetString(entry, attributeName), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;

    /// <summary>Returns a long attribute, or null when it is absent or unparsable.</summary>
    public static long? GetInt64(SearchResultEntry entry, string attributeName) =>
        long.TryParse(GetString(entry, attributeName), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;

    /// <summary>Returns the raw bytes of a binary attribute.</summary>
    public static byte[]? GetBytes(SearchResultEntry entry, string attributeName)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (Redaction.IsSensitiveAttribute(attributeName) || !entry.Attributes.Contains(attributeName))
        {
            return null;
        }

        var attribute = entry.Attributes[attributeName];
        return attribute.Count == 0 ? null : attribute[0] as byte[];
    }

    /// <summary>
    /// Converts a directory timestamp stored as a Windows file time. Zero and the "never" sentinel
    /// both return null, because both mean the event has not happened.
    /// </summary>
    public static DateTimeOffset? GetFileTime(SearchResultEntry entry, string attributeName)
    {
        var raw = GetInt64(entry, attributeName);

        if (raw is null or 0 or NeverFileTime || raw < 0)
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromFileTime(raw.Value).ToUniversalTime();
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>
    /// Converts a directory interval stored as a negative hundred-nanosecond file-time span, such
    /// as the maximum password age. Values meaning "never" return <see cref="TimeSpan.Zero"/>.
    /// </summary>
    public static TimeSpan GetNegativeInterval(SearchResultEntry entry, string attributeName)
    {
        var raw = GetInt64(entry, attributeName);

        if (raw is null || raw == 0 || raw == long.MinValue)
        {
            return TimeSpan.Zero;
        }

        var ticks = Math.Abs(raw.Value);
        return ticks > TimeSpan.MaxValue.Ticks ? TimeSpan.Zero : TimeSpan.FromTicks(ticks);
    }

    /// <summary>Parses a generalised time value of the form <c>yyyyMMddHHmmss.fZ</c>.</summary>
    public static DateTimeOffset? GetGeneralizedTime(SearchResultEntry entry, string attributeName)
    {
        var raw = GetString(entry, attributeName);

        if (string.IsNullOrWhiteSpace(raw) || raw.Length < 14)
        {
            return null;
        }

        return DateTimeOffset.TryParseExact(
            raw[..14],
            "yyyyMMddHHmmss",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : null;
    }

    /// <summary>Converts a binary security identifier attribute into its string form.</summary>
    public static string? GetSid(SearchResultEntry entry, string attributeName)
    {
        var bytes = GetBytes(entry, attributeName);
        return bytes is null ? null : SidConverter.ToString(bytes);
    }

    /// <summary>Converts every value of a multi-valued binary security identifier attribute.</summary>
    public static IReadOnlyList<string> GetSids(SearchResultEntry entry, string attributeName)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (!entry.Attributes.Contains(attributeName))
        {
            return [];
        }

        var attribute = entry.Attributes[attributeName];
        var values = new List<string>(attribute.Count);

        for (var index = 0; index < attribute.Count; index++)
        {
            if (attribute[index] is byte[] bytes)
            {
                var sid = SidConverter.ToString(bytes);
                if (sid is not null)
                {
                    values.Add(sid);
                }
            }
        }

        return values;
    }

    private static string? DecodeUtf8(object? value) =>
        value is byte[] bytes ? Encoding.UTF8.GetString(bytes) : value?.ToString();
}

/// <summary>
/// Converts binary security identifiers to their canonical string form. The conversion is
/// implemented here rather than through a platform type so that Windows and Linux produce
/// identical normalised evidence.
/// </summary>
public static class SidConverter
{
    /// <summary>Converts a binary security identifier to the form <c>S-1-5-21-...</c>.</summary>
    public static string? ToString(ReadOnlySpan<byte> sid)
    {
        if (sid.Length < 8)
        {
            return null;
        }

        var revision = sid[0];
        var subAuthorityCount = sid[1];

        if (sid.Length < 8 + (subAuthorityCount * 4))
        {
            return null;
        }

        // The identifier authority is a six-byte big-endian value.
        long authority = 0;
        for (var index = 2; index < 8; index++)
        {
            authority = (authority << 8) | sid[index];
        }

        var builder = new StringBuilder(64);
        builder.Append("S-").Append(revision).Append('-').Append(authority);

        for (var index = 0; index < subAuthorityCount; index++)
        {
            var offset = 8 + (index * 4);
            var subAuthority = (uint)(sid[offset]
                                      | (sid[offset + 1] << 8)
                                      | (sid[offset + 2] << 16)
                                      | (sid[offset + 3] << 24));

            builder.Append('-').Append(subAuthority);
        }

        return builder.ToString();
    }

    /// <summary>Converts a canonical security identifier string back to its binary form.</summary>
    public static byte[]? ToBytes(string sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return null;
        }

        var parts = sid.Split('-');
        if (parts.Length < 3 || !parts[0].Equals("S", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!byte.TryParse(parts[1], out var revision)
            || !long.TryParse(parts[2], out var authority))
        {
            return null;
        }

        var subAuthorities = new uint[parts.Length - 3];
        for (var index = 0; index < subAuthorities.Length; index++)
        {
            if (!uint.TryParse(parts[index + 3], out subAuthorities[index]))
            {
                return null;
            }
        }

        var bytes = new byte[8 + (subAuthorities.Length * 4)];
        bytes[0] = revision;
        bytes[1] = (byte)subAuthorities.Length;

        for (var index = 0; index < 6; index++)
        {
            bytes[2 + index] = (byte)(authority >> ((5 - index) * 8));
        }

        for (var index = 0; index < subAuthorities.Length; index++)
        {
            var offset = 8 + (index * 4);
            var value = subAuthorities[index];
            bytes[offset] = (byte)value;
            bytes[offset + 1] = (byte)(value >> 8);
            bytes[offset + 2] = (byte)(value >> 16);
            bytes[offset + 3] = (byte)(value >> 24);
        }

        return bytes;
    }
}
