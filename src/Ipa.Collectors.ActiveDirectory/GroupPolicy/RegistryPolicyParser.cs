using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.GroupPolicy;

/// <summary>
/// Parses the binary <c>registry.pol</c> format used by Group Policy and by the registry policy
/// files inside a Microsoft security baseline. The parser is fully managed and byte-oriented so
/// that it produces identical results on Windows and Linux.
/// </summary>
/// <remarks>
/// The file begins with the signature <c>PReg</c> followed by a little-endian version word. Each
/// entry is then written as <c>[key;value;type;size;data]</c> where the brackets, semicolons and
/// strings are UTF-16 little-endian and strings are null terminated.
/// </remarks>
public static class RegistryPolicyParser
{
    /// <summary>File signature: the ASCII characters <c>PReg</c>.</summary>
    private static readonly byte[] Signature = [0x50, 0x52, 0x65, 0x67];

    /// <summary>Largest file the parser will accept, guarding against hostile input.</summary>
    public const int MaxFileBytes = 32 * 1024 * 1024;

    /// <summary>Largest single value the parser will accept.</summary>
    public const int MaxValueBytes = 1 * 1024 * 1024;

    // Registry value types, as written into the policy file.
    private const int RegSz = 1;
    private const int RegExpandSz = 2;
    private const int RegBinary = 3;
    private const int RegDword = 4;
    private const int RegDwordBigEndian = 5;
    private const int RegMultiSz = 7;
    private const int RegQword = 11;

    /// <summary>Result of parsing one policy file.</summary>
    /// <param name="Settings">Settings recovered from the file, in file order.</param>
    /// <param name="Notes">Diagnostics describing entries that were skipped.</param>
    public readonly record struct ParseResult(
        IReadOnlyList<RegistryPolicySetting> Settings,
        IReadOnlyList<string> Notes);

    /// <summary>Parses a policy file. Malformed trailing data is reported rather than thrown.</summary>
    /// <param name="content">Raw file bytes.</param>
    /// <param name="isMachineScope">True for the machine hive, false for the user hive.</param>
    public static ParseResult Parse(ReadOnlySpan<byte> content, bool isMachineScope = true)
    {
        var settings = new List<RegistryPolicySetting>();
        var notes = new List<string>();

        if (content.Length > MaxFileBytes)
        {
            return new ParseResult([], [$"The policy file exceeds the {MaxFileBytes} byte limit and was not parsed."]);
        }

        if (content.Length < 8 || !content[..4].SequenceEqual(Signature))
        {
            return new ParseResult([], ["The file does not start with the expected PReg signature."]);
        }

        var version = BinaryPrimitives.ReadUInt32LittleEndian(content[4..8]);
        if (version != 1)
        {
            notes.Add($"Unexpected policy file version {version}; parsing continued.");
        }

        var offset = 8;

        while (offset < content.Length)
        {
            // Each record opens with '[' encoded as UTF-16 little-endian.
            if (!TryReadChar(content, ref offset, '['))
            {
                if (IsOnlyPadding(content[offset..]))
                {
                    break;
                }

                notes.Add($"Stopped parsing at byte {offset}: expected the start of a record.");
                break;
            }

            if (!TryReadString(content, ref offset, out var keyPath)
                || !TryReadChar(content, ref offset, ';')
                || !TryReadString(content, ref offset, out var valueName)
                || !TryReadChar(content, ref offset, ';')
                || !TryReadUInt32(content, ref offset, out var valueType)
                || !TryReadChar(content, ref offset, ';')
                || !TryReadUInt32(content, ref offset, out var valueSize)
                || !TryReadChar(content, ref offset, ';'))
            {
                notes.Add($"Stopped parsing at byte {offset}: the record header is truncated or malformed.");
                break;
            }

            if (valueSize > MaxValueBytes)
            {
                notes.Add($"Skipped '{keyPath}\\{valueName}': the value of {valueSize} bytes exceeds the limit.");
                break;
            }

            if (offset + (int)valueSize > content.Length)
            {
                notes.Add($"Stopped parsing at byte {offset}: the value data is truncated.");
                break;
            }

            var data = content.Slice(offset, (int)valueSize);
            offset += (int)valueSize;

            if (!TryReadChar(content, ref offset, ']'))
            {
                notes.Add($"Stopped parsing at byte {offset}: the record is not terminated.");
                break;
            }

            settings.Add(new RegistryPolicySetting
            {
                KeyPath = keyPath,
                ValueName = valueName,
                ValueType = (int)valueType,
                Value = RenderValue((int)valueType, data),
                IsMachineScope = isMachineScope,
            });
        }

        return new ParseResult(settings, notes);
    }

    /// <summary>Renders a registry value into the canonical string form used for comparison.</summary>
    public static string RenderValue(int valueType, ReadOnlySpan<byte> data) => valueType switch
    {
        RegDword when data.Length >= 4 =>
            BinaryPrimitives.ReadUInt32LittleEndian(data).ToString(CultureInfo.InvariantCulture),

        RegDwordBigEndian when data.Length >= 4 =>
            BinaryPrimitives.ReadUInt32BigEndian(data).ToString(CultureInfo.InvariantCulture),

        RegQword when data.Length >= 8 =>
            BinaryPrimitives.ReadUInt64LittleEndian(data).ToString(CultureInfo.InvariantCulture),

        RegSz or RegExpandSz => DecodeString(data),

        RegMultiSz => string.Join(
            "|",
            DecodeString(data).Split('\0', StringSplitOptions.RemoveEmptyEntries)),

        RegBinary => Convert.ToHexString(data),

        _ => data.IsEmpty ? string.Empty : Convert.ToHexString(data),
    };

    private static string DecodeString(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return string.Empty;
        }

        var text = Encoding.Unicode.GetString(data);
        return text.TrimEnd('\0');
    }

    private static bool TryReadChar(ReadOnlySpan<byte> content, ref int offset, char expected)
    {
        if (offset + 2 > content.Length)
        {
            return false;
        }

        var value = (char)BinaryPrimitives.ReadUInt16LittleEndian(content[offset..]);
        if (value != expected)
        {
            return false;
        }

        offset += 2;
        return true;
    }

    private static bool TryReadString(ReadOnlySpan<byte> content, ref int offset, out string value)
    {
        value = string.Empty;
        var start = offset;

        while (offset + 2 <= content.Length)
        {
            var unit = BinaryPrimitives.ReadUInt16LittleEndian(content[offset..]);
            if (unit == 0)
            {
                value = Encoding.Unicode.GetString(content[start..offset]);
                offset += 2;
                return true;
            }

            offset += 2;
        }

        offset = start;
        return false;
    }

    private static bool TryReadUInt32(ReadOnlySpan<byte> content, ref int offset, out uint value)
    {
        value = 0;

        if (offset + 4 > content.Length)
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(content[offset..]);
        offset += 4;
        return true;
    }

    /// <summary>True when the remaining bytes are zero padding rather than a truncated record.</summary>
    private static bool IsOnlyPadding(ReadOnlySpan<byte> remaining)
    {
        foreach (var value in remaining)
        {
            if (value != 0)
            {
                return false;
            }
        }

        return true;
    }
}
