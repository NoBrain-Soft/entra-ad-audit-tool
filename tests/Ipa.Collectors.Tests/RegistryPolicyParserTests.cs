using System.Buffers.Binary;
using System.Text;
using Ipa.Collectors.ActiveDirectory.GroupPolicy;
using Xunit;

namespace Ipa.Collectors.Tests;

/// <summary>
/// Golden tests for the registry policy parser. The fixtures are built byte by byte from the
/// documented format so that the expectations do not depend on any platform tooling.
/// </summary>
public sealed class RegistryPolicyParserTests
{
    /// <summary>Builds a policy file containing the supplied records.</summary>
    private static byte[] BuildFile(params (string Key, string Value, int Type, byte[] Data)[] records)
    {
        using var stream = new MemoryStream();
        stream.Write("PReg"u8);
        Span<byte> version = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(version, 1);
        stream.Write(version);

        foreach (var (key, value, type, data) in records)
        {
            WriteChar(stream, '[');
            WriteString(stream, key);
            WriteChar(stream, ';');
            WriteString(stream, value);
            WriteChar(stream, ';');
            WriteUInt32(stream, (uint)type);
            WriteChar(stream, ';');
            WriteUInt32(stream, (uint)data.Length);
            WriteChar(stream, ';');
            stream.Write(data);
            WriteChar(stream, ']');
        }

        return stream.ToArray();
    }

    private static void WriteChar(Stream stream, char value)
    {
        Span<byte> buffer = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void WriteString(Stream stream, string value)
    {
        stream.Write(Encoding.Unicode.GetBytes(value));
        WriteChar(stream, '\0');
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    private static byte[] Dword(uint value)
    {
        var buffer = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        return buffer;
    }

    [Fact]
    public void ParsesDwordValue()
    {
        var file = BuildFile((@"System\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity", 4, Dword(2)));

        var result = RegistryPolicyParser.Parse(file);

        var setting = Assert.Single(result.Settings);
        Assert.Equal(@"System\CurrentControlSet\Services\NTDS\Parameters", setting.KeyPath);
        Assert.Equal("LDAPServerIntegrity", setting.ValueName);
        Assert.Equal(4, setting.ValueType);
        Assert.Equal("2", setting.Value);
        Assert.True(setting.IsMachineScope);
        Assert.Empty(result.Notes);
    }

    [Fact]
    public void ParsesStringAndMultiStringValues()
    {
        var file = BuildFile(
            (@"Software\Policies\Test", "Banner", 1, Encoding.Unicode.GetBytes("Authorised users only\0")),
            (@"Software\Policies\Test", "List", 7, Encoding.Unicode.GetBytes("first\0second\0\0")));

        var result = RegistryPolicyParser.Parse(file);

        Assert.Equal(2, result.Settings.Count);
        Assert.Equal("Authorised users only", result.Settings[0].Value);
        Assert.Equal("first|second", result.Settings[1].Value);
    }

    [Fact]
    public void ParsesQwordAndBinaryValues()
    {
        var qword = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(qword, 4_294_967_296);

        var file = BuildFile(
            (@"Software\Test", "Big", 11, qword),
            (@"Software\Test", "Blob", 3, [0xDE, 0xAD, 0xBE, 0xEF]));

        var result = RegistryPolicyParser.Parse(file);

        Assert.Equal("4294967296", result.Settings[0].Value);
        Assert.Equal("DEADBEEF", result.Settings[1].Value);
    }

    [Fact]
    public void UserScopeIsRecordedWhenRequested()
    {
        var file = BuildFile((@"Software\Test", "Value", 4, Dword(1)));

        var result = RegistryPolicyParser.Parse(file, isMachineScope: false);

        Assert.False(Assert.Single(result.Settings).IsMachineScope);
    }

    [Fact]
    public void MissingSignatureIsReportedRatherThanThrown()
    {
        var result = RegistryPolicyParser.Parse("not a policy file"u8);

        Assert.Empty(result.Settings);
        Assert.Contains(result.Notes, note => note.Contains("PReg signature", StringComparison.Ordinal));
    }

    [Fact]
    public void EmptyFileIsHandled()
    {
        var result = RegistryPolicyParser.Parse(ReadOnlySpan<byte>.Empty);

        Assert.Empty(result.Settings);
        Assert.NotEmpty(result.Notes);
    }

    [Fact]
    public void TruncatedRecordStopsParsingAndKeepsEarlierSettings()
    {
        var complete = BuildFile(
            (@"Software\Test", "First", 4, Dword(1)),
            (@"Software\Test", "Second", 4, Dword(2)));

        // Cut the file inside the second record.
        var truncated = complete[..(complete.Length - 10)];

        var result = RegistryPolicyParser.Parse(truncated);

        Assert.Single(result.Settings);
        Assert.Equal("First", result.Settings[0].ValueName);
        Assert.NotEmpty(result.Notes);
    }

    [Fact]
    public void TrailingZeroPaddingIsNotReportedAsCorruption()
    {
        var file = BuildFile((@"Software\Test", "Value", 4, Dword(1)));
        var padded = file.Concat(new byte[16]).ToArray();

        var result = RegistryPolicyParser.Parse(padded);

        Assert.Single(result.Settings);
        Assert.Empty(result.Notes);
    }

    [Fact]
    public void DeclaredValueSizeBeyondTheFileIsRefused()
    {
        var file = BuildFile((@"Software\Test", "Value", 4, Dword(1))).ToList();

        // Rewrite the declared size to a value far beyond the remaining bytes.
        var sizeOffset = file.Count - 4 - 2 - 4; // data + closing bracket, back to the size field
        var inflated = BitConverter.GetBytes(1_000_000u);
        for (var index = 0; index < 4; index++)
        {
            file[sizeOffset + index] = inflated[index];
        }

        var result = RegistryPolicyParser.Parse(file.ToArray());

        Assert.Empty(result.Settings);
        Assert.NotEmpty(result.Notes);
    }

    [Fact]
    public void OversizedFileIsRefusedWithoutParsing()
    {
        var oversized = new byte[RegistryPolicyParser.MaxFileBytes + 1];

        var result = RegistryPolicyParser.Parse(oversized);

        Assert.Empty(result.Settings);
        Assert.Contains(result.Notes, note => note.Contains("limit", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ParsingIsDeterministic()
    {
        var file = BuildFile(
            (@"Software\A", "One", 4, Dword(1)),
            (@"Software\B", "Two", 1, Encoding.Unicode.GetBytes("value\0")));

        var first = RegistryPolicyParser.Parse(file);
        var second = RegistryPolicyParser.Parse(file);

        Assert.Equal(
            first.Settings.Select(setting => (setting.KeyPath, setting.ValueName, setting.Value)),
            second.Settings.Select(setting => (setting.KeyPath, setting.ValueName, setting.Value)));
    }
}
