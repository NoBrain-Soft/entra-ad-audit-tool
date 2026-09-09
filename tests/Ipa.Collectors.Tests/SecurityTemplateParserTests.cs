using System.Text;
using Ipa.Collectors.ActiveDirectory.GroupPolicy;
using Xunit;

namespace Ipa.Collectors.Tests;

/// <summary>Golden tests for the security template parser.</summary>
public sealed class SecurityTemplateParserTests
{
    private const string Sample = """
        [Unicode]
        Unicode=yes
        [System Access]
        MinimumPasswordLength = 14
        PasswordComplexity = 1
        ClearTextPassword = 0
        [Privilege Rights]
        SeDebugPrivilege = *S-1-5-32-544
        SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
        SeNetworkLogonRight = *S-1-1-0,CONTOSO\Operators
        [Version]
        signature="$CHICAGO$"
        """;

    [Fact]
    public void ParsesSectionsAndValues()
    {
        var result = SecurityTemplateParser.Parse(Sample);

        Assert.Contains(result.Settings, setting =>
            setting.Section == "System Access"
            && setting.Name == "MinimumPasswordLength"
            && setting.Value == "14");

        Assert.Contains(result.Settings, setting =>
            setting.Section == "Version" && setting.Name == "signature");
    }

    [Fact]
    public void PrivilegeRightsResolveTrustees()
    {
        var result = SecurityTemplateParser.Parse(Sample);

        var backup = result.Settings.Single(setting => setting.Name == "SeBackupPrivilege");

        Assert.Equal(["S-1-5-32-544", "S-1-5-32-551"], backup.Trustees);
    }

    [Fact]
    public void NamedTrusteesArePreservedVerbatimForOperatorResolution()
    {
        var result = SecurityTemplateParser.Parse(Sample);

        var logon = result.Settings.Single(setting => setting.Name == "SeNetworkLogonRight");

        Assert.Equal(["S-1-1-0", @"CONTOSO\Operators"], logon.Trustees);
    }

    [Fact]
    public void ScalarSectionsCarryNoTrustees()
    {
        var result = SecurityTemplateParser.Parse(Sample);

        var length = result.Settings.Single(setting => setting.Name == "MinimumPasswordLength");

        Assert.Empty(length.Trustees);
    }

    [Fact]
    public void CommentsAndBlankLinesAreIgnored()
    {
        var text = "; a comment\n\n[System Access]\n# another comment\nMinimumPasswordLength = 8\n";

        var result = SecurityTemplateParser.Parse(text);

        Assert.Single(result.Settings);
    }

    [Fact]
    public void LinesWithoutASeparatorAreNoted()
    {
        var result = SecurityTemplateParser.Parse("[System Access]\nnot a pair\n");

        Assert.Empty(result.Settings);
        Assert.NotEmpty(result.Notes);
    }

    [Fact]
    public void Utf16LittleEndianWithBomIsDecoded()
    {
        var bytes = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(Sample)).ToArray();

        var result = SecurityTemplateParser.Parse(bytes);

        Assert.Contains(result.Settings, setting => setting.Name == "MinimumPasswordLength");
    }

    [Fact]
    public void Utf16WithoutBomIsDetectedByContent()
    {
        var bytes = Encoding.Unicode.GetBytes(Sample);

        var result = SecurityTemplateParser.Parse(bytes);

        Assert.Contains(result.Settings, setting => setting.Name == "PasswordComplexity");
    }

    [Fact]
    public void Utf8WithBomIsDecoded()
    {
        var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(Sample)).ToArray();

        var result = SecurityTemplateParser.Parse(bytes);

        Assert.Contains(result.Settings, setting => setting.Name == "ClearTextPassword");
    }

    [Fact]
    public void OversizedTemplateIsRefused()
    {
        var result = SecurityTemplateParser.Parse(new byte[SecurityTemplateParser.MaxFileBytes + 1]);

        Assert.Empty(result.Settings);
        Assert.NotEmpty(result.Notes);
    }

    [Fact]
    public void EmptyTrusteeListYieldsNoEntries() =>
        Assert.Empty(SecurityTemplateParser.ParseTrustees(string.Empty));

    [Fact]
    public void ParsingIsDeterministic()
    {
        var first = SecurityTemplateParser.Parse(Sample);
        var second = SecurityTemplateParser.Parse(Sample);

        Assert.Equal(
            first.Settings.Select(setting => (setting.Section, setting.Name, setting.Value)),
            second.Settings.Select(setting => (setting.Section, setting.Name, setting.Value)));
    }
}
