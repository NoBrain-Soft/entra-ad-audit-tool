using System.Text;
using Ipa.Collectors.ActiveDirectory.GroupPolicy;
using Xunit;

namespace Ipa.Collectors.Tests;

/// <summary>
/// Tests for stored-credential detection in Group Policy Preferences. The scanner must report the
/// location without ever surfacing the stored value.
/// </summary>
public sealed class PreferenceCredentialScannerTests
{
    private const string GroupsWithPassword = """
        <?xml version="1.0" encoding="utf-8"?>
        <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
          <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)" uid="{1}">
            <Properties action="U" newName="" fullName="" description=""
              cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
              changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="Administrator"/>
          </User>
        </Groups>
        """;

    private const string GroupsWithoutPassword = """
        <?xml version="1.0" encoding="utf-8"?>
        <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
          <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)">
            <Properties action="U" newName="" description="" deleteAllUsers="0"/>
          </Group>
        </Groups>
        """;

    [Fact]
    public void StoredCredentialIsDetected()
    {
        var artifacts = PreferenceCredentialScanner.Scan(
            @"contoso.com\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml",
            Encoding.UTF8.GetBytes(GroupsWithPassword));

        var artifact = Assert.Single(artifacts);
        Assert.Equal("Administrator", artifact.AccountName);
        Assert.Contains("Groups/User/Properties", artifact.Element, StringComparison.Ordinal);
    }

    [Fact]
    public void TheStoredValueItselfIsNeverRecorded()
    {
        var artifacts = PreferenceCredentialScanner.Scan(
            "Groups.xml",
            Encoding.UTF8.GetBytes(GroupsWithPassword));

        var serialised = string.Join(
            '\n',
            artifacts.Select(artifact => $"{artifact.RelativePath}|{artifact.Element}|{artifact.AccountName}"));

        Assert.DoesNotContain("edBSHOwhZLTjt", serialised, StringComparison.Ordinal);
    }

    [Fact]
    public void CleanFileProducesNoFinding()
    {
        var artifacts = PreferenceCredentialScanner.Scan(
            "Groups.xml",
            Encoding.UTF8.GetBytes(GroupsWithoutPassword));

        Assert.Empty(artifacts);
    }

    [Fact]
    public void MalformedXmlIsHandledWithoutThrowing()
    {
        var artifacts = PreferenceCredentialScanner.Scan("Groups.xml", "<Groups><User "u8);

        Assert.Empty(artifacts);
    }

    [Fact]
    public void ExternalEntityDeclarationIsRefused()
    {
        // A document type declaration is prohibited outright, so an entity referencing a local file
        // is never resolved.
        const string hostile = """
            <?xml version="1.0"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <Groups><User><Properties cpassword="x" userName="&xxe;"/></User></Groups>
            """;

        var artifacts = PreferenceCredentialScanner.Scan("Groups.xml", Encoding.UTF8.GetBytes(hostile));

        Assert.Empty(artifacts);
    }

    [Fact]
    public void EmptyAndOversizedFilesAreSkipped()
    {
        Assert.Empty(PreferenceCredentialScanner.Scan("Groups.xml", ReadOnlySpan<byte>.Empty));
        Assert.Empty(PreferenceCredentialScanner.Scan(
            "Groups.xml",
            new byte[PreferenceCredentialScanner.MaxFileBytes + 1]));
    }

    [Fact]
    public void EveryKnownPreferenceFileIsScanned() =>
        Assert.Contains("ScheduledTasks.xml", PreferenceCredentialScanner.CandidateFileNames);
}
