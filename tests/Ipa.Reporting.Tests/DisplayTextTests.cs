using Ipa.Contracts;
using Ipa.Contracts.Reporting;
using Ipa.Contracts.Text;
using Ipa.Reporting.Html;
using Xunit;

namespace Ipa.Reporting.Tests;

/// <summary>
/// Labels shown to a reader are derived from identifiers, so the derivation is checked here: the
/// report, the interface and the generated rule catalogue all name a thing through this one path.
/// </summary>
public sealed class DisplayTextTests
{
    [Theory]
    [InlineData("AdPrivilegedAccess", "AD privileged access")]
    [InlineData("AdDelegationAndAcl", "AD delegation and ACL")]
    [InlineData("IsoReadiness", "ISO readiness")]
    [InlineData("EntraSecureScore", "Entra secure score")]
    [InlineData("HybridIdentityCorrelation", "Hybrid identity correlation")]
    [InlineData("Cover", "Cover")]
    public void IdentifiersBecomeReadableLabels(string identifier, string expected) =>
        Assert.Equal(expected, DisplayText.Humanise(identifier));

    [Fact]
    public void TheComposerUsesTheSameDerivation() =>
        Assert.Equal(
            DisplayText.Humanise(nameof(CheckGroup.AdDelegationAndAcl)),
            HtmlReportComposer.SplitCamelCase(nameof(CheckGroup.AdDelegationAndAcl)));

    [Fact]
    public void EveryCheckGroupAndReportSectionProducesALabel()
    {
        // An abbreviation left as an ordinary word is the failure this guards against, so the
        // assertion is that nothing comes back containing a bare "Ad", "Acl" or "Iso" word.
        var identifiers = Enum.GetValues<CheckGroup>().Select(group => group.ToString())
            .Concat(Enum.GetValues<ReportSection>().Select(section => section.ToString()));

        foreach (var identifier in identifiers)
        {
            var label = DisplayText.Humanise(identifier);

            Assert.NotEmpty(label);

            Assert.DoesNotContain(
                label.Split(' '),
                word => word is "Ad" or "ad" or "Acl" or "acl" or "Iso" or "iso");
        }
    }
}
