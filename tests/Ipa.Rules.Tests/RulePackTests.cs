using Ipa.Contracts;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Xunit;

namespace Ipa.Rules.Tests;

/// <summary>Structural checks that every rule in the shipped pack satisfies the pack contract.</summary>
public sealed class RulePackTests
{
    private static readonly IRulePack Pack = FirstPartyRulePack.Current;

    [Fact]
    public void PackValidatesOnLoad()
    {
        // Construction runs RulePackValidator; reaching this point means the pack is well formed.
        Assert.NotEmpty(Pack.Rules);
        Assert.Equal(Pack.Rules.Count, Pack.Definitions.Count);
        Assert.False(string.IsNullOrWhiteSpace(Pack.Version));
    }

    [Fact]
    public void RuleIdentifiersAreUnique()
    {
        var duplicates = Pack.Definitions
            .GroupBy(definition => definition.Id.Value, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToList();

        Assert.Empty(duplicates);
    }

    [Fact]
    public void WeightsNeverExceedTheirSeverityBand()
    {
        foreach (var definition in Pack.Definitions)
        {
            Assert.InRange(definition.Weight, 0, SeverityWeights.Maximum(definition.Severity));
        }
    }

    [Fact]
    public void InformationalRulesCarryNoWeight()
    {
        foreach (var definition in Pack.Definitions.Where(d => d.Severity == RuleSeverity.Informational))
        {
            Assert.Equal(0, definition.Weight);
        }
    }

    [Fact]
    public void EveryRuleDeclaresRemediationAndRationale()
    {
        foreach (var definition in Pack.Definitions)
        {
            Assert.False(string.IsNullOrWhiteSpace(definition.Remediation), definition.Id.Value);
            Assert.False(string.IsNullOrWhiteSpace(definition.Rationale), definition.Id.Value);
            Assert.False(string.IsNullOrWhiteSpace(definition.Title), definition.Id.Value);
        }
    }

    [Fact]
    public void EveryRuleDeclaresAtLeastOneEvidenceRequirement()
    {
        foreach (var definition in Pack.Definitions)
        {
            Assert.NotEmpty(definition.RequiredEvidence);
        }
    }

    [Fact]
    public void MetricsThatMustNotBeDoubleCountedAreInformational()
    {
        var excluded = Pack.Definitions
            .Where(definition => definition.Group is CheckGroup.BaselineConformity or CheckGroup.EntraSecureScore)
            .ToList();

        Assert.NotEmpty(excluded);
        Assert.All(excluded, definition => Assert.Equal(RuleSeverity.Informational, definition.Severity));
    }

    [Fact]
    public void EveryDomainIsCovered()
    {
        foreach (var domain in Enum.GetValues<RuleDomain>())
        {
            Assert.Contains(Pack.Definitions, definition => definition.Domain == domain);
        }
    }

    [Fact]
    public void EveryCheckGroupHasAtLeastOneRule()
    {
        foreach (var group in Enum.GetValues<CheckGroup>())
        {
            Assert.Contains(Pack.Definitions, definition => definition.Group == group);
        }
    }
}
