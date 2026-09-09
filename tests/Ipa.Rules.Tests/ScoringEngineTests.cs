using Ipa.Contracts;
using Ipa.Contracts.Rules;
using Ipa.Contracts.Scoring;
using Ipa.Rules.Engine;
using Ipa.Rules.Scoring;
using Xunit;

namespace Ipa.Rules.Tests;

/// <summary>Verifies the documented scoring semantics exactly, including the exclusion rules.</summary>
public sealed class ScoringEngineTests
{
    private static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static RuleDefinition Definition(
        string id,
        RuleSeverity severity,
        RuleDomain domain = RuleDomain.ActiveDirectory,
        CheckGroup group = CheckGroup.AdPrivilegedAccess,
        int? weight = null) =>
        RuleFactory.Create(
            id: id,
            version: 1,
            title: id,
            domain: domain,
            group: group,
            severity: severity,
            rationale: "test rationale",
            remediation: "test remediation",
            evidenceKeys: [Contracts.Evidence.EvidenceKeys.AdUsers],
            weight: weight);

    private static RuleResult Result(string id, RuleStatus status) => new()
    {
        RuleId = new RuleId(id),
        RuleVersion = 1,
        Status = status,
        EvaluatedAt = Reference,
        Rationale = status.ToString(),
    };

    [Fact]
    public void PassEarnsFullWeightAndFailEarnsZero()
    {
        var definitions = new[]
        {
            Definition("R1", RuleSeverity.Critical), // weight 10
            Definition("R2", RuleSeverity.High),     // weight 6
        };

        var results = new[] { Result("R1", RuleStatus.Pass), Result("R2", RuleStatus.Fail) };

        var scores = new ScoringEngine().Compute(definitions, results, "test", Reference);

        Assert.Equal(10, scores.Overall.PassedWeight);
        Assert.Equal(16, scores.Overall.EvaluatedWeight);
        Assert.Equal(63, scores.Overall.Value); // 10/16 = 62.5, rounded away from zero
    }

    [Fact]
    public void NotApplicableIsExcludedFromScoreAndCoverage()
    {
        var definitions = new[]
        {
            Definition("R1", RuleSeverity.Critical),
            Definition("R2", RuleSeverity.Critical),
        };

        var results = new[] { Result("R1", RuleStatus.Pass), Result("R2", RuleStatus.NotApplicable) };

        var scores = new ScoringEngine().Compute(definitions, results, "test", Reference);

        Assert.Equal(100, scores.Overall.Value);
        Assert.Equal(1d, scores.Overall.Coverage);
        Assert.Equal(1, scores.Overall.NotApplicableCount);
    }

    [Fact]
    public void NotCollectedAndErrorLeaveTheScoreButReduceCoverage()
    {
        var definitions = new[]
        {
            Definition("R1", RuleSeverity.Critical), // 10, passes
            Definition("R2", RuleSeverity.High),     // 6, not collected
            Definition("R3", RuleSeverity.Medium),   // 3, error
        };

        var results = new[]
        {
            Result("R1", RuleStatus.Pass),
            Result("R2", RuleStatus.NotCollected),
            Result("R3", RuleStatus.Error),
        };

        var scores = new ScoringEngine().Compute(definitions, results, "test", Reference);

        Assert.Equal(100, scores.Overall.Value);
        Assert.Equal(10, scores.Overall.EvaluatedWeight);
        Assert.Equal(6, scores.Overall.NotCollectedWeight);
        Assert.Equal(3, scores.Overall.ErrorWeight);
        Assert.Equal(10d / 19d, scores.Overall.Coverage, 6);
    }

    [Fact]
    public void CoverageBelowNinetyPercentMarksTheScoreProvisional()
    {
        var definitions = new[]
        {
            Definition("R1", RuleSeverity.Critical), // 10 evaluated
            Definition("R2", RuleSeverity.Medium),   // 3 not collected -> coverage 10/13 = 77%
        };

        var results = new[] { Result("R1", RuleStatus.Pass), Result("R2", RuleStatus.NotCollected) };

        var scores = new ScoringEngine().Compute(definitions, results, "test", Reference);

        Assert.True(scores.Overall.IsProvisional);
        Assert.Equal(77, scores.Overall.CoveragePercent);
    }

    [Fact]
    public void CoverageAtExactlyNinetyPercentIsNotProvisional()
    {
        // Nine critical rules evaluated (90 weight) and one low rule not collected (10 weight)
        // gives exactly 0.9 coverage, which is the inclusive threshold.
        var definitions = Enumerable.Range(1, 9)
            .Select(index => Definition($"R{index}", RuleSeverity.Critical))
            .Append(Definition("RX", RuleSeverity.Critical))
            .ToArray();

        var results = Enumerable.Range(1, 9)
            .Select(index => Result($"R{index}", RuleStatus.Pass))
            .Append(Result("RX", RuleStatus.NotCollected))
            .ToArray();

        var scores = new ScoringEngine().Compute(definitions, results, "test", Reference);

        Assert.Equal(0.9d, scores.Overall.Coverage, 6);
        Assert.False(scores.Overall.IsProvisional);
    }

    [Fact]
    public void InformationalRulesDoNotAffectTheScore()
    {
        var definitions = new[]
        {
            Definition("R1", RuleSeverity.Critical),
            Definition("R2", RuleSeverity.Informational),
        };

        var results = new[] { Result("R1", RuleStatus.Fail), Result("R2", RuleStatus.Pass) };

        var scores = new ScoringEngine().Compute(definitions, results, "test", Reference);

        Assert.Equal(0, scores.Overall.Value);
        Assert.Equal(10, scores.Overall.EvaluatedWeight);
    }

    [Fact]
    public void BaselineAndSecureScoreGroupsAreExcludedFromPosture()
    {
        var definitions = new[]
        {
            Definition("R1", RuleSeverity.Critical),
            Definition("BAS-X", RuleSeverity.Informational, group: CheckGroup.BaselineConformity),
            Definition("SS-X", RuleSeverity.Informational, RuleDomain.Entra, CheckGroup.EntraSecureScore),
        };

        var results = new[]
        {
            Result("R1", RuleStatus.Pass),
            Result("BAS-X", RuleStatus.Pass),
            Result("SS-X", RuleStatus.NotCollected),
        };

        var scores = new ScoringEngine().Compute(definitions, results, "test", Reference);

        Assert.DoesNotContain(CheckGroup.BaselineConformity, scores.ByGroup.Keys);
        Assert.DoesNotContain(CheckGroup.EntraSecureScore, scores.ByGroup.Keys);
        Assert.Equal(1d, scores.Overall.Coverage);
    }

    [Fact]
    public void ScoresArePartitionedByDomainAndGroup()
    {
        var definitions = new[]
        {
            Definition("AD1", RuleSeverity.High, RuleDomain.ActiveDirectory, CheckGroup.AdPrivilegedAccess),
            Definition("EID1", RuleSeverity.High, RuleDomain.Entra, CheckGroup.EntraPrivilegedAccess),
            Definition("HYB1", RuleSeverity.High, RuleDomain.Hybrid, CheckGroup.HybridPrivilegeExposure),
        };

        var results = new[]
        {
            Result("AD1", RuleStatus.Pass),
            Result("EID1", RuleStatus.Fail),
            Result("HYB1", RuleStatus.Pass),
        };

        var scores = new ScoringEngine().Compute(definitions, results, "test", Reference);

        Assert.Equal(100, scores.ByDomain[RuleDomain.ActiveDirectory].Value);
        Assert.Equal(0, scores.ByDomain[RuleDomain.Entra].Value);
        Assert.Equal(100, scores.ByDomain[RuleDomain.Hybrid].Value);
        Assert.Equal(3, scores.ByGroup.Count);
    }

    [Fact]
    public void ScoreIsNullWhenNothingCouldBeEvaluated()
    {
        var definitions = new[] { Definition("R1", RuleSeverity.Critical) };
        var results = new[] { Result("R1", RuleStatus.NotCollected) };

        var scores = new ScoringEngine().Compute(definitions, results, "test", Reference);

        Assert.Null(scores.Overall.Value);
        Assert.True(scores.Overall.IsProvisional);
    }

    [Fact]
    public void ProviderAndBaselineMetricsAreReportedSeparately()
    {
        var definitions = new[] { Definition("R1", RuleSeverity.Critical) };
        var results = new[] { Result("R1", RuleStatus.Pass) };

        var secureScore = new Contracts.Evidence.SecureScoreSnapshot
        {
            CreatedDateTime = Reference,
            CurrentScore = 45,
            MaxScore = 90,
        };

        var comparison = new Contracts.Baselines.BaselineComparison
        {
            BaselineId = "b1",
            ProductName = "Windows Server 2022",
            BaselineVersion = "September 2024",
            PackageSha256 = new string('a', 64),
            ComparedAt = Reference,
            Rows =
            [
                new Contracts.Baselines.BaselineComparisonRow
                {
                    SettingKey = "k", DisplayName = "d", ExpectedValue = "1",
                    Outcome = Contracts.Baselines.BaselineComparisonOutcome.Match,
                },
            ],
        };

        var scores = new ScoringEngine().Compute(
            definitions, results, "test", Reference, secureScore, comparison);

        Assert.Equal(100, scores.Overall.Value);
        Assert.NotNull(scores.MicrosoftSecureScore);
        Assert.Equal(50, scores.MicrosoftSecureScore!.Percent);
        Assert.NotNull(scores.BaselineConformity);
        Assert.Equal(100, scores.BaselineConformity!.ConformityPercent);
    }

    [Fact]
    public void ProvisionalThresholdIsNinetyPercent() =>
        Assert.Equal(0.90d, ScoringConstants.ProvisionalCoverageThreshold);
}
