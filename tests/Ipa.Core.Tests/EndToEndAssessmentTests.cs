using Ipa.Contracts;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Core.Assessment;
using Ipa.Core.Tests.Fixtures;
using Xunit;

namespace Ipa.Core.Tests;

/// <summary>
/// End-to-end evaluation over the synthetic environments: the healthy forest and tenant should pass
/// the rules that apply to them, the weak ones should fail, and both runs must be reproducible.
/// </summary>
public sealed class EndToEndAssessmentTests
{
    private static readonly AssessmentService Service = new();

    private static AssessmentSession Session(
        ActiveDirectoryEvidence? forest,
        EntraEvidence? tenant,
        params CheckGroup[] groups)
    {
        var scope = new AssessmentScope
        {
            IncludeActiveDirectory = forest is not null,
            IncludeEntra = tenant is not null,
            SelectedGroups = groups.Length > 0 ? groups : Enum.GetValues<CheckGroup>(),
        };

        var availability = new Dictionary<string, EvidenceAvailabilityEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (var key in EvidenceKeys.All)
        {
            var applies =
                (forest is not null && key.StartsWith("ad.", StringComparison.Ordinal))
                || (tenant is not null && key.StartsWith("entra.", StringComparison.Ordinal));

            availability[key] = new EvidenceAvailabilityEntry
            {
                EvidenceKey = key,
                Availability = applies ? EvidenceAvailability.Collected : EvidenceAvailability.NotSelected,
                Reason = applies ? null : "The source was not part of this assessment.",
            };
        }

        return new AssessmentSession
        {
            AssessmentId = Guid.NewGuid(),
            Metadata = new AssessmentMetadata { CustomerName = "Contoso", AssessorName = "Assessor" },
            Scope = scope,
            CreatedAt = SyntheticEnvironment.Reference,
            ReferenceTime = SyntheticEnvironment.Reference,
            Evidence = new NormalizedEvidence
            {
                ActiveDirectory = forest,
                Entra = tenant,
                Availability = availability,
                ReferenceTime = SyntheticEnvironment.Reference,
            },
        };
    }

    [Fact]
    public void HealthyEnvironmentScoresWell()
    {
        var session = Session(SyntheticEnvironment.HealthyForest(), SyntheticEnvironment.HealthyTenant());

        var outcome = Service.Evaluate(session);

        var failures = outcome.Results.Where(result => result.Status == RuleStatus.Fail).ToList();

        Assert.NotNull(outcome.Scores.Overall.Value);
        Assert.True(
            outcome.Scores.Overall.Value >= 70,
            $"Expected a high score for the healthy environment but scored {outcome.Scores.Overall.Value}. " +
            $"Failures: {string.Join(", ", failures.Select(failure => failure.RuleId.Value))}");
    }

    [Fact]
    public void WeakEnvironmentScoresPoorly()
    {
        var session = Session(SyntheticEnvironment.WeakForest(), SyntheticEnvironment.WeakTenant());

        var outcome = Service.Evaluate(session);

        Assert.NotNull(outcome.Scores.Overall.Value);
        Assert.True(
            outcome.Scores.Overall.Value <= 40,
            $"Expected a low score for the weak environment but scored {outcome.Scores.Overall.Value}.");

        Assert.NotEmpty(outcome.Findings);
    }

    [Theory]
    [InlineData("AD-PRIV-003")] // Kerberoastable tier-zero account
    [InlineData("AD-ACCT-003")] // Password not required
    [InlineData("AD-ACCT-004")] // Pre-authentication not required
    [InlineData("AD-DELEG-001")] // Unconstrained delegation
    [InlineData("AD-DELEG-003")] // Replication rights outside tier zero
    [InlineData("AD-POL-001")] // Minimum password length
    [InlineData("AD-POL-003")] // Reversible encryption
    [InlineData("AD-POL-006")] // Key distribution account rotation
    [InlineData("AD-POL-007")] // Machine account quota
    [InlineData("AD-GPO-001")] // Group Policy writable outside tier zero
    [InlineData("AD-GPO-002")] // Stored preference credential
    [InlineData("EID-PRIV-003")] // Guest administrator
    [InlineData("EID-CA-001")] // No tenant-wide multi-factor policy
    [InlineData("EID-AUTH-002")] // Legacy authentication not blocked
    [InlineData("EID-AUTH-003")] // Legacy authentication observed
    [InlineData("EID-APP-003")] // High-impact application permission
    public void WeakEnvironmentFailsTheExpectedRule(string ruleId)
    {
        var session = Session(SyntheticEnvironment.WeakForest(), SyntheticEnvironment.WeakTenant());

        var outcome = Service.Evaluate(session);
        var result = outcome.Results.Single(candidate => candidate.RuleId.Value == ruleId);

        Assert.Equal(RuleStatus.Fail, result.Status);
    }

    [Theory]
    [InlineData("AD-PRIV-003")]
    [InlineData("AD-ACCT-003")]
    [InlineData("AD-DELEG-001")]
    [InlineData("AD-POL-001")]
    [InlineData("AD-GPO-004")]
    [InlineData("EID-CA-001")]
    [InlineData("EID-AUTH-002")]
    public void HealthyEnvironmentPassesTheExpectedRule(string ruleId)
    {
        var session = Session(SyntheticEnvironment.HealthyForest(), SyntheticEnvironment.HealthyTenant());

        var outcome = Service.Evaluate(session);
        var result = outcome.Results.Single(candidate => candidate.RuleId.Value == ruleId);

        Assert.Equal(RuleStatus.Pass, result.Status);
    }

    [Fact]
    public void EvaluationIsDeterministic()
    {
        var session = Session(SyntheticEnvironment.WeakForest(), SyntheticEnvironment.WeakTenant());

        var first = Service.Evaluate(session);
        var second = Service.Evaluate(session);

        Assert.Equal(
            first.Results.Select(result => (result.RuleId.Value, result.Status, result.Rationale)),
            second.Results.Select(result => (result.RuleId.Value, result.Status, result.Rationale)));

        Assert.Equal(first.Scores.Overall.Value, second.Scores.Overall.Value);
        Assert.Equal(first.Scores.Overall.Coverage, second.Scores.Overall.Coverage);
    }

    [Fact]
    public void ScoresAreTiedToTheRulePackVersion()
    {
        var session = Session(SyntheticEnvironment.HealthyForest(), null);

        var outcome = Service.Evaluate(session);

        Assert.Equal(Service.RulePackVersion, outcome.Scores.RulePackVersion);
    }

    [Fact]
    public void ActiveDirectoryOnlyAssessmentDisablesTheHybridScore()
    {
        var session = Session(SyntheticEnvironment.HealthyForest(), null);

        var outcome = Service.Evaluate(session);

        Assert.DoesNotContain(RuleDomain.Hybrid, outcome.Scores.ByDomain.Keys);
        Assert.DoesNotContain(RuleDomain.Entra, outcome.Scores.ByDomain.Keys);
        Assert.Contains(RuleDomain.ActiveDirectory, outcome.Scores.ByDomain.Keys);

        // Every hybrid rule is excluded as not applicable, with the missing source stated, so it
        // neither scores nor depresses the coverage of the sources that were assessed.
        var hybrid = outcome.Results.Where(result => result.RuleId.Value.StartsWith("HYB-", StringComparison.Ordinal));

        Assert.All(hybrid, result =>
        {
            Assert.Equal(RuleStatus.NotApplicable, result.Status);
            Assert.Contains("hybrid score is disabled", result.Rationale, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void EntraOnlyAssessmentDisablesTheActiveDirectoryScore()
    {
        var session = Session(null, SyntheticEnvironment.HealthyTenant());

        var outcome = Service.Evaluate(session);

        Assert.Contains(RuleDomain.Entra, outcome.Scores.ByDomain.Keys);
        Assert.DoesNotContain(RuleDomain.ActiveDirectory, outcome.Scores.ByDomain.Keys);
    }

    [Fact]
    public void UnselectedCheckGroupsProduceNotCollectedWithAReason()
    {
        var session = Session(
            SyntheticEnvironment.HealthyForest(),
            null,
            CheckGroup.AdPrivilegedAccess);

        var outcome = Service.Evaluate(session);

        var accountHygiene = outcome.Results.Single(result => result.RuleId.Value == "AD-ACCT-001");

        Assert.Equal(RuleStatus.NotCollected, accountHygiene.Status);
        Assert.Contains("not selected", accountHygiene.Rationale, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FailAndNotCollectedAreDistinguishableInTheResults()
    {
        var session = Session(SyntheticEnvironment.WeakForest(), null);

        var outcome = Service.Evaluate(session);
        var statuses = outcome.Results.Select(result => result.Status).Distinct().ToList();

        Assert.Contains(RuleStatus.Fail, statuses);
        Assert.Contains(RuleStatus.NotCollected, statuses);
        Assert.Contains(RuleStatus.Pass, statuses);

        // A not-collected result never becomes a finding: only failures and errors do.
        Assert.All(outcome.Findings, finding =>
            Assert.True(finding.Status is RuleStatus.Fail or RuleStatus.Error));
    }

    [Fact]
    public void ExclusionsAreSummarisedWithTheirReasons()
    {
        var session = Session(SyntheticEnvironment.HealthyForest(), null);

        var outcome = Service.Evaluate(session);
        var exclusions = Service.SummariseExclusions(outcome.Results);

        Assert.NotEmpty(exclusions);
        Assert.All(exclusions, exclusion => Assert.False(string.IsNullOrWhiteSpace(exclusion.Reason)));
        Assert.Contains(exclusions, exclusion => exclusion.Status == RuleStatus.NotCollected);
    }

    [Fact]
    public void OperatorAnnotationsDoNotChangeTheRawScore()
    {
        var session = Session(SyntheticEnvironment.WeakForest(), null);

        var baseline = Service.Evaluate(session);

        var annotated = Service.Evaluate(
            session,
            findingNotes: new Dictionary<string, string> { ["AD-PRIV-003"] = "Accepted for this engagement." },
            findingExceptions: new Dictionary<string, Contracts.Findings.FindingException>
            {
                ["AD-PRIV-003"] = new()
                {
                    Disposition = Contracts.Findings.FindingDisposition.RiskAccepted,
                    Justification = "Service migration is scheduled.",
                    RecordedBy = "Assessor",
                    RecordedAt = SyntheticEnvironment.Reference,
                },
            });

        Assert.Equal(baseline.Scores.Overall.Value, annotated.Scores.Overall.Value);
        Assert.Equal(baseline.Scores.Overall.PassedWeight, annotated.Scores.Overall.PassedWeight);

        var finding = annotated.Findings.Single(candidate => candidate.RuleId.Value == "AD-PRIV-003");
        Assert.Equal(Contracts.Findings.FindingDisposition.RiskAccepted, finding.Disposition);
        Assert.True(finding.IsAnnotated);
    }

    [Fact]
    public void ASingleRuleCanBeReevaluatedInIsolation()
    {
        var session = Session(SyntheticEnvironment.WeakForest(), null);

        var outcome = Service.Evaluate(session, onlyRules: [new RuleId("AD-PRIV-003")]);

        var result = Assert.Single(outcome.Results);
        Assert.Equal("AD-PRIV-003", result.RuleId.Value);
        Assert.Equal(RuleStatus.Fail, result.Status);
    }

    [Fact]
    public void ComplianceMappingIsPopulatedFromTheResults()
    {
        var session = Session(SyntheticEnvironment.WeakForest(), SyntheticEnvironment.WeakTenant());

        var outcome = Service.Evaluate(session);
        var privilegedAccess = outcome.Compliance.Get("A.8.2");

        Assert.NotEmpty(privilegedAccess.MappedRuleIds);
        Assert.NotEqual(Contracts.Compliance.SuggestedStatus.None, privilegedAccess.Suggested);
        Assert.False(privilegedAccess.OperatorConfirmed);
    }

    [Fact]
    public void SecureScoreIsReportedSeparatelyFromThePostureScore()
    {
        var tenant = SyntheticEnvironment.HealthyTenant() with
        {
            SecureScore = new SecureScoreSnapshot
            {
                CreatedDateTime = SyntheticEnvironment.Reference,
                CurrentScore = 30,
                MaxScore = 100,
            },
        };

        var session = Session(null, tenant);
        var outcome = Service.Evaluate(session);

        Assert.NotNull(outcome.Scores.MicrosoftSecureScore);
        Assert.Equal(30, outcome.Scores.MicrosoftSecureScore!.Percent);

        // A low provider score must not drag the product's own score down.
        Assert.True(outcome.Scores.Overall.Value > 30);
    }
}
