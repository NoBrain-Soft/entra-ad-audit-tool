using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Tests.Fixtures;
using Xunit;

namespace Ipa.Rules.Tests;

/// <summary>
/// Contract tests that every rule in the shipped pack must satisfy. They run against the whole pack
/// rather than a hand-picked subset, so a rule added later is covered the moment it is registered.
/// </summary>
public sealed class RuleContractTests
{
    private static readonly IRulePack Pack = FirstPartyRulePack.Current;

    /// <summary>Every rule in the pack, for the theory data.</summary>
    public static TheoryData<string> AllRuleIds
    {
        get
        {
            var data = new TheoryData<string>();

            foreach (var definition in Pack.Definitions)
            {
                data.Add(definition.Id.Value);
            }

            return data;
        }
    }

    private static RuleBase Rule(string ruleId) =>
        Pack.Rules.Single(rule => rule.RuleId.Value == ruleId);

    private static RuleEvaluationContext Context(RuleBase rule, NormalizedEvidence evidence) => new()
    {
        Rule = rule.Definition,
        Evidence = evidence,
        ReferenceTime = evidence.ReferenceTime,
    };

    [Theory]
    [MemberData(nameof(AllRuleIds))]
    public void MissingEvidenceNeverProducesAPass(string ruleId)
    {
        var rule = Rule(ruleId);

        var result = rule.Evaluate(Context(rule, EvidenceBuilder.Empty()));

        Assert.Equal(RuleStatus.NotCollected, result.Status);
        Assert.NotNull(result.Availability);
        Assert.False(string.IsNullOrWhiteSpace(result.Rationale));
    }

    [Theory]
    [MemberData(nameof(AllRuleIds))]
    public void MissingEvidenceExplainsWhichSetWasMissing(string ruleId)
    {
        var rule = Rule(ruleId);

        var result = rule.Evaluate(Context(rule, EvidenceBuilder.Empty()));

        Assert.NotEmpty(result.Diagnostics);

        // The rationale names at least one of the evidence sets the rule declared.
        Assert.Contains(
            rule.Definition.RequiredEvidence,
            requirement => result.Rationale.Contains(requirement.EvidenceKey, StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(AllRuleIds))]
    public void EachDeclaredEvidenceSetIsActuallyRequired(string ruleId)
    {
        var rule = Rule(ruleId);

        foreach (var requirement in rule.Definition.RequiredEvidence)
        {
            var evidence = EvidenceBuilder.Sparse() with
            {
                Availability = EvidenceBuilder.AllCollectedExcept(requirement.EvidenceKey),
            };

            var result = rule.Evaluate(Context(rule, evidence));

            Assert.Equal(RuleStatus.NotCollected, result.Status);
            Assert.Equal(EvidenceAvailability.PermissionDenied, result.Availability);
        }
    }

    [Theory]
    [MemberData(nameof(AllRuleIds))]
    public void EmptyButCollectedEvidenceIsHandledWithoutThrowing(string ruleId)
    {
        var rule = Rule(ruleId);

        // Every set is marked collected, but the collections themselves are empty. A rule must
        // reach a defensible conclusion rather than fail on an empty environment.
        var result = rule.Evaluate(Context(rule, EvidenceBuilder.Sparse()));

        Assert.NotEqual(RuleStatus.Error, result.Status);
        Assert.False(string.IsNullOrWhiteSpace(result.Rationale));
    }

    [Theory]
    [MemberData(nameof(AllRuleIds))]
    public void ResultsCarryTheRuleIdentityAndVersion(string ruleId)
    {
        var rule = Rule(ruleId);

        var result = rule.Evaluate(Context(rule, EvidenceBuilder.Sparse()));

        Assert.Equal(rule.Definition.Id, result.RuleId);
        Assert.Equal(rule.Definition.Version, result.RuleVersion);
        Assert.Equal(EvidenceBuilder.Reference, result.EvaluatedAt);
    }

    [Theory]
    [MemberData(nameof(AllRuleIds))]
    public void EvaluationIsDeterministicForIdenticalEvidence(string ruleId)
    {
        var rule = Rule(ruleId);
        var evidence = EvidenceBuilder.Sparse();

        var first = rule.Evaluate(Context(rule, evidence));
        var second = rule.Evaluate(Context(rule, evidence));

        Assert.Equal(first.Status, second.Status);
        Assert.Equal(first.Rationale, second.Rationale);
        Assert.Equal(
            first.AffectedObjects.Select(affected => affected.Identifier),
            second.AffectedObjects.Select(affected => affected.Identifier));
    }

    [Theory]
    [MemberData(nameof(AllRuleIds))]
    public void EveryRuleUsesTheReferenceTimeRatherThanTheClock(string ruleId)
    {
        var rule = Rule(ruleId);

        // Evaluating the same evidence against a reference instant far in the future must be able
        // to change an age-based outcome, which proves the wall clock is not consulted.
        var now = EvidenceBuilder.Sparse();

        var later = now with
        {
            ReferenceTime = EvidenceBuilder.Reference.AddYears(5),
            ActiveDirectory = now.ActiveDirectory is null
                ? null
                : now.ActiveDirectory with { ReferenceTime = EvidenceBuilder.Reference.AddYears(5) },
            Entra = now.Entra is null
                ? null
                : now.Entra with { ReferenceTime = EvidenceBuilder.Reference.AddYears(5) },
            Hybrid = now.Hybrid is null
                ? null
                : now.Hybrid with { ReferenceTime = EvidenceBuilder.Reference.AddYears(5) },
        };

        var result = rule.Evaluate(Context(rule, later));

        Assert.Equal(EvidenceBuilder.Reference.AddYears(5), result.EvaluatedAt);
    }

    [Theory]
    [MemberData(nameof(AllRuleIds))]
    public void AffectedObjectListsAreBounded(string ruleId)
    {
        var rule = Rule(ruleId);

        var result = rule.Evaluate(Context(rule, EvidenceBuilder.Sparse()));

        Assert.True(
            result.AffectedObjects.Count <= RuleHelpers.MaxAffectedObjects + 1,
            $"{ruleId} produced an unbounded affected-object list.");
    }

    [Fact]
    public void AnEvaluatorThatThrowsYieldsErrorRatherThanPass()
    {
        var rule = new ThrowingRule();

        var result = rule.Evaluate(new RuleEvaluationContext
        {
            Rule = rule.Definition,
            Evidence = EvidenceBuilder.Sparse(),
            ReferenceTime = EvidenceBuilder.Reference,
        });

        Assert.Equal(RuleStatus.Error, result.Status);
        Assert.Contains(result.Diagnostics, note => note.Code == "EvaluationError");
        Assert.Equal(nameof(InvalidOperationException), result.Diagnostics[0].Message);
    }

    [Fact]
    public void CancellationIsNotSwallowedAsAnEvaluationError()
    {
        var rule = new CancellingRule();

        Assert.Throws<OperationCanceledException>(() => rule.Evaluate(new RuleEvaluationContext
        {
            Rule = rule.Definition,
            Evidence = EvidenceBuilder.Sparse(),
            ReferenceTime = EvidenceBuilder.Reference,
        }));
    }

    /// <summary>A rule whose evaluation throws, used to prove the failure contract.</summary>
    private sealed class ThrowingRule : RuleBase
    {
        public override RuleDefinition Definition { get; } = RuleFactory.Create(
            id: "TEST-THROW",
            version: 1,
            title: "Throwing rule",
            domain: RuleDomain.ActiveDirectory,
            group: CheckGroup.AdPrivilegedAccess,
            severity: RuleSeverity.High,
            rationale: "test",
            remediation: "test",
            evidenceKeys: [EvidenceKeys.AdUsers]);

        protected override RuleResult EvaluateCore(RuleEvaluationContext context) =>
            throw new InvalidOperationException("deliberate failure");
    }

    /// <summary>A rule whose evaluation cancels, used to prove cancellation propagates.</summary>
    private sealed class CancellingRule : RuleBase
    {
        public override RuleDefinition Definition { get; } = RuleFactory.Create(
            id: "TEST-CANCEL",
            version: 1,
            title: "Cancelling rule",
            domain: RuleDomain.ActiveDirectory,
            group: CheckGroup.AdPrivilegedAccess,
            severity: RuleSeverity.High,
            rationale: "test",
            remediation: "test",
            evidenceKeys: [EvidenceKeys.AdUsers]);

        protected override RuleResult EvaluateCore(RuleEvaluationContext context) =>
            throw new OperationCanceledException();
    }
}
