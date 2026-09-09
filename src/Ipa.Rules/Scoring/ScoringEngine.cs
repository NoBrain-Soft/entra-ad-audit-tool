using Ipa.Contracts;
using Ipa.Contracts.Baselines;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Contracts.Scoring;

namespace Ipa.Rules.Scoring;

/// <summary>
/// Computes posture scores from rule results. The calculation is a pure function of the results
/// and the rule definitions, so the same evidence and rule-pack version always produce the same
/// scores.
/// </summary>
public sealed class ScoringEngine
{
    /// <summary>
    /// Check groups whose results are reported as separately labelled metrics and never folded
    /// into the posture score, so that no control is counted twice.
    /// </summary>
    public static IReadOnlySet<CheckGroup> GroupsExcludedFromPosture { get; } =
        new HashSet<CheckGroup> { CheckGroup.BaselineConformity, CheckGroup.EntraSecureScore };

    /// <summary>Computes the full score set for an evaluated assessment.</summary>
    public PostureScoreSet Compute(
        IReadOnlyCollection<RuleDefinition> definitions,
        IReadOnlyCollection<RuleResult> results,
        string rulePackVersion,
        DateTimeOffset calculatedAt,
        SecureScoreSnapshot? secureScore = null,
        BaselineComparison? baselineComparison = null)
    {
        ArgumentNullException.ThrowIfNull(definitions);
        ArgumentNullException.ThrowIfNull(results);
        ArgumentException.ThrowIfNullOrWhiteSpace(rulePackVersion);

        var definitionsById = definitions
            .GroupBy(definition => definition.Id.Value, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);

        var scorable = new List<ScorableResult>();

        foreach (var result in results)
        {
            if (!definitionsById.TryGetValue(result.RuleId.Value, out var definition))
            {
                // A result without a matching definition cannot be weighted; it is ignored for
                // scoring and surfaced separately by the assessment service.
                continue;
            }

            if (GroupsExcludedFromPosture.Contains(definition.Group))
            {
                continue;
            }

            scorable.Add(new ScorableResult(definition, result));
        }

        var overall = Aggregate("Overall", scorable);

        var byDomain = scorable
            .GroupBy(item => item.Definition.Domain)
            .ToDictionary(
                group => group.Key,
                group => Aggregate(group.Key.ToString(), group.ToList()));

        var byGroup = scorable
            .GroupBy(item => item.Definition.Group)
            .ToDictionary(
                group => group.Key,
                group => Aggregate(group.Key.ToString(), group.ToList()));

        return new PostureScoreSet
        {
            Overall = overall,
            ByDomain = byDomain,
            ByGroup = byGroup,
            RulePackVersion = rulePackVersion,
            CalculatedAt = calculatedAt,
            MicrosoftSecureScore = secureScore is null
                ? null
                : new ProviderScore
                {
                    Provider = "Microsoft",
                    MetricName = "Microsoft Secure Score",
                    Current = secureScore.CurrentScore,
                    Maximum = secureScore.MaxScore,
                    AsOf = secureScore.CreatedDateTime,
                },
            BaselineConformity = baselineComparison is null
                ? null
                : new BaselineConformityMetric
                {
                    ProductName = baselineComparison.ProductName,
                    BaselineVersion = baselineComparison.BaselineVersion,
                    PackageSha256 = baselineComparison.PackageSha256,
                    ConformityPercent = baselineComparison.ConformityPercent,
                    MatchCount = baselineComparison.MatchCount,
                    DifferentCount = baselineComparison.DifferentCount,
                    NotConfiguredCount = baselineComparison.NotConfiguredCount,
                    NotComparableCount = baselineComparison.NotComparableCount,
                },
        };
    }

    private static PostureScore Aggregate(string scope, IReadOnlyCollection<ScorableResult> items)
    {
        var passedWeight = 0;
        var evaluatedWeight = 0;
        var notCollectedWeight = 0;
        var errorWeight = 0;
        var notApplicable = 0;
        var statusCounts = new Dictionary<RuleStatus, int>();

        foreach (var item in items)
        {
            var weight = item.Definition.Weight;
            statusCounts[item.Result.Status] = statusCounts.GetValueOrDefault(item.Result.Status) + 1;

            switch (item.Result.Status)
            {
                case RuleStatus.Pass:
                    passedWeight += weight;
                    evaluatedWeight += weight;
                    break;

                case RuleStatus.Fail:
                    evaluatedWeight += weight;
                    break;

                case RuleStatus.NotCollected:
                    notCollectedWeight += weight;
                    break;

                case RuleStatus.Error:
                    errorWeight += weight;
                    break;

                case RuleStatus.NotApplicable:
                    // Excluded from the score and from coverage entirely.
                    notApplicable++;
                    break;

                default:
                    throw new InvalidOperationException($"Unhandled rule status {item.Result.Status}.");
            }
        }

        return new PostureScore
        {
            Scope = scope,
            PassedWeight = passedWeight,
            EvaluatedWeight = evaluatedWeight,
            NotCollectedWeight = notCollectedWeight,
            ErrorWeight = errorWeight,
            NotApplicableCount = notApplicable,
            StatusCounts = statusCounts,
        };
    }

    private readonly record struct ScorableResult(RuleDefinition Definition, RuleResult Result);
}
