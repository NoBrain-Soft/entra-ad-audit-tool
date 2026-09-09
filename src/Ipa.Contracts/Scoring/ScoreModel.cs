using Ipa.Contracts.Rules;

namespace Ipa.Contracts.Scoring;

/// <summary>
/// A posture score for one scope. Scores are whole numbers between zero and one hundred and are
/// derived only from passed and failed weight; annotations never alter them.
/// </summary>
public sealed record PostureScore
{
    /// <summary>Scope label: a domain name, a category name or <c>Overall</c>.</summary>
    public required string Scope { get; init; }

    /// <summary>Weight earned by rules that passed.</summary>
    public required int PassedWeight { get; init; }

    /// <summary>Weight of all evaluated rules, that is passes plus failures.</summary>
    public required int EvaluatedWeight { get; init; }

    /// <summary>Weight of rules whose evidence was not collected.</summary>
    public required int NotCollectedWeight { get; init; }

    /// <summary>Weight of rules that errored during evaluation.</summary>
    public required int ErrorWeight { get; init; }

    /// <summary>Number of rules excluded because they do not apply to this environment.</summary>
    public required int NotApplicableCount { get; init; }

    /// <summary>Count of rules by status, for the score card breakdown.</summary>
    public IReadOnlyDictionary<RuleStatus, int> StatusCounts { get; init; } =
        new Dictionary<RuleStatus, int>();

    /// <summary>
    /// Score as a whole number between zero and one hundred: passed weight divided by evaluated
    /// weight. Null when nothing in scope could be evaluated.
    /// </summary>
    public int? Value => EvaluatedWeight == 0
        ? null
        : (int)Math.Round(PassedWeight * 100d / EvaluatedWeight, MidpointRounding.AwayFromZero);

    /// <summary>
    /// Weighted collection coverage: evaluated weight over evaluated plus uncollected and errored
    /// weight. Rules that do not apply are excluded from both sides.
    /// </summary>
    public double Coverage
    {
        get
        {
            var denominator = EvaluatedWeight + NotCollectedWeight + ErrorWeight;
            return denominator == 0 ? 0d : EvaluatedWeight / (double)denominator;
        }
    }

    /// <summary>Coverage as a whole percentage, for display.</summary>
    public int CoveragePercent => (int)Math.Round(Coverage * 100d, MidpointRounding.AwayFromZero);

    /// <summary>
    /// True when weighted collection coverage is below the provisional threshold. Provisional
    /// scores must be labelled as such everywhere they are shown.
    /// </summary>
    public bool IsProvisional => Coverage < ScoringConstants.ProvisionalCoverageThreshold;
}

/// <summary>Constants that define scoring behaviour. Changing these changes score semantics.</summary>
public static class ScoringConstants
{
    /// <summary>Weighted collection coverage below this fraction marks a score provisional.</summary>
    public const double ProvisionalCoverageThreshold = 0.90d;

    /// <summary>Label appended to provisional scores in the user interface and reports.</summary>
    public const string ProvisionalLabel = "Provisional";
}

/// <summary>
/// The full set of scores for an assessment: per domain, per category and overall, plus the
/// separately reported provider and baseline metrics.
/// </summary>
public sealed record PostureScoreSet
{
    public required PostureScore Overall { get; init; }

    /// <summary>Scores keyed by rule domain. A domain with no connected source is absent.</summary>
    public IReadOnlyDictionary<RuleDomain, PostureScore> ByDomain { get; init; } =
        new Dictionary<RuleDomain, PostureScore>();

    /// <summary>Scores keyed by check group, used for the category breakdown.</summary>
    public IReadOnlyDictionary<CheckGroup, PostureScore> ByGroup { get; init; } =
        new Dictionary<CheckGroup, PostureScore>();

    /// <summary>Rule-pack version the scores were produced with. Required for reproducibility.</summary>
    public required string RulePackVersion { get; init; }

    public required DateTimeOffset CalculatedAt { get; init; }

    /// <summary>
    /// Microsoft Secure Score, when retrieved. Displayed as the provider's own metric and never
    /// blended into <see cref="Overall"/>.
    /// </summary>
    public ProviderScore? MicrosoftSecureScore { get; init; }

    /// <summary>
    /// Baseline conformity, when a baseline was imported. A separately labelled metric that is
    /// never folded into the posture score.
    /// </summary>
    public BaselineConformityMetric? BaselineConformity { get; init; }
}

/// <summary>A score published by an external provider, shown with attribution and never blended.</summary>
public sealed record ProviderScore
{
    public required string Provider { get; init; }
    public required string MetricName { get; init; }
    public required double Current { get; init; }
    public required double Maximum { get; init; }
    public required DateTimeOffset AsOf { get; init; }

    public int Percent => Maximum <= 0
        ? 0
        : (int)Math.Round(Current / Maximum * 100d, MidpointRounding.AwayFromZero);
}

/// <summary>Conformity against an imported baseline, reported separately from the posture score.</summary>
public sealed record BaselineConformityMetric
{
    public required string ProductName { get; init; }
    public required string BaselineVersion { get; init; }
    public required string PackageSha256 { get; init; }
    public required int ConformityPercent { get; init; }
    public required int MatchCount { get; init; }
    public required int DifferentCount { get; init; }
    public required int NotConfiguredCount { get; init; }
    public required int NotComparableCount { get; init; }
}
