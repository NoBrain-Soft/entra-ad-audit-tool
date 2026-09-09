using Ipa.Contracts.Evidence;

namespace Ipa.Contracts.Rules;

/// <summary>Everything an evaluator may read. There is deliberately no network or clock access.</summary>
public sealed record RuleEvaluationContext
{
    public required RuleDefinition Rule { get; init; }

    public required NormalizedEvidence Evidence { get; init; }

    /// <summary>
    /// Fixed evaluation instant. Evaluators must use this rather than the system clock so that
    /// re-evaluating the same evidence with the same rule version yields an identical result.
    /// </summary>
    public required DateTimeOffset ReferenceTime { get; init; }

    /// <summary>Thresholds an operator may tune, resolved from the rule pack defaults.</summary>
    public IReadOnlyDictionary<string, int> Thresholds { get; init; } =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    public int Threshold(string name, int fallback) =>
        Thresholds.TryGetValue(name, out var value) ? value : fallback;
}

/// <summary>
/// Evaluates one rule against normalised evidence. Implementations are pure: identical inputs
/// always produce an identical <see cref="RuleResult"/>, and no input or output is performed.
/// </summary>
public interface IRuleEvaluator
{
    /// <summary>The rule this evaluator implements.</summary>
    RuleId RuleId { get; }

    /// <summary>Evaluates the rule.</summary>
    RuleResult Evaluate(RuleEvaluationContext context);
}
