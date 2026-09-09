using Ipa.Contracts;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Findings;
using Ipa.Contracts.Rules;

namespace Ipa.Rules.Engine;

/// <summary>Options controlling one evaluation pass.</summary>
public sealed record RuleEvaluationOptions
{
    /// <summary>Check groups the operator selected. Rules outside them are not evaluated.</summary>
    public IReadOnlyCollection<CheckGroup> SelectedGroups { get; init; } = Enum.GetValues<CheckGroup>();

    /// <summary>Operator-tuned thresholds, keyed by the threshold names the rules declare.</summary>
    public IReadOnlyDictionary<string, int> Thresholds { get; init; } =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Restricts the pass to specific rules, used when rerunning a single rule.</summary>
    public IReadOnlyCollection<RuleId>? OnlyRules { get; init; }

    /// <summary>Domains that were connected. Rules for a disconnected domain are not evaluated.</summary>
    public IReadOnlyCollection<RuleDomain> ActiveDomains { get; init; } = Enum.GetValues<RuleDomain>();
}

/// <summary>
/// Runs a rule pack over normalised evidence. Evaluation performs no input or output and depends
/// only on the evidence, the rule versions and the fixed reference time, so the same inputs always
/// produce the same results.
/// </summary>
public sealed class RuleEngine
{
    private readonly IRulePack _pack;

    public RuleEngine(IRulePack pack)
    {
        ArgumentNullException.ThrowIfNull(pack);
        _pack = pack;
    }

    /// <summary>The rule pack this engine evaluates.</summary>
    public IRulePack Pack => _pack;

    /// <summary>Evaluates every applicable rule and returns the results in rule identifier order.</summary>
    public IReadOnlyList<RuleResult> Evaluate(NormalizedEvidence evidence, RuleEvaluationOptions options)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(options);

        var results = new List<RuleResult>();

        foreach (var rule in _pack.Rules)
        {
            var definition = rule.Definition;

            if (definition.IsWithdrawn)
            {
                continue;
            }

            if (options.OnlyRules is { Count: > 0 }
                && !options.OnlyRules.Any(id => string.Equals(id.Value, definition.Id.Value, StringComparison.Ordinal)))
            {
                continue;
            }

            if (!options.ActiveDomains.Contains(definition.Domain))
            {
                // The rule's source is not part of this assessment at all, so the rule does not
                // apply and is excluded from the score entirely. Counting it as uncollected would
                // depress the coverage of an assessment that was never meant to cover that source.
                results.Add(new RuleResult
                {
                    RuleId = definition.Id,
                    RuleVersion = definition.Version,
                    Status = RuleStatus.NotApplicable,
                    EvaluatedAt = evidence.ReferenceTime,
                    Rationale = definition.Domain == RuleDomain.Hybrid
                        ? "Hybrid rules require both an Active Directory forest and an Entra tenant. " +
                          "Only one source was connected, so the hybrid score is disabled."
                        : $"The {definition.Domain} source was not connected for this assessment.",
                });

                continue;
            }

            if (!options.SelectedGroups.Contains(definition.Group))
            {
                // The source is connected but the operator deselected this group, so the rule is
                // uncollected: it reduces coverage, which is what makes a partial scan visible.
                results.Add(new RuleResult
                {
                    RuleId = definition.Id,
                    RuleVersion = definition.Version,
                    Status = RuleStatus.NotCollected,
                    EvaluatedAt = evidence.ReferenceTime,
                    Availability = EvidenceAvailability.NotSelected,
                    Rationale = $"The {definition.Group} check group was not selected for this assessment.",
                });

                continue;
            }

            var context = new RuleEvaluationContext
            {
                Rule = definition,
                Evidence = evidence,
                ReferenceTime = evidence.ReferenceTime,
                Thresholds = options.Thresholds,
            };

            results.Add(rule.Evaluate(context));
        }

        return results
            .OrderBy(result => result.RuleId.Value, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Converts rule results into findings. A finding is produced for every failed or errored
    /// rule; passes and non-applicable results are recorded in the score but produce no finding.
    /// </summary>
    public IReadOnlyList<Finding> BuildFindings(
        IReadOnlyCollection<RuleResult> results,
        DateTimeOffset detectedAt,
        IReadOnlyDictionary<string, FindingException>? existingExceptions = null,
        IReadOnlyDictionary<string, string>? existingNotes = null)
    {
        ArgumentNullException.ThrowIfNull(results);

        var definitions = _pack.Definitions
            .ToDictionary(definition => definition.Id.Value, definition => definition, StringComparer.OrdinalIgnoreCase);

        var findings = new List<Finding>();

        foreach (var result in results.Where(result => result.Status is RuleStatus.Fail or RuleStatus.Error))
        {
            if (!definitions.TryGetValue(result.RuleId.Value, out var definition))
            {
                continue;
            }

            var findingId = $"{result.RuleId.Value}";

            findings.Add(new Finding
            {
                FindingId = findingId,
                RuleId = definition.Id,
                RuleVersion = result.RuleVersion,
                Title = definition.Title,
                Severity = definition.Severity,
                Domain = definition.Domain,
                Group = definition.Group,
                Status = result.Status,
                RiskExplanation = definition.Rationale,
                Remediation = definition.Remediation,
                Rationale = result.Rationale,
                AffectedObjects = result.AffectedObjects,
                EvidenceReferences = result.EvidenceReferences,
                References = definition.References,
                FrameworkMappings = definition.FrameworkMappings,
                OperatorNotes = existingNotes?.GetValueOrDefault(findingId),
                Exception = existingExceptions?.GetValueOrDefault(findingId),
                DetectedAt = detectedAt,
            });
        }

        return findings
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding => finding.RuleId.Value, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Returns the domains that should be evaluated for a scope. Hybrid rules run only when both
    /// sources are connected; with a single source the hybrid score is disabled entirely.
    /// </summary>
    public static IReadOnlyCollection<RuleDomain> DomainsFor(AssessmentScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var domains = new List<RuleDomain>();

        if (scope.IncludeActiveDirectory)
        {
            domains.Add(RuleDomain.ActiveDirectory);
        }

        if (scope.IncludeEntra)
        {
            domains.Add(RuleDomain.Entra);
        }

        if (scope.IncludeHybrid)
        {
            domains.Add(RuleDomain.Hybrid);
        }

        return domains;
    }
}
