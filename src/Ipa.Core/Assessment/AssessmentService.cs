using Ipa.Compliance;
using Ipa.Contracts;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Baselines;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Findings;
using Ipa.Contracts.Rules;
using Ipa.Contracts.Scoring;
using Ipa.Core.Collection;
using Ipa.Rules.Engine;
using Ipa.Rules.Scoring;

namespace Ipa.Core.Assessment;

/// <summary>The complete outcome of evaluating collected evidence.</summary>
public sealed record EvaluationOutcome
{
    public required IReadOnlyList<RuleResult> Results { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required PostureScoreSet Scores { get; init; }
    public required ComplianceWorkspace Compliance { get; init; }
}

/// <summary>
/// Orchestrates an assessment: collection, evaluation, scoring, findings and compliance mapping.
/// </summary>
/// <remarks>
/// The service is deliberately free of any user interface dependency, so the same orchestration
/// could be driven by a future command-line or service front end without changing rule semantics.
/// Evaluation is a pure function of the normalised evidence and the rule pack version, so
/// recalculating produces identical results for identical inputs.
/// </remarks>
public sealed class AssessmentService
{
    private readonly RuleEngine _ruleEngine;
    private readonly ScoringEngine _scoringEngine = new();
    private readonly CollectionPipeline _pipeline;

    public AssessmentService(IRulePack? rulePack = null, CollectionPipeline? pipeline = null)
    {
        _ruleEngine = new RuleEngine(rulePack ?? FirstPartyRulePack.Current);
        _pipeline = pipeline ?? new CollectionPipeline();
    }

    /// <summary>The rule pack version recorded with every score set this service produces.</summary>
    public string RulePackVersion => _ruleEngine.Pack.Version;

    /// <summary>Creates a new assessment session with a fixed reference time.</summary>
    public static AssessmentSession CreateSession(
        AssessmentMetadata metadata,
        AssessmentScope scope,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(scope);

        if (scope.IsEmpty)
        {
            throw new ArgumentException(
                "An assessment must include at least one identity source.",
                nameof(scope));
        }

        return new AssessmentSession
        {
            AssessmentId = Guid.NewGuid(),
            Metadata = metadata,
            Scope = scope,
            CreatedAt = now,

            // Every age comparison in every rule uses this instant rather than the wall clock, so
            // re-evaluating the same evidence later produces the same results.
            ReferenceTime = now,
            State = AssessmentState.Created,
        };
    }

    /// <summary>Runs collection for a session and returns the session with its evidence attached.</summary>
    public async Task<AssessmentSession> CollectAsync(
        AssessmentSession session,
        IReadOnlyList<CollectionStage> stages,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(stages);

        var context = new CollectionContext
        {
            AssessmentId = session.AssessmentId,
            ReferenceTime = session.ReferenceTime,
            SelectedGroups = session.Scope.SelectedGroups,
            Progress = progress,
        };

        var run = await _pipeline.RunAsync(stages, context, cancellationToken).ConfigureAwait(false);

        return session with
        {
            Evidence = run.Evidence,
            CollectionResults = run.Results,
            Diagnostics = run.Diagnostics,
            State = run.WasCancelled ? AssessmentState.Collecting : AssessmentState.Collected,
        };
    }

    /// <summary>
    /// Reruns the collectors that failed, keeping the results that succeeded. Recalculation
    /// afterwards is deterministic for the evidence that results.
    /// </summary>
    public async Task<AssessmentSession> RerunAsync(
        AssessmentSession session,
        IReadOnlyList<ICollector> collectors,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(collectors);

        if (session.Evidence is null)
        {
            throw new InvalidOperationException("Collect before rerunning individual collectors.");
        }

        var context = new CollectionContext
        {
            AssessmentId = session.AssessmentId,
            ReferenceTime = session.ReferenceTime,
            SelectedGroups = session.Scope.SelectedGroups,
            Progress = progress,
        };

        var run = await _pipeline
            .RerunAsync(collectors, session.Evidence, session.CollectionResults, context, cancellationToken)
            .ConfigureAwait(false);

        return session with
        {
            Evidence = run.Evidence,
            CollectionResults = run.Results,
            Diagnostics = [.. session.Diagnostics, .. run.Diagnostics],
            State = AssessmentState.Collected,
        };
    }

    /// <summary>
    /// Evaluates the rule pack over the session's evidence and produces results, findings, scores
    /// and the compliance mapping. Existing operator workflow state is carried forward.
    /// </summary>
    public EvaluationOutcome Evaluate(
        AssessmentSession session,
        IReadOnlyDictionary<string, string>? findingNotes = null,
        IReadOnlyDictionary<string, FindingException>? findingExceptions = null,
        IReadOnlyCollection<Contracts.Compliance.ControlAssessment>? existingControls = null,
        IReadOnlyDictionary<string, int>? thresholds = null,
        IReadOnlyCollection<RuleId>? onlyRules = null)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (session.Evidence is null)
        {
            throw new InvalidOperationException("There is no collected evidence to evaluate.");
        }

        var options = new RuleEvaluationOptions
        {
            SelectedGroups = session.Scope.SelectedGroups.Count > 0
                ? session.Scope.SelectedGroups
                : Enum.GetValues<CheckGroup>(),
            ActiveDomains = RuleEngine.DomainsFor(session.Scope),
            Thresholds = thresholds ?? new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase),
            OnlyRules = onlyRules,
        };

        var results = _ruleEngine.Evaluate(session.Evidence, options);

        var findings = _ruleEngine.BuildFindings(
            results,
            session.ReferenceTime,
            findingExceptions,
            findingNotes);

        var scores = _scoringEngine.Compute(
            _ruleEngine.Pack.Definitions,
            results,
            _ruleEngine.Pack.Version,
            session.ReferenceTime,
            session.Evidence.Entra?.SecureScore,
            session.Evidence.BaselineComparison);

        var compliance = new ComplianceWorkspace(existingControls);
        compliance.ApplyAutomatedEvidence(_ruleEngine.Pack.Definitions, results, session.ReferenceTime);

        return new EvaluationOutcome
        {
            Results = results,
            Findings = findings,
            Scores = scores,
            Compliance = compliance,
        };
    }

    /// <summary>Applies an evaluation outcome to a session.</summary>
    public static AssessmentSession Apply(AssessmentSession session, EvaluationOutcome outcome, string rulePackVersion)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(outcome);

        return session with
        {
            RuleResults = outcome.Results,
            Findings = outcome.Findings,
            Scores = outcome.Scores,
            ControlAssessments = outcome.Compliance.Assessments,
            RulePackVersion = rulePackVersion,
            State = AssessmentState.Evaluated,
        };
    }

    /// <summary>
    /// Attaches an imported baseline comparison to a session's evidence, so the separately reported
    /// conformity metric can be produced without rerunning collection.
    /// </summary>
    public static AssessmentSession AttachBaseline(
        AssessmentSession session,
        ImportedBaseline baseline,
        BaselineComparison comparison)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(comparison);

        if (session.Evidence is null)
        {
            throw new InvalidOperationException("Collect before attaching a baseline comparison.");
        }

        var accumulator = new EvidenceAccumulator(session.ReferenceTime, session.Evidence);
        accumulator.SetBaselineComparison(comparison);

        return session with
        {
            Baseline = baseline,
            Evidence = accumulator.Build(),
        };
    }

    /// <summary>
    /// Summarises which rules could not be evaluated and why, for the report's exclusions section
    /// and for the collection diagnostics view.
    /// </summary>
    public IReadOnlyList<ExclusionSummary> SummariseExclusions(IReadOnlyCollection<RuleResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        var definitions = _ruleEngine.Pack.Definitions
            .ToDictionary(definition => definition.Id.Value, definition => definition, StringComparer.OrdinalIgnoreCase);

        return results
            .Where(result => result.Status is RuleStatus.NotCollected or RuleStatus.Error or RuleStatus.NotApplicable)
            .Select(result => new ExclusionSummary
            {
                RuleId = result.RuleId.Value,
                Title = definitions.GetValueOrDefault(result.RuleId.Value)?.Title ?? result.RuleId.Value,
                Status = result.Status,
                Availability = result.Availability,
                Reason = result.Rationale,
                Weight = definitions.GetValueOrDefault(result.RuleId.Value)?.Weight ?? 0,
            })
            .OrderBy(summary => summary.RuleId, StringComparer.Ordinal)
            .ToList();
    }
}

/// <summary>One row of the report's exclusions section.</summary>
public sealed record ExclusionSummary
{
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required RuleStatus Status { get; init; }
    public EvidenceAvailability? Availability { get; init; }
    public required string Reason { get; init; }
    public required int Weight { get; init; }
}
