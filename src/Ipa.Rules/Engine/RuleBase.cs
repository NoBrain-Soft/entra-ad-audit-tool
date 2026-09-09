using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;

namespace Ipa.Rules.Engine;

/// <summary>
/// Base class for every first-party rule. It pairs a rule's definition with its evaluation logic
/// so the two cannot drift apart, and it enforces the outcome contract: missing evidence yields
/// <see cref="RuleStatus.NotCollected"/> and an unexpected exception yields
/// <see cref="RuleStatus.Error"/>, never a pass.
/// </summary>
public abstract class RuleBase : IRuleEvaluator
{
    /// <summary>The immutable definition of this rule.</summary>
    public abstract RuleDefinition Definition { get; }

    /// <inheritdoc />
    public RuleId RuleId => Definition.Id;

    /// <inheritdoc />
    public RuleResult Evaluate(RuleEvaluationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var missing = Definition.RequiredEvidence
            .Select(requirement => context.Evidence.GetAvailability(requirement.EvidenceKey))
            .Where(entry => !entry.IsAvailable)
            .ToList();

        if (missing.Count > 0)
        {
            var worst = missing
                .OrderByDescending(entry => SeverityOf(entry.Availability))
                .First();

            return new RuleResult
            {
                RuleId = Definition.Id,
                RuleVersion = Definition.Version,
                Status = RuleStatus.NotCollected,
                EvaluatedAt = context.ReferenceTime,
                Availability = worst.Availability,
                Rationale = DescribeMissing(missing),
                Diagnostics = missing
                    .Select(entry => new DiagnosticNote(
                        entry.Availability.ToString(),
                        $"{entry.EvidenceKey}: {entry.Reason ?? "not available"}"))
                    .ToList(),
            };
        }

        try
        {
            return EvaluateCore(context);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new RuleResult
            {
                RuleId = Definition.Id,
                RuleVersion = Definition.Version,
                Status = RuleStatus.Error,
                EvaluatedAt = context.ReferenceTime,
                Rationale = "The rule could not be evaluated because of an unexpected error.",
                Diagnostics = [new DiagnosticNote("EvaluationError", ex.GetType().Name)],
            };
        }
    }

    /// <summary>Evaluates the rule once every declared evidence requirement is available.</summary>
    protected abstract RuleResult EvaluateCore(RuleEvaluationContext context);

    /// <summary>Builds a passing result.</summary>
    protected RuleResult Pass(
        RuleEvaluationContext context,
        string rationale,
        IReadOnlyList<AffectedObject>? affected = null,
        IReadOnlyList<string>? evidenceReferences = null) =>
        Build(context, RuleStatus.Pass, rationale, affected, evidenceReferences);

    /// <summary>Builds a failing result.</summary>
    protected RuleResult Fail(
        RuleEvaluationContext context,
        string rationale,
        IReadOnlyList<AffectedObject>? affected = null,
        IReadOnlyList<string>? evidenceReferences = null) =>
        Build(context, RuleStatus.Fail, rationale, affected, evidenceReferences);

    /// <summary>Builds a not-applicable result, which is excluded from scoring entirely.</summary>
    protected RuleResult NotApplicable(RuleEvaluationContext context, string rationale) =>
        Build(context, RuleStatus.NotApplicable, rationale, null, null);

    /// <summary>
    /// Builds a not-collected result for evidence that is present in principle but unusable,
    /// for example a licence-gated data set the tenant does not expose.
    /// </summary>
    protected RuleResult NotCollected(
        RuleEvaluationContext context,
        EvidenceAvailability availability,
        string rationale) =>
        new()
        {
            RuleId = Definition.Id,
            RuleVersion = Definition.Version,
            Status = RuleStatus.NotCollected,
            EvaluatedAt = context.ReferenceTime,
            Availability = availability,
            Rationale = rationale,
        };

    private RuleResult Build(
        RuleEvaluationContext context,
        RuleStatus status,
        string rationale,
        IReadOnlyList<AffectedObject>? affected,
        IReadOnlyList<string>? evidenceReferences) =>
        new()
        {
            RuleId = Definition.Id,
            RuleVersion = Definition.Version,
            Status = status,
            EvaluatedAt = context.ReferenceTime,
            Rationale = rationale,
            AffectedObjects = affected ?? [],
            EvidenceReferences = evidenceReferences ?? [],
        };

    private static string DescribeMissing(IReadOnlyList<EvidenceAvailabilityEntry> missing)
    {
        var keys = string.Join(", ", missing.Select(entry => entry.EvidenceKey));
        var reason = missing[0].Reason;
        var suffix = string.IsNullOrWhiteSpace(reason) ? string.Empty : $" {reason}";
        return $"Required evidence was not collected ({keys}).{suffix} " +
               "The rule is excluded from the posture score and reduces collection coverage.";
    }

    private static int SeverityOf(EvidenceAvailability availability) => availability switch
    {
        EvidenceAvailability.Error => 4,
        EvidenceAvailability.PermissionDenied => 3,
        EvidenceAvailability.Unsupported => 2,
        EvidenceAvailability.NotSelected => 1,
        _ => 0,
    };
}
