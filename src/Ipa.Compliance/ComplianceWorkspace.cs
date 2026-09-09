using Ipa.Compliance.Catalogue;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Rules;

namespace Ipa.Compliance;

/// <summary>
/// The operator's ISO/IEC 27001 readiness workspace for one assessment.
/// </summary>
/// <remarks>
/// Automated findings may suggest a readiness status, but only an explicit operator confirmation
/// sets a control's status. Nothing this class does can mark a control compliant on the strength of
/// automated evidence alone, and every metric it produces is labelled as readiness rather than
/// certification.
/// </remarks>
public sealed class ComplianceWorkspace
{
    private readonly Dictionary<string, ControlAssessment> _assessments;

    public ComplianceWorkspace(IEnumerable<ControlAssessment>? existing = null)
    {
        _assessments = IsoControlCatalogue.All.ToDictionary(
            control => control.ControlId,
            control => new ControlAssessment { ControlId = control.ControlId },
            StringComparer.OrdinalIgnoreCase);

        foreach (var assessment in existing ?? [])
        {
            _assessments[assessment.ControlId] = assessment;
        }
    }

    /// <summary>Every control assessment, in catalogue order.</summary>
    public IReadOnlyList<ControlAssessment> Assessments => IsoControlCatalogue.All
        .Select(control => _assessments[control.ControlId])
        .ToList();

    /// <summary>Returns the assessment for one control.</summary>
    public ControlAssessment Get(string controlId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(controlId);

        return _assessments.TryGetValue(controlId, out var assessment)
            ? assessment
            : throw new KeyNotFoundException($"Control {controlId} is not in the catalogue.");
    }

    /// <summary>
    /// Applies automated rule results to the workspace, recording the mapped rules and the status
    /// the evidence suggests. The operator's own status and confirmation are never overwritten.
    /// </summary>
    public void ApplyAutomatedEvidence(
        IReadOnlyCollection<RuleDefinition> definitions,
        IReadOnlyCollection<RuleResult> results,
        DateTimeOffset appliedAt)
    {
        ArgumentNullException.ThrowIfNull(definitions);
        ArgumentNullException.ThrowIfNull(results);

        var resultsByRule = results.ToDictionary(
            result => result.RuleId.Value,
            result => result,
            StringComparer.OrdinalIgnoreCase);

        var byControl = new Dictionary<string, List<(RuleDefinition Definition, RuleResult Result)>>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var definition in definitions)
        {
            if (!resultsByRule.TryGetValue(definition.Id.Value, out var result))
            {
                continue;
            }

            foreach (var mapping in definition.FrameworkMappings.Where(mapping =>
                         string.Equals(mapping.Framework, IsoControlCatalogue.Framework, StringComparison.OrdinalIgnoreCase)))
            {
                if (!_assessments.ContainsKey(mapping.ControlId))
                {
                    continue;
                }

                if (!byControl.TryGetValue(mapping.ControlId, out var list))
                {
                    list = [];
                    byControl[mapping.ControlId] = list;
                }

                list.Add((definition, result));
            }
        }

        foreach (var (controlId, mapped) in byControl)
        {
            var current = _assessments[controlId];

            _assessments[controlId] = current with
            {
                MappedRuleIds = mapped
                    .Select(entry => entry.Definition.Id.Value)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(id => id, StringComparer.Ordinal)
                    .ToList(),
                EvidenceReferences = mapped
                    .SelectMany(entry => entry.Result.EvidenceReferences)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                Suggested = Suggest(mapped.Select(entry => entry.Result).ToList()),
                LastUpdatedAt = appliedAt,
            };
        }
    }

    /// <summary>
    /// Derives the status the automated evidence suggests. Every mapped rule passing suggests the
    /// control is satisfied; any failure suggests otherwise. A suggestion never sets the status.
    /// </summary>
    public static SuggestedStatus Suggest(IReadOnlyCollection<RuleResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        var evaluated = results.Where(result => result.IsScored).ToList();

        if (evaluated.Count == 0)
        {
            return SuggestedStatus.None;
        }

        var failed = evaluated.Count(result => result.Status == RuleStatus.Fail);

        if (failed == 0)
        {
            return SuggestedStatus.SuggestSatisfied;
        }

        return failed == evaluated.Count ? SuggestedStatus.SuggestUnsatisfied : SuggestedStatus.SuggestPartial;
    }

    /// <summary>
    /// Records the operator's judgement for a control. Confirmation is explicit: a status set here
    /// is attributed to the operator, not to the automated evidence.
    /// </summary>
    public ControlAssessment RecordStatus(
        string controlId,
        ControlStatus status,
        string recordedBy,
        DateTimeOffset recordedAt,
        string? notes = null,
        string? owner = null,
        DateTimeOffset? reviewDate = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(controlId);
        ArgumentException.ThrowIfNullOrWhiteSpace(recordedBy);

        var current = Get(controlId);

        var updated = current with
        {
            Status = status,
            OperatorConfirmed = true,
            Notes = notes ?? current.Notes,
            Owner = owner ?? current.Owner,
            ReviewDate = reviewDate ?? current.ReviewDate,
            LastUpdatedAt = recordedAt,
        };

        _assessments[controlId] = updated;
        return updated;
    }

    /// <summary>Marks a control as in or out of scope for the assessment.</summary>
    public ControlAssessment SetApplicability(string controlId, bool isApplicable, DateTimeOffset updatedAt)
    {
        var current = Get(controlId);

        var updated = current with
        {
            IsApplicable = isApplicable,
            Status = isApplicable ? current.Status : ControlStatus.NotApplicable,
            OperatorConfirmed = isApplicable ? current.OperatorConfirmed : true,
            LastUpdatedAt = updatedAt,
        };

        _assessments[controlId] = updated;
        return updated;
    }

    /// <summary>Adds an operator attestation to a control.</summary>
    public ControlAssessment AddAttestation(Attestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);

        var current = Get(attestation.ControlId);

        var updated = current with
        {
            Attestations = [.. current.Attestations, attestation],
            AttachmentIds = current.AttachmentIds
                .Concat(attestation.AttachmentIds)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            LastUpdatedAt = attestation.AttestedAt,
        };

        _assessments[attestation.ControlId] = updated;
        return updated;
    }

    /// <summary>Records operator-supplied licensed control text inside the project only.</summary>
    public ControlAssessment SetLicensedText(string controlId, string? licensedText, DateTimeOffset updatedAt)
    {
        var current = Get(controlId);
        var updated = current with { LicensedText = licensedText, LastUpdatedAt = updatedAt };

        _assessments[controlId] = updated;
        return updated;
    }

    /// <summary>Computes the readiness metrics for the framework.</summary>
    public ReadinessMetrics ComputeMetrics()
    {
        var applicable = Assessments.Where(assessment => assessment.IsApplicable).ToList();

        var distribution = new Dictionary<ControlStatus, int>();

        foreach (var status in Enum.GetValues<ControlStatus>())
        {
            distribution[status] = 0;
        }

        foreach (var assessment in Assessments)
        {
            var status = assessment.IsApplicable ? assessment.Status : ControlStatus.NotApplicable;
            distribution[status] = distribution.GetValueOrDefault(status) + 1;
        }

        return new ReadinessMetrics
        {
            Framework = IsoControlCatalogue.Framework,
            ApplicableControlCount = applicable.Count,
            AssessedControlCount = applicable.Count(assessment => assessment.IsAssessed),
            ConfirmedSatisfiedCount = applicable.Count(assessment => assessment.IsConfirmedSatisfied),
            StatusDistribution = distribution,
        };
    }

    /// <summary>
    /// Controls whose automated evidence suggests a status the operator has not yet confirmed.
    /// These are the workspace's outstanding items.
    /// </summary>
    public IReadOnlyList<ControlAssessment> PendingConfirmation() => Assessments
        .Where(assessment => assessment.IsApplicable)
        .Where(assessment => assessment.Suggested != SuggestedStatus.None)
        .Where(assessment => !assessment.OperatorConfirmed)
        .ToList();
}
