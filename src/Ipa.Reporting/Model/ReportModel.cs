using Ipa.Contracts;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Baselines;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Findings;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Reporting;
using Ipa.Contracts.Rules;
using Ipa.Contracts.Scoring;

namespace Ipa.Reporting.Model;

/// <summary>One row of the report's exclusions section.</summary>
public sealed record ReportExclusion
{
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required RuleStatus Status { get; init; }
    public EvidenceAvailability? Availability { get; init; }
    public required string Reason { get; init; }
}

/// <summary>One step of the remediation roadmap.</summary>
public sealed record RemediationStep
{
    public required int Order { get; init; }
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required RuleSeverity Severity { get; init; }
    public required string Remediation { get; init; }
    public required int AffectedObjectCount { get; init; }
    public required string Horizon { get; init; }
}

/// <summary>
/// Everything the report renders. The model is assembled once and rendered without further lookups,
/// so the same model always produces byte-identical HTML.
/// </summary>
public sealed record ReportModel
{
    public required AssessmentMetadata Metadata { get; init; }
    public required AssessmentScope Scope { get; init; }
    public required ReportProfile Profile { get; init; }
    public required PostureScoreSet Scores { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required IReadOnlyList<RuleResult> Results { get; init; }
    public required IReadOnlyList<ReportExclusion> Exclusions { get; init; }
    public required IReadOnlyList<RemediationStep> Roadmap { get; init; }
    public required ReadinessMetrics Readiness { get; init; }
    public required IReadOnlyList<ControlAssessment> Controls { get; init; }
    public required IReadOnlyList<ControlDefinition> ControlDefinitions { get; init; }
    public required IReadOnlyList<CollectionDiagnostic> Diagnostics { get; init; }
    public required IReadOnlyList<EvidenceRecord> EvidenceRecords { get; init; }
    public BaselineComparison? Baseline { get; init; }
    public ImportedBaseline? ImportedBaseline { get; init; }

    /// <summary>Rule-pack version the results were produced with.</summary>
    public required string RulePackVersion { get; init; }

    /// <summary>Application version that produced the report.</summary>
    public string ApplicationVersion { get; init; } = ProductInfo.Version;

    /// <summary>
    /// Instant printed on the report. Supplied by the caller rather than read from the clock, so a
    /// report regenerated from the same project is identical.
    /// </summary>
    public required DateTimeOffset GeneratedAt { get; init; }

    /// <summary>Certificate and other exceptions the operator accepted during collection.</summary>
    public IReadOnlyList<string> AcceptedExceptions { get; init; } = [];

    /// <summary>Findings the operator annotated, which are reported but never rescored.</summary>
    public IReadOnlyList<Finding> AnnotatedFindings =>
        Findings.Where(finding => finding.IsAnnotated).ToList();
}

/// <summary>Builds a report model from an evaluated assessment.</summary>
public static class ReportModelBuilder
{
    /// <summary>Assembles the model.</summary>
    public static ReportModel Build(
        AssessmentSession session,
        ReportProfile profile,
        ReadinessMetrics readiness,
        IReadOnlyList<ControlDefinition> controlDefinitions,
        DateTimeOffset generatedAt,
        IReadOnlyList<RuleDefinition> ruleDefinitions,
        IReadOnlyList<string>? acceptedExceptions = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(readiness);
        ArgumentNullException.ThrowIfNull(ruleDefinitions);

        if (session.Scores is null)
        {
            throw new InvalidOperationException("The assessment has not been evaluated, so no report can be produced.");
        }

        var definitionsById = ruleDefinitions.ToDictionary(
            definition => definition.Id.Value,
            definition => definition,
            StringComparer.OrdinalIgnoreCase);

        var exclusions = session.RuleResults
            .Where(result => result.Status is RuleStatus.NotCollected or RuleStatus.Error or RuleStatus.NotApplicable)
            .Select(result => new ReportExclusion
            {
                RuleId = result.RuleId.Value,
                Title = definitionsById.GetValueOrDefault(result.RuleId.Value)?.Title ?? result.RuleId.Value,
                Status = result.Status,
                Availability = result.Availability,
                Reason = result.Rationale,
            })
            .OrderBy(exclusion => exclusion.RuleId, StringComparer.Ordinal)
            .ToList();

        return new ReportModel
        {
            Metadata = session.Metadata,
            Scope = session.Scope,
            Profile = profile,
            Scores = session.Scores,
            Findings = session.Findings,
            Results = session.RuleResults,
            Exclusions = exclusions,
            Roadmap = BuildRoadmap(session.Findings),
            Readiness = readiness,
            Controls = session.ControlAssessments,
            ControlDefinitions = controlDefinitions,
            Diagnostics = session.Diagnostics,
            EvidenceRecords = session.Evidence?.Records ?? [],
            Baseline = session.Evidence?.BaselineComparison,
            ImportedBaseline = session.Baseline,
            RulePackVersion = session.RulePackVersion ?? "unknown",
            GeneratedAt = generatedAt,
            AcceptedExceptions = acceptedExceptions ?? [],
        };
    }

    /// <summary>
    /// Orders findings into a remediation roadmap: severity first, then the number of objects the
    /// finding affects, so the work that removes the most exposure appears at the top.
    /// </summary>
    public static IReadOnlyList<RemediationStep> BuildRoadmap(IReadOnlyCollection<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        return findings
            .Where(finding => finding.Disposition != FindingDisposition.FalsePositive)
            .OrderByDescending(finding => finding.Severity)
            .ThenByDescending(finding => finding.AffectedObjects.Count)
            .ThenBy(finding => finding.RuleId.Value, StringComparer.Ordinal)
            .Select((finding, index) => new RemediationStep
            {
                Order = index + 1,
                RuleId = finding.RuleId.Value,
                Title = finding.Title,
                Severity = finding.Severity,
                Remediation = finding.Remediation,
                AffectedObjectCount = finding.AffectedObjects.Count,
                Horizon = finding.Severity switch
                {
                    RuleSeverity.Critical => "Immediate",
                    RuleSeverity.High => "Within 30 days",
                    RuleSeverity.Medium => "Within 90 days",
                    _ => "Next review cycle",
                },
            })
            .ToList();
    }
}
