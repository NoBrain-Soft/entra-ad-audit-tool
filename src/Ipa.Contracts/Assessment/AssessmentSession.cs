using Ipa.Contracts.Baselines;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Findings;
using Ipa.Contracts.Reporting;
using Ipa.Contracts.Rules;
using Ipa.Contracts.Scoring;

namespace Ipa.Contracts.Assessment;

/// <summary>Customer and assessor metadata captured before collection starts.</summary>
public sealed record AssessmentMetadata
{
    public required string CustomerName { get; init; }
    public string? CustomerReference { get; init; }
    public required string AssessorName { get; init; }
    public string? AssessorCompany { get; init; }
    public string? EngagementReference { get; init; }
    public string? ScopeNotes { get; init; }
    public DateTimeOffset? PlannedStartDate { get; init; }
    public DateTimeOffset? PlannedEndDate { get; init; }
}

/// <summary>Which identity sources are in scope for this assessment.</summary>
public sealed record AssessmentScope
{
    public bool IncludeActiveDirectory { get; init; }
    public bool IncludeEntra { get; init; }

    /// <summary>
    /// Hybrid rules are evaluated only when both sources are connected. With one source the
    /// hybrid score is disabled and the missing source is stated explicitly.
    /// </summary>
    public bool IncludeHybrid => IncludeActiveDirectory && IncludeEntra;

    public IReadOnlyCollection<CheckGroup> SelectedGroups { get; init; } = [];

    /// <summary>True when the scope selects nothing at all and collection cannot start.</summary>
    public bool IsEmpty => !IncludeActiveDirectory && !IncludeEntra;
}

/// <summary>Lifecycle state of an assessment session.</summary>
public enum AssessmentState
{
    Created,
    Connected,
    PreflightComplete,
    Collecting,
    Collected,
    Evaluated,
    Reported,
    Failed,
}

/// <summary>
/// One assessment of one Active Directory forest and/or one Entra tenant. Sessions are ephemeral
/// by default: state lives in a temporary encrypted database that is deleted on normal exit
/// unless the operator explicitly saves a project.
/// </summary>
public sealed record AssessmentSession
{
    public required Guid AssessmentId { get; init; }

    public required AssessmentMetadata Metadata { get; init; }

    public required AssessmentScope Scope { get; init; }

    public AssessmentState State { get; init; } = AssessmentState.Created;

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Fixed reference instant for the whole run, so recalculation is deterministic.</summary>
    public required DateTimeOffset ReferenceTime { get; init; }

    /// <summary>Application version that produced the session.</summary>
    public string ApplicationVersion { get; init; } = ProductInfo.Version;

    /// <summary>Rule-pack version used for evaluation. Recorded so scores stay reproducible.</summary>
    public string? RulePackVersion { get; init; }

    public NormalizedEvidence? Evidence { get; init; }

    public IReadOnlyList<CollectionResult> CollectionResults { get; init; } = [];

    public IReadOnlyList<RuleResult> RuleResults { get; init; } = [];

    public IReadOnlyList<Finding> Findings { get; init; } = [];

    public PostureScoreSet? Scores { get; init; }

    public IReadOnlyList<ControlAssessment> ControlAssessments { get; init; } = [];

    public ImportedBaseline? Baseline { get; init; }

    public ReportProfile? ReportProfile { get; init; }

    public IReadOnlyList<CollectionDiagnostic> Diagnostics { get; init; } = [];

    /// <summary>True when nothing has been collected yet.</summary>
    public bool IsEmpty => Evidence is null && CollectionResults.Count == 0;
}
