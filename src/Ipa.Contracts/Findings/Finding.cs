using Ipa.Contracts.Rules;

namespace Ipa.Contracts.Findings;

/// <summary>Operator disposition of a finding. Dispositions never change the raw score.</summary>
public enum FindingDisposition
{
    /// <summary>Default state: the finding stands as reported.</summary>
    Open,

    /// <summary>The operator accepts the risk. Annotated in the report; the score is unchanged.</summary>
    RiskAccepted,

    /// <summary>The operator judges the finding incorrect. Annotated in the report; the score is unchanged.</summary>
    FalsePositive,

    /// <summary>Remediation is confirmed by the operator but not re-collected.</summary>
    RemediationPlanned,
}

/// <summary>Operator-supplied justification attached to a disposition.</summary>
public sealed record FindingException
{
    public required FindingDisposition Disposition { get; init; }
    public required string Justification { get; init; }
    public required string RecordedBy { get; init; }
    public required DateTimeOffset RecordedAt { get; init; }
    public DateTimeOffset? ReviewDate { get; init; }
}

/// <summary>
/// A reportable issue derived from a rule result. Findings carry the workflow state an operator
/// adds on top of the deterministic evaluation; the underlying <see cref="RuleResult"/> is never
/// mutated by that workflow.
/// </summary>
public sealed record Finding
{
    public required string FindingId { get; init; }
    public required RuleId RuleId { get; init; }
    public required int RuleVersion { get; init; }
    public required string Title { get; init; }
    public required RuleSeverity Severity { get; init; }
    public required RuleDomain Domain { get; init; }
    public required CheckGroup Group { get; init; }
    public required RuleStatus Status { get; init; }

    /// <summary>Why the finding matters, taken from the rule definition.</summary>
    public required string RiskExplanation { get; init; }

    /// <summary>What the operator should do. The product never performs remediation itself.</summary>
    public required string Remediation { get; init; }

    /// <summary>What was observed, taken from the rule result.</summary>
    public required string Rationale { get; init; }

    public IReadOnlyList<AffectedObject> AffectedObjects { get; init; } = [];

    public IReadOnlyList<string> EvidenceReferences { get; init; } = [];

    public IReadOnlyList<ReferenceLink> References { get; init; } = [];

    public IReadOnlyList<FrameworkMapping> FrameworkMappings { get; init; } = [];

    /// <summary>Free-text operator notes carried into the report.</summary>
    public string? OperatorNotes { get; init; }

    /// <summary>Disposition and justification, when the operator has recorded one.</summary>
    public FindingException? Exception { get; init; }

    public FindingDisposition Disposition => Exception?.Disposition ?? FindingDisposition.Open;

    /// <summary>True when the finding is annotated but still counted in the raw score.</summary>
    public bool IsAnnotated => Exception is not null;

    public required DateTimeOffset DetectedAt { get; init; }
}
