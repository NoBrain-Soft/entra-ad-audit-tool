namespace Ipa.Contracts.Compliance;

/// <summary>Operator-confirmed status of a compliance control.</summary>
public enum ControlStatus
{
    /// <summary>No operator judgement has been recorded yet.</summary>
    NotAssessed,

    /// <summary>The control is implemented and evidenced.</summary>
    Satisfied,

    /// <summary>The control is partially implemented.</summary>
    Partial,

    /// <summary>The control is not implemented.</summary>
    Unsatisfied,

    /// <summary>The control does not apply to the assessed scope.</summary>
    NotApplicable,
}

/// <summary>
/// A readiness status the automated findings suggest. A suggestion is never authoritative:
/// only an operator confirmation can set the control's <see cref="ControlAssessment.Status"/>.
/// </summary>
public enum SuggestedStatus
{
    None,
    SuggestSatisfied,
    SuggestPartial,
    SuggestUnsatisfied,
}

/// <summary>
/// An operator-authored statement supporting a control. Attestations are the only way a control
/// becomes satisfied on the strength of evidence the product cannot collect itself.
/// </summary>
public sealed record Attestation
{
    public required string AttestationId { get; init; }
    public required string ControlId { get; init; }
    public required string Statement { get; init; }
    public required string AttestedBy { get; init; }
    public required DateTimeOffset AttestedAt { get; init; }

    /// <summary>Identifiers of attachments stored inside the encrypted project container.</summary>
    public IReadOnlyList<string> AttachmentIds { get; init; } = [];

    public DateTimeOffset? ReviewDate { get; init; }
}

/// <summary>
/// A control definition. Only the control identifier is taken from the framework; the title and
/// guidance are written by this product. Normative framework text is never redistributed, and the
/// operator may paste their own licensed description into <see cref="ControlAssessment.LicensedText"/>.
/// </summary>
public sealed record ControlDefinition
{
    /// <summary>Framework identifier, for example <c>ISO/IEC 27001:2022</c>.</summary>
    public required string Framework { get; init; }

    /// <summary>Control identifier within the framework, for example <c>A.5.15</c>.</summary>
    public required string ControlId { get; init; }

    /// <summary>Tool-authored short label. Not the framework's own control title.</summary>
    public required string ToolAuthoredLabel { get; init; }

    /// <summary>Tool-authored explanation of what this product examines for the control.</summary>
    public required string ToolAuthoredGuidance { get; init; }

    /// <summary>Theme grouping used in the user interface, for example <c>Organisational</c>.</summary>
    public required string Theme { get; init; }
}

/// <summary>The operator's working state for one control within an assessment.</summary>
public sealed record ControlAssessment
{
    public required string ControlId { get; init; }

    /// <summary>Whether the control is in scope for this assessment.</summary>
    public bool IsApplicable { get; init; } = true;

    public ControlStatus Status { get; init; } = ControlStatus.NotAssessed;

    /// <summary>Automated suggestion derived from mapped rule results. Advisory only.</summary>
    public SuggestedStatus Suggested { get; init; } = SuggestedStatus.None;

    /// <summary>True once an operator has explicitly confirmed the status.</summary>
    public bool OperatorConfirmed { get; init; }

    public string? Owner { get; init; }

    public string? Notes { get; init; }

    /// <summary>Operator-pasted licensed control text. Never shipped with the product.</summary>
    public string? LicensedText { get; init; }

    /// <summary>Rule identifiers whose results were mapped to this control.</summary>
    public IReadOnlyList<string> MappedRuleIds { get; init; } = [];

    /// <summary>Evidence record identifiers linked to this control.</summary>
    public IReadOnlyList<string> EvidenceReferences { get; init; } = [];

    public IReadOnlyList<Attestation> Attestations { get; init; } = [];

    public IReadOnlyList<string> AttachmentIds { get; init; } = [];

    public DateTimeOffset? ReviewDate { get; init; }

    public DateTimeOffset? LastUpdatedAt { get; init; }

    /// <summary>
    /// True when the control counts as assessed: an operator recorded a status, or mapped
    /// automated evidence exists and the operator confirmed it.
    /// </summary>
    public bool IsAssessed => IsApplicable && Status != ControlStatus.NotAssessed;

    /// <summary>True when the control is confirmed satisfied by the operator.</summary>
    public bool IsConfirmedSatisfied =>
        IsApplicable && OperatorConfirmed && Status == ControlStatus.Satisfied;
}

/// <summary>Readiness metrics for a framework. Always presented as readiness, never certification.</summary>
public sealed record ReadinessMetrics
{
    public required string Framework { get; init; }

    public required int ApplicableControlCount { get; init; }

    public required int AssessedControlCount { get; init; }

    public required int ConfirmedSatisfiedCount { get; init; }

    public IReadOnlyDictionary<ControlStatus, int> StatusDistribution { get; init; } =
        new Dictionary<ControlStatus, int>();

    /// <summary>Assessed applicable controls divided by all applicable controls.</summary>
    public double EvidenceCoverage => ApplicableControlCount == 0
        ? 0d
        : AssessedControlCount / (double)ApplicableControlCount;

    /// <summary>Confirmed satisfied applicable controls divided by assessed applicable controls.</summary>
    public double Readiness => AssessedControlCount == 0
        ? 0d
        : ConfirmedSatisfiedCount / (double)AssessedControlCount;

    public int EvidenceCoveragePercent =>
        (int)Math.Round(EvidenceCoverage * 100d, MidpointRounding.AwayFromZero);

    public int ReadinessPercent =>
        (int)Math.Round(Readiness * 100d, MidpointRounding.AwayFromZero);

    /// <summary>Mandatory qualifier shown wherever these metrics appear.</summary>
    public string Disclaimer => ProductInfo.IsoReadinessDisclaimer;
}
