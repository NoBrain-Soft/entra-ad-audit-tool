namespace Ipa.Contracts.Rules;

/// <summary>A directory or tenant object a rule result refers to.</summary>
public sealed record AffectedObject
{
    /// <summary>Stable identifier: object SID, Entra object id, GPO GUID or policy identifier.</summary>
    public required string Identifier { get; init; }

    /// <summary>Human-readable label shown in the user interface and reports.</summary>
    public required string DisplayName { get; init; }

    /// <summary>Object class, for example <c>user</c>, <c>group</c>, <c>gpo</c>, <c>servicePrincipal</c>.</summary>
    public required string ObjectType { get; init; }

    public AssessmentSource Source { get; init; } = AssessmentSource.ActiveDirectory;

    /// <summary>Supporting detail such as the offending attribute value or ACE right.</summary>
    public string? Detail { get; init; }

    /// <summary>Classification used to decide whether the detail appears in a default report.</summary>
    public Sensitivity Sensitivity { get; init; } = Sensitivity.ObjectIdentifying;
}

/// <summary>A note recorded during evaluation: why data was missing, or what was skipped.</summary>
public sealed record DiagnosticNote(string Code, string Message);

/// <summary>
/// Outcome of evaluating one rule. Results are pure functions of the normalised evidence and
/// the rule version, so recalculation is deterministic.
/// </summary>
public sealed record RuleResult
{
    public required RuleId RuleId { get; init; }

    public required int RuleVersion { get; init; }

    public required RuleStatus Status { get; init; }

    public required DateTimeOffset EvaluatedAt { get; init; }

    /// <summary>Explanation of the outcome, including the observed values that drove it.</summary>
    public required string Rationale { get; init; }

    /// <summary>Identifiers of the <see cref="Evidence.EvidenceRecord"/> instances consulted.</summary>
    public IReadOnlyList<string> EvidenceReferences { get; init; } = [];

    public IReadOnlyList<AffectedObject> AffectedObjects { get; init; } = [];

    public IReadOnlyList<DiagnosticNote> Diagnostics { get; init; } = [];

    /// <summary>Reason the evidence was unavailable. Set only for <see cref="RuleStatus.NotCollected"/>.</summary>
    public EvidenceAvailability? Availability { get; init; }

    /// <summary>True when the result contributes weight to the posture denominator.</summary>
    public bool IsScored => Status is RuleStatus.Pass or RuleStatus.Fail;

    /// <summary>True when the result reduces weighted collection coverage.</summary>
    public bool ReducesCoverage => Status is RuleStatus.NotCollected or RuleStatus.Error;
}
