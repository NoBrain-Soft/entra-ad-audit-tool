namespace Ipa.Contracts.Evidence;

/// <summary>Kind of artefact an <see cref="EvidenceRecord"/> describes.</summary>
public enum EvidenceKind
{
    /// <summary>A directory or tenant query result normalised into the evidence model.</summary>
    DirectoryQuery,

    /// <summary>A policy document such as a GPO, Conditional Access policy or password policy.</summary>
    PolicyDocument,

    /// <summary>A derived correlation such as a hybrid identity match.</summary>
    Correlation,

    /// <summary>Content parsed from an operator-imported baseline package.</summary>
    ImportedBaseline,

    /// <summary>An operator-supplied file attached to a finding or control.</summary>
    OperatorAttachment,

    /// <summary>An operator-authored statement supporting a compliance control.</summary>
    OperatorAttestation,
}

/// <summary>
/// Auditable record of one collected artefact. Records are what the report's evidence appendix
/// and the user interface drill-down display; rule evaluation itself reads the strongly typed
/// normalised model rather than these envelopes.
/// </summary>
public sealed record EvidenceRecord
{
    /// <summary>Stable identifier, unique within an assessment.</summary>
    public required string EvidenceId { get; init; }

    public required EvidenceKind Kind { get; init; }

    public required AssessmentSource Source { get; init; }

    /// <summary>Identifier of the collector that produced the record.</summary>
    public required string CollectorId { get; init; }

    public required DateTimeOffset CollectedAt { get; init; }

    /// <summary>Short, non-sensitive description shown without opting into raw evidence.</summary>
    public required string Summary { get; init; }

    /// <summary>Classification governing whether the payload appears in a default report.</summary>
    public Sensitivity Sensitivity { get; init; } = Sensitivity.Summary;

    /// <summary>
    /// Optional canonical payload (JSON) retained for the evidence appendix. Never contains
    /// credentials, tokens or password material; collectors redact before recording.
    /// </summary>
    public string? Payload { get; init; }

    /// <summary>SHA-256 of <see cref="Payload"/> when present, used for container integrity.</summary>
    public string? PayloadSha256 { get; init; }

    /// <summary>Identifier of a stored attachment inside the encrypted project container.</summary>
    public string? AttachmentId { get; init; }
}
