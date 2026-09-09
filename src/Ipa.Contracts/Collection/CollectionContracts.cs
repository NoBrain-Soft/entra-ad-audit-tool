using Ipa.Contracts.Evidence;

namespace Ipa.Contracts.Collection;

/// <summary>A prerequisite a collector needs before it can run.</summary>
public sealed record CollectorPrerequisite(string Name, string Description);

/// <summary>Severity of a collection diagnostic entry.</summary>
public enum DiagnosticSeverity
{
    Debug,
    Information,
    Warning,
    Error,
}

/// <summary>
/// One entry of the collection diagnostic log. Entries are shown in the user interface and
/// included in the report so that "not collected" is always explainable.
/// </summary>
public sealed record CollectionDiagnostic
{
    public required DateTimeOffset Timestamp { get; init; }
    public required DiagnosticSeverity Severity { get; init; }
    public required string CollectorId { get; init; }
    public required string Message { get; init; }
    public string? Code { get; init; }

    /// <summary>Exception type name only. Messages are redacted before they reach this log.</summary>
    public string? ExceptionType { get; init; }

    /// <summary>Number of retry attempts made before this entry was written.</summary>
    public int Attempt { get; init; }
}

/// <summary>Progress notification raised by a collector while it runs.</summary>
public sealed record CollectionProgress
{
    public required string CollectorId { get; init; }
    public required string StageName { get; init; }
    public required string Activity { get; init; }

    /// <summary>Items processed so far, when a total is known.</summary>
    public int? Completed { get; init; }

    /// <summary>Total items, when known ahead of time.</summary>
    public int? Total { get; init; }

    public double? Fraction => Total is > 0 && Completed is not null
        ? Math.Clamp(Completed.Value / (double)Total.Value, 0d, 1d)
        : null;
}

/// <summary>Outcome of running one collector.</summary>
public enum CollectionOutcome
{
    /// <summary>Every declared evidence set was produced.</summary>
    Succeeded,

    /// <summary>Some evidence sets were produced; others are marked unavailable with a reason.</summary>
    PartiallySucceeded,

    /// <summary>Nothing was produced. The failure reason is recorded in the diagnostics.</summary>
    Failed,

    /// <summary>The operator cancelled the run before the collector completed.</summary>
    Cancelled,

    /// <summary>The collector was not applicable to the selected scope and did not run.</summary>
    Skipped,
}

/// <summary>The result of one collector run.</summary>
public sealed record CollectionResult
{
    public required string CollectorId { get; init; }
    public required CollectionOutcome Outcome { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }

    /// <summary>Availability of every evidence set the collector declared.</summary>
    public IReadOnlyList<EvidenceAvailabilityEntry> Availability { get; init; } = [];

    /// <summary>Evidence records produced for the audit appendix.</summary>
    public IReadOnlyList<EvidenceRecord> Records { get; init; } = [];

    public IReadOnlyList<CollectionDiagnostic> Diagnostics { get; init; } = [];

    /// <summary>
    /// Fragment of the normalised evidence produced by this collector. The pipeline merges
    /// fragments from every collector into the single <see cref="NormalizedEvidence"/> instance.
    /// </summary>
    public EvidenceFragment Fragment { get; init; } = new();

    public TimeSpan Duration => CompletedAt - StartedAt;
}

/// <summary>
/// A partial contribution to the normalised evidence model. Exactly one collector owns each
/// property; the merge step rejects conflicting contributions.
/// </summary>
public sealed record EvidenceFragment
{
    public ActiveDirectoryEvidence? ActiveDirectory { get; init; }
    public EntraEvidence? Entra { get; init; }
    public HybridEvidence? Hybrid { get; init; }
    public Baselines.BaselineComparison? BaselineComparison { get; init; }
}

/// <summary>Everything a collector needs to run, supplied by the pipeline.</summary>
public sealed record CollectionContext
{
    /// <summary>Identifier of the assessment this collection belongs to.</summary>
    public required Guid AssessmentId { get; init; }

    /// <summary>Fixed reference instant. Every age comparison uses this value, never the wall clock.</summary>
    public required DateTimeOffset ReferenceTime { get; init; }

    /// <summary>Check groups the operator selected. Collectors gather only what these require.</summary>
    public required IReadOnlyCollection<CheckGroup> SelectedGroups { get; init; }

    /// <summary>Maximum number of concurrent requests a collector may issue.</summary>
    public int MaxConcurrency { get; init; } = 4;

    /// <summary>Retry budget per transient failure.</summary>
    public int MaxRetries { get; init; } = 3;

    /// <summary>Evidence contributed by collectors that already ran in this session.</summary>
    public NormalizedEvidence? PreviousEvidence { get; init; }

    /// <summary>Sink for progress notifications.</summary>
    public IProgress<CollectionProgress>? Progress { get; init; }

    /// <summary>Sink for diagnostics. Implementations redact secrets before writing.</summary>
    public Action<CollectionDiagnostic>? Diagnostics { get; init; }

    public void Report(CollectionProgress progress) => Progress?.Report(progress);

    public void Log(CollectionDiagnostic diagnostic) => Diagnostics?.Invoke(diagnostic);
}

/// <summary>
/// A source of normalised evidence. Collectors are the only components permitted to perform
/// network input and output, and they are strictly read-only: no implementation may issue a
/// write, modify or delete request against a directory or tenant.
/// </summary>
public interface ICollector
{
    /// <summary>Stable identifier, for example <c>ad.directory</c> or <c>entra.roles</c>.</summary>
    string CollectorId { get; }

    /// <summary>Operator-facing name shown in the collection progress view.</summary>
    string DisplayName { get; }

    /// <summary>Identity source this collector reads from.</summary>
    AssessmentSource Source { get; }

    /// <summary>Prerequisites that must hold before the collector can run.</summary>
    IReadOnlyList<CollectorPrerequisite> Prerequisites { get; }

    /// <summary>Permissions or protocol access the collector requires.</summary>
    IReadOnlyList<string> RequiredPermissions { get; }

    /// <summary>Evidence keys the collector produces when it succeeds.</summary>
    IReadOnlyList<string> ProducedEvidenceKeys { get; }

    /// <summary>Check groups that need this collector. An unselected collector is skipped.</summary>
    IReadOnlyList<CheckGroup> SupportedGroups { get; }

    /// <summary>Returns true when the collector should run for the supplied context.</summary>
    bool AppliesTo(CollectionContext context);

    /// <summary>Runs the collector. Implementations must honour cancellation promptly.</summary>
    Task<CollectionResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken);
}
