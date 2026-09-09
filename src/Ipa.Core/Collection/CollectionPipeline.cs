using Ipa.Contracts;
using Ipa.Contracts.Baselines;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Security;

namespace Ipa.Core.Collection;

/// <summary>One ordered stage of the collection run.</summary>
/// <param name="Name">Operator-facing stage name.</param>
/// <param name="Collectors">Collectors belonging to the stage.</param>
public sealed record CollectionStage(string Name, IReadOnlyList<ICollector> Collectors);

/// <summary>The outcome of a full collection run.</summary>
public sealed record CollectionRunResult
{
    /// <summary>The merged normalised evidence.</summary>
    public required NormalizedEvidence Evidence { get; init; }

    /// <summary>Per-collector results, in the order the collectors ran.</summary>
    public required IReadOnlyList<CollectionResult> Results { get; init; }

    /// <summary>The combined diagnostic log.</summary>
    public required IReadOnlyList<CollectionDiagnostic> Diagnostics { get; init; }

    /// <summary>True when the operator cancelled before every stage completed.</summary>
    public bool WasCancelled { get; init; }

    /// <summary>Collectors that failed and can be rerun without discarding valid results.</summary>
    public IReadOnlyList<string> FailedCollectorIds => Results
        .Where(result => result.Outcome is CollectionOutcome.Failed)
        .Select(result => result.CollectorId)
        .ToList();
}

/// <summary>
/// Runs collectors in ordered stages.
/// </summary>
/// <remarks>
/// Collectors that read the same source run in sequence, because each contributes to the same
/// evidence fragment and a concurrent write would lose one of the contributions. Different sources
/// run in parallel, bounded by the configured degree. Cancellation is honoured between and within
/// stages, and a failing collector never aborts the run: its evidence is marked unavailable so the
/// rules that need it report as not collected, and the collector can be rerun on its own afterwards.
/// </remarks>
public sealed class CollectionPipeline
{
    private readonly int _maxParallelSources;

    public CollectionPipeline(int maxParallelSources = 2)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxParallelSources, 1);
        _maxParallelSources = maxParallelSources;
    }

    /// <summary>Runs the supplied stages in order.</summary>
    /// <param name="stages">Ordered stages. Later stages see the evidence earlier ones produced.</param>
    /// <param name="context">Base collection context. Each collector receives a copy with the accumulated evidence.</param>
    /// <param name="cancellationToken">Cancellation token honoured between collectors.</param>
    public async Task<CollectionRunResult> RunAsync(
        IReadOnlyList<CollectionStage> stages,
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stages);
        ArgumentNullException.ThrowIfNull(context);

        var accumulator = new EvidenceAccumulator(context.ReferenceTime);
        var results = new List<CollectionResult>();
        var diagnostics = new List<CollectionDiagnostic>();
        var cancelled = false;

        var diagnosticSink = new Action<CollectionDiagnostic>(diagnostic =>
        {
            lock (diagnostics)
            {
                diagnostics.Add(diagnostic);
            }

            context.Diagnostics?.Invoke(diagnostic);
        });

        foreach (var stage in stages)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                cancelled = true;
                break;
            }

            var applicable = stage.Collectors
                .Where(collector => collector.AppliesTo(context with { PreviousEvidence = accumulator.Snapshot() }))
                .ToList();

            var skipped = stage.Collectors.Except(applicable).ToList();

            foreach (var collector in skipped)
            {
                results.Add(BuildSkippedResult(collector, context));
            }

            if (applicable.Count == 0)
            {
                continue;
            }

            // Collectors reading the same source share an evidence fragment, so they run in order.
            var chains = applicable
                .GroupBy(collector => collector.Source)
                .Select(group => group.ToList())
                .ToList();

            using var throttle = new SemaphoreSlim(Math.Min(_maxParallelSources, chains.Count));

            var chainTasks = chains.Select(async chain =>
            {
                await throttle.WaitAsync(cancellationToken).ConfigureAwait(false);

                try
                {
                    var chainResults = new List<CollectionResult>();

                    foreach (var collector in chain)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var collectorContext = context with
                        {
                            PreviousEvidence = accumulator.Snapshot(),
                            Diagnostics = diagnosticSink,
                        };

                        var result = await RunCollectorAsync(collector, collectorContext, cancellationToken)
                            .ConfigureAwait(false);

                        accumulator.Merge(result);
                        chainResults.Add(result);
                    }

                    return chainResults;
                }
                finally
                {
                    throttle.Release();
                }
            });

            try
            {
                var completed = await Task.WhenAll(chainTasks).ConfigureAwait(false);
                results.AddRange(completed.SelectMany(chain => chain));
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
                break;
            }
        }

        return new CollectionRunResult
        {
            Evidence = accumulator.Build(),
            Results = results,
            Diagnostics = diagnostics.OrderBy(diagnostic => diagnostic.Timestamp).ToList(),
            WasCancelled = cancelled || cancellationToken.IsCancellationRequested,
        };
    }

    /// <summary>
    /// Reruns a subset of collectors against evidence that has already been collected, so a failed
    /// stage can be retried without discarding the results that succeeded.
    /// </summary>
    public async Task<CollectionRunResult> RerunAsync(
        IReadOnlyList<ICollector> collectors,
        NormalizedEvidence existingEvidence,
        IReadOnlyList<CollectionResult> existingResults,
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(collectors);
        ArgumentNullException.ThrowIfNull(existingEvidence);
        ArgumentNullException.ThrowIfNull(existingResults);

        var rerun = await RunAsync(
                [new CollectionStage("Rerun", collectors)],
                context with { PreviousEvidence = existingEvidence },
                cancellationToken)
            .ConfigureAwait(false);

        var rerunIds = collectors.Select(collector => collector.CollectorId).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Results for collectors that were not rerun are preserved exactly as they were.
        var merged = existingResults
            .Where(result => !rerunIds.Contains(result.CollectorId))
            .Concat(rerun.Results)
            .ToList();

        var accumulator = new EvidenceAccumulator(context.ReferenceTime, existingEvidence);

        foreach (var result in rerun.Results)
        {
            accumulator.Merge(result);
        }

        return new CollectionRunResult
        {
            Evidence = accumulator.Build(),
            Results = merged,
            Diagnostics = rerun.Diagnostics,
            WasCancelled = rerun.WasCancelled,
        };
    }

    private static async Task<CollectionResult> RunCollectorAsync(
        ICollector collector,
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        var startedAt = DateTimeOffset.UtcNow;

        try
        {
            return await collector.CollectAsync(context, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // A collector that throws instead of reporting a failure must still leave the run in a
            // consistent state: its evidence is marked as errored so the rules that need it report
            // NotCollected rather than passing on absent data.
            var diagnostic = new CollectionDiagnostic
            {
                Timestamp = DateTimeOffset.UtcNow,
                Severity = DiagnosticSeverity.Error,
                CollectorId = collector.CollectorId,
                Message = Redaction.Scrub($"The collector failed unexpectedly: {ex.Message}"),
                Code = "UnhandledCollectorFailure",
                ExceptionType = ex.GetType().Name,
            };

            context.Log(diagnostic);

            return new CollectionResult
            {
                CollectorId = collector.CollectorId,
                Outcome = CollectionOutcome.Failed,
                StartedAt = startedAt,
                CompletedAt = DateTimeOffset.UtcNow,
                Availability = collector.ProducedEvidenceKeys
                    .Select(key => new EvidenceAvailabilityEntry
                    {
                        EvidenceKey = key,
                        Availability = EvidenceAvailability.Error,
                        Reason = "The collector failed unexpectedly.",
                    })
                    .ToList(),
                Diagnostics = [diagnostic],
            };
        }
    }

    private static CollectionResult BuildSkippedResult(ICollector collector, CollectionContext context) => new()
    {
        CollectorId = collector.CollectorId,
        Outcome = CollectionOutcome.Skipped,
        StartedAt = DateTimeOffset.UtcNow,
        CompletedAt = DateTimeOffset.UtcNow,
        Availability = collector.ProducedEvidenceKeys
            .Select(key => new EvidenceAvailabilityEntry
            {
                EvidenceKey = key,
                Availability = EvidenceAvailability.NotSelected,
                Reason = $"The {collector.DisplayName} collector does not apply to the selected scope.",
            })
            .ToList(),
    };
}

/// <summary>
/// Merges evidence fragments from collectors into one normalised view, keeping the availability map
/// and the evidence records aligned with what was actually produced.
/// </summary>
public sealed class EvidenceAccumulator
{
    private readonly DateTimeOffset _referenceTime;
    private readonly Dictionary<string, EvidenceAvailabilityEntry> _availability = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<EvidenceRecord> _records = [];
    private readonly Lock _gate = new();

    private ActiveDirectoryEvidence? _activeDirectory;
    private EntraEvidence? _entra;
    private HybridEvidence? _hybrid;
    private BaselineComparison? _baseline;

    public EvidenceAccumulator(DateTimeOffset referenceTime, NormalizedEvidence? seed = null)
    {
        _referenceTime = referenceTime;

        if (seed is null)
        {
            return;
        }

        _activeDirectory = seed.ActiveDirectory;
        _entra = seed.Entra;
        _hybrid = seed.Hybrid;
        _baseline = seed.BaselineComparison;
        _records.AddRange(seed.Records);

        foreach (var entry in seed.Availability)
        {
            _availability[entry.Key] = entry.Value;
        }
    }

    /// <summary>Merges one collector result into the accumulated evidence.</summary>
    public void Merge(CollectionResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        lock (_gate)
        {
            if (result.Fragment.ActiveDirectory is { } activeDirectory)
            {
                _activeDirectory = activeDirectory;
            }

            if (result.Fragment.Entra is { } entra)
            {
                _entra = entra;
            }

            if (result.Fragment.Hybrid is { } hybrid)
            {
                _hybrid = hybrid;
            }

            if (result.Fragment.BaselineComparison is { } baseline)
            {
                _baseline = baseline;
            }

            foreach (var entry in result.Availability)
            {
                // A later successful collection supersedes an earlier unavailable one, which is
                // what makes rerunning a failed collector restore coverage.
                if (!_availability.TryGetValue(entry.EvidenceKey, out var existing)
                    || entry.IsAvailable
                    || !existing.IsAvailable)
                {
                    _availability[entry.EvidenceKey] = entry;
                }
            }

            foreach (var record in result.Records)
            {
                _records.RemoveAll(existing =>
                    string.Equals(existing.EvidenceId, record.EvidenceId, StringComparison.OrdinalIgnoreCase));

                _records.Add(record);
            }
        }
    }

    /// <summary>Attaches a baseline comparison produced outside the collector pipeline.</summary>
    public void SetBaselineComparison(BaselineComparison comparison)
    {
        ArgumentNullException.ThrowIfNull(comparison);

        lock (_gate)
        {
            _baseline = comparison;
            _availability[EvidenceKeys.BaselineComparison] = new EvidenceAvailabilityEntry
            {
                EvidenceKey = EvidenceKeys.BaselineComparison,
                Availability = EvidenceAvailability.Collected,
            };
        }
    }

    /// <summary>Returns the evidence collected so far, for the next collector in a chain.</summary>
    public NormalizedEvidence Snapshot() => Build();

    /// <summary>Builds the merged normalised evidence.</summary>
    public NormalizedEvidence Build()
    {
        lock (_gate)
        {
            return new NormalizedEvidence
            {
                ActiveDirectory = _activeDirectory,
                Entra = _entra,
                Hybrid = _hybrid,
                BaselineComparison = _baseline,
                Availability = new Dictionary<string, EvidenceAvailabilityEntry>(_availability, StringComparer.OrdinalIgnoreCase),
                Records = [.. _records],
                ReferenceTime = _referenceTime,
            };
        }
    }
}
