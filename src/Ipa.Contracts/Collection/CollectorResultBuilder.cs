using Ipa.Contracts.Evidence;
using Ipa.Contracts.Security;

namespace Ipa.Contracts.Collection;

/// <summary>
/// Accumulates the availability entries, diagnostics and evidence records a collector produces,
/// and applies redaction consistently before anything reaches a log or a report.
/// </summary>
public sealed class CollectorResultBuilder
{
    private readonly string _collectorId;
    private readonly AssessmentSource _source;
    private readonly CollectionContext _context;
    private readonly List<EvidenceAvailabilityEntry> _availability = [];
    private readonly List<CollectionDiagnostic> _diagnostics = [];
    private readonly List<EvidenceRecord> _records = [];
    private readonly DateTimeOffset _startedAt;

    public CollectorResultBuilder(string collectorId, AssessmentSource source, CollectionContext context)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(collectorId);
        ArgumentNullException.ThrowIfNull(context);

        _collectorId = collectorId;
        _source = source;
        _context = context;
        _startedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>Records an evidence set as successfully collected.</summary>
    public void MarkCollected(string evidenceKey) =>
        _availability.Add(new EvidenceAvailabilityEntry
        {
            EvidenceKey = evidenceKey,
            Availability = EvidenceAvailability.Collected,
        });

    /// <summary>Records an evidence set as unavailable, with the reason a rule will report.</summary>
    public void MarkUnavailable(string evidenceKey, EvidenceAvailability availability, string reason)
    {
        _availability.Add(new EvidenceAvailabilityEntry
        {
            EvidenceKey = evidenceKey,
            Availability = availability,
            Reason = Redaction.Scrub(reason),
        });
    }

    /// <summary>Writes a diagnostic entry, scrubbing any secret the message might carry.</summary>
    public void Log(DiagnosticSeverity severity, string message, string? code = null, Exception? exception = null, int attempt = 0)
    {
        var diagnostic = new CollectionDiagnostic
        {
            Timestamp = DateTimeOffset.UtcNow,
            Severity = severity,
            CollectorId = _collectorId,
            Message = Redaction.Scrub(message),
            Code = code,
            ExceptionType = exception?.GetType().Name,
            Attempt = attempt,
        };

        _diagnostics.Add(diagnostic);
        _context.Log(diagnostic);
    }

    /// <summary>Reports progress to the user interface.</summary>
    public void Progress(string stageName, string activity, int? completed = null, int? total = null) =>
        _context.Report(new CollectionProgress
        {
            CollectorId = _collectorId,
            StageName = stageName,
            Activity = activity,
            Completed = completed,
            Total = total,
        });

    /// <summary>Adds an evidence record for the report's evidence appendix.</summary>
    public void AddRecord(
        string evidenceId,
        EvidenceKind kind,
        string summary,
        Sensitivity sensitivity = Sensitivity.Summary,
        string? payload = null)
    {
        var scrubbed = payload is null ? null : Redaction.Scrub(payload);

        _records.Add(new EvidenceRecord
        {
            EvidenceId = evidenceId,
            Kind = kind,
            Source = _source,
            CollectorId = _collectorId,
            CollectedAt = DateTimeOffset.UtcNow,
            Summary = Redaction.Scrub(summary),
            Sensitivity = sensitivity,
            Payload = scrubbed,
            PayloadSha256 = scrubbed is null
                ? null
                : Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes(scrubbed))).ToLowerInvariant(),
        });
    }

    /// <summary>Builds the final collector result.</summary>
    public CollectionResult Build(CollectionOutcome outcome, EvidenceFragment fragment) => new()
    {
        CollectorId = _collectorId,
        Outcome = outcome,
        StartedAt = _startedAt,
        CompletedAt = DateTimeOffset.UtcNow,
        Availability = _availability,
        Records = _records,
        Diagnostics = _diagnostics,
        Fragment = fragment,
    };

    /// <summary>
    /// Determines the outcome from what was collected: everything available is a success, nothing
    /// available is a failure, and a mixture is a partial success.
    /// </summary>
    public CollectionOutcome DetermineOutcome()
    {
        if (_availability.Count == 0)
        {
            return CollectionOutcome.Failed;
        }

        var collected = _availability.Count(entry => entry.IsAvailable);

        if (collected == _availability.Count)
        {
            return CollectionOutcome.Succeeded;
        }

        return collected == 0 ? CollectionOutcome.Failed : CollectionOutcome.PartiallySucceeded;
    }
}

/// <summary>Runs an operation with bounded retries and exponential backoff.</summary>
public static class RetryPolicy
{
    /// <summary>
    /// Executes an operation, retrying transient failures. The delay doubles on each attempt,
    /// starting at the supplied base delay.
    /// </summary>
    public static async Task<T> ExecuteAsync<T>(
        Func<int, CancellationToken, Task<T>> operation,
        int maxAttempts,
        Func<Exception, bool> isTransient,
        Action<int, Exception>? onRetry,
        CancellationToken cancellationToken,
        TimeSpan? baseDelay = null)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(isTransient);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxAttempts, 1);

        var delay = baseDelay ?? TimeSpan.FromSeconds(1);

        for (var attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return await operation(attempt, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (attempt < maxAttempts && ex is not OperationCanceledException && isTransient(ex))
            {
                onRetry?.Invoke(attempt, ex);
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 30_000));
            }
        }
    }
}
