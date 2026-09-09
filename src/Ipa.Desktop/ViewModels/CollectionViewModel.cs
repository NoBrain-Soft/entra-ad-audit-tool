using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Collectors.ActiveDirectory.Collectors;
using Ipa.Collectors.Entra.Graph;
using Ipa.Contracts.Collection;
using Ipa.Core.Collection;
using Ipa.Desktop.Services;

namespace Ipa.Desktop.ViewModels;

/// <summary>One collector's progress and outcome.</summary>
public sealed partial class CollectorProgressViewModel : ObservableObject
{
    public CollectorProgressViewModel(string collectorId, string displayName)
    {
        CollectorId = collectorId;
        DisplayName = displayName;
    }

    /// <summary>Identifier of the collector.</summary>
    public string CollectorId { get; }

    /// <summary>Operator-facing name.</summary>
    public string DisplayName { get; }

    [ObservableProperty]
    private string _activity = "Waiting";

    [ObservableProperty]
    private double _fraction;

    [ObservableProperty]
    private string _outcome = "Pending";

    [ObservableProperty]
    private bool _canRerun;
}

/// <summary>
/// Runs collection with progress, cancellation and per-collector retry. A failed collector can be
/// rerun on its own; results that already succeeded are never discarded.
/// </summary>
public sealed partial class CollectionViewModel : ViewModelBase, IWorkflowStepViewModel
{
    private readonly AssessmentWorkspace _workspace;
    private readonly MainWindowViewModel _shell;
    private CancellationTokenSource? _cancellation;
    private DirectorySession? _directorySession;
    private GraphReadClient? _graph;

    public CollectionViewModel(AssessmentWorkspace workspace, MainWindowViewModel shell)
    {
        _workspace = workspace;
        _shell = shell;
        Collectors = [];
        Diagnostics = [];
    }

    /// <inheritdoc />
    public override string Title => "Collection";

    /// <inheritdoc />
    public override string Description =>
        "Collection is read-only and cancellable. A collector that fails does not stop the run: its " +
        "evidence is marked unavailable and it can be rerun on its own.";

    /// <summary>Per-collector progress.</summary>
    public ObservableCollection<CollectorProgressViewModel> Collectors { get; }

    /// <summary>The diagnostic log produced during collection.</summary>
    public ObservableCollection<CollectionDiagnostic> Diagnostics { get; }

    [ObservableProperty]
    private bool _isCollecting;

    [ObservableProperty]
    private string _currentActivity = "Ready to collect.";

    [ObservableProperty]
    private double _overallProgress;

    /// <summary>True when at least one collector failed and can be rerun.</summary>
    public bool HasFailures => Collectors.Any(collector => collector.CanRerun);

    /// <inheritdoc />
    public void OnEntered()
    {
        if (_workspace.Session?.CollectionResults.Count > 0)
        {
            ApplyResults(_workspace.Session.CollectionResults);
            return;
        }

        ShowPlan();
    }

    /// <summary>
    /// Runs collection against the connected sources. A source that is in scope but not connected
    /// is reported as such rather than silently skipped, so the coverage figure stays honest.
    /// </summary>
    [RelayCommand]
    private async Task CollectAsync()
    {
        ClearMessages();

        if (_workspace.Session is not { } session)
        {
            ErrorMessage = "Create an assessment first.";
            return;
        }

        var stages = CollectionPlanner.Build(session.Scope, _directorySession, _graph);

        if (stages.Count == 0)
        {
            ErrorMessage =
                "No source is connected. Connect the Active Directory forest or the Entra tenant on " +
                "the connection step before collecting.";

            return;
        }

        var token = BeginRun();

        try
        {
            var progress = new Progress<CollectionProgress>(ApplyProgress);

            await _workspace.CollectAsync(stages, progress, token).ConfigureAwait(true);

            ApplyResults(_workspace.Session?.CollectionResults ?? []);

            StatusMessage = token.IsCancellationRequested
                ? "Collection was cancelled. The evidence collected so far is kept and can be evaluated."
                : "Collection complete. Evaluate the evidence to produce findings and scores.";

            _shell.UpdateStepAvailability();
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Collection was cancelled. The evidence collected so far is kept.";
        }
        catch (Exception ex)
        {
            ReportFailure("Collection failed", ex);
        }
        finally
        {
            EndRun();
        }
    }

    /// <summary>Reruns the collectors that failed, keeping the results that succeeded.</summary>
    [RelayCommand]
    private async Task RerunFailedAsync()
    {
        ClearMessages();

        if (_workspace.Session is not { } session)
        {
            return;
        }

        var failed = Collectors
            .Where(collector => collector.CanRerun)
            .Select(collector => collector.CollectorId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (failed.Count == 0)
        {
            StatusMessage = "No collector needs to be rerun.";
            return;
        }

        var collectors = CollectionPlanner
            .Build(session.Scope, _directorySession, _graph)
            .SelectMany(stage => stage.Collectors)
            .Where(collector => failed.Contains(collector.CollectorId))
            .ToList();

        if (collectors.Count == 0)
        {
            ErrorMessage = "The failed collectors need their source to be reconnected first.";
            return;
        }

        var token = BeginRun();

        try
        {
            var progress = new Progress<CollectionProgress>(ApplyProgress);

            await _workspace.RerunAsync(collectors, progress, token).ConfigureAwait(true);

            ApplyResults(_workspace.Session?.CollectionResults ?? []);
            StatusMessage = $"Reran {collectors.Count} collector(s). Results that already succeeded were kept.";
        }
        catch (Exception ex)
        {
            ReportFailure("The rerun failed", ex);
        }
        finally
        {
            EndRun();
        }
    }

    /// <summary>Attaches the connected sources so collection can run against them.</summary>
    public void AttachSources(DirectorySession? directorySession, GraphReadClient? graph)
    {
        _directorySession = directorySession;
        _graph = graph;
        OnPropertyChanged(nameof(CanCollect));
    }

    /// <summary>True when at least one source is connected.</summary>
    public bool CanCollect => _directorySession is not null || _graph is not null;

    private void ShowPlan()
    {
        if (_workspace.Session is not { } session || Collectors.Count > 0)
        {
            return;
        }

        foreach (var (stage, collectorId, displayName) in CollectionPlanner.Describe(session.Scope))
        {
            Collectors.Add(new CollectorProgressViewModel(collectorId, displayName)
            {
                Activity = $"{stage}: waiting for a connected source",
            });
        }
    }

    /// <summary>Cancels a run in progress. The partial evidence collected so far is kept.</summary>
    [RelayCommand]
    private void Cancel()
    {
        _cancellation?.Cancel();
        CurrentActivity = "Cancelling. Evidence collected so far is kept.";
    }

    /// <summary>Records the outcome of a completed run.</summary>
    public void ApplyResults(IReadOnlyCollection<CollectionResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        foreach (var result in results)
        {
            var entry = Collectors.FirstOrDefault(collector =>
                string.Equals(collector.CollectorId, result.CollectorId, StringComparison.OrdinalIgnoreCase));

            if (entry is null)
            {
                entry = new CollectorProgressViewModel(result.CollectorId, result.CollectorId);
                Collectors.Add(entry);
            }

            entry.Outcome = result.Outcome.ToString();
            entry.Fraction = result.Outcome == CollectionOutcome.Succeeded ? 1 : entry.Fraction;
            entry.CanRerun = result.Outcome == CollectionOutcome.Failed;

            entry.Activity = result.Outcome switch
            {
                CollectionOutcome.Succeeded => "Complete",
                CollectionOutcome.PartiallySucceeded => "Complete with gaps",
                CollectionOutcome.Failed => "Failed - can be rerun",
                CollectionOutcome.Cancelled => "Cancelled",
                CollectionOutcome.Skipped => "Not applicable to this scope",
                _ => entry.Activity,
            };
        }

        Diagnostics.Clear();

        foreach (var diagnostic in _workspace.Session?.Diagnostics ?? [])
        {
            Diagnostics.Add(diagnostic);
        }

        OnPropertyChanged(nameof(HasFailures));

        OverallProgress = Collectors.Count == 0
            ? 0
            : Collectors.Count(collector => collector.Outcome is "Succeeded" or "Skipped") / (double)Collectors.Count;
    }

    /// <summary>Records progress reported by a collector.</summary>
    public void ApplyProgress(CollectionProgress progress)
    {
        ArgumentNullException.ThrowIfNull(progress);

        var entry = Collectors.FirstOrDefault(collector =>
            string.Equals(collector.CollectorId, progress.CollectorId, StringComparison.OrdinalIgnoreCase));

        if (entry is null)
        {
            entry = new CollectorProgressViewModel(progress.CollectorId, progress.CollectorId);
            Collectors.Add(entry);
        }

        entry.Activity = progress.Total is > 0
            ? $"{progress.StageName}: {progress.Activity} ({progress.Completed}/{progress.Total})"
            : $"{progress.StageName}: {progress.Activity}";

        entry.Fraction = progress.Fraction ?? entry.Fraction;
        CurrentActivity = entry.Activity;
    }

    /// <summary>Evaluates the collected evidence and moves to the findings dashboard.</summary>
    [RelayCommand]
    private void Evaluate()
    {
        ClearMessages();

        if (_workspace.Session?.Evidence is null)
        {
            ErrorMessage = "There is no collected evidence to evaluate.";
            return;
        }

        try
        {
            IsBusy = true;

            var outcome = _workspace.Evaluate();

            StatusMessage =
                $"Evaluated {outcome.Results.Count} rule(s) against rule pack {_workspace.RulePackVersion}. " +
                $"{outcome.Findings.Count} finding(s) produced.";

            _shell.UpdateStepAvailability();
            _shell.GoTo(WorkflowStep.Findings);
        }
        catch (Exception ex)
        {
            ReportFailure("Evaluation failed", ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Creates the cancellation source for a run.</summary>
    public CancellationToken BeginRun()
    {
        _cancellation?.Dispose();
        _cancellation = new CancellationTokenSource();

        IsCollecting = true;
        CurrentActivity = "Collecting.";

        return _cancellation.Token;
    }

    /// <summary>Marks a run as finished.</summary>
    public void EndRun()
    {
        IsCollecting = false;
        _cancellation?.Dispose();
        _cancellation = null;
    }
}
