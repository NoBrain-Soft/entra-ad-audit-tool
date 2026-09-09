using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Contracts;
using Ipa.Contracts.Findings;
using Ipa.Contracts.Rules;
using Ipa.Contracts.Scoring;
using Ipa.Desktop.Services;

namespace Ipa.Desktop.ViewModels;

/// <summary>A score card shown on the dashboard.</summary>
public sealed record ScoreCardViewModel(string Label, string Value, string Coverage, bool IsProvisional);

/// <summary>An affected object shown in the drill-down.</summary>
public sealed record AffectedObjectViewModel(string DisplayName, string ObjectType, string? Detail);

/// <summary>
/// The findings dashboard: scores, coverage, a searchable and filterable finding list, per-finding
/// drill-down, and the operator's disposition workflow.
/// </summary>
public sealed partial class FindingsViewModel : ViewModelBase, IWorkflowStepViewModel
{
    private readonly AssessmentWorkspace _workspace;
    private readonly MainWindowViewModel _shell;
    private List<Finding> _allFindings = [];

    public FindingsViewModel(AssessmentWorkspace workspace, MainWindowViewModel shell)
    {
        _workspace = workspace;
        _shell = shell;

        ScoreCards = [];
        Findings = [];
        AffectedObjects = [];
        SeverityFilters = new ObservableCollection<string>(
            ["All", .. Enum.GetNames<RuleSeverity>()]);
        DomainFilters = new ObservableCollection<string>(
            ["All", .. Enum.GetNames<RuleDomain>()]);
    }

    /// <inheritdoc />
    public override string Title => "Findings";

    /// <inheritdoc />
    public override string Description =>
        "Scores reflect only what was evaluated. Annotating a finding records your judgement in the " +
        "report but never changes the score.";

    /// <summary>The score cards shown at the top of the dashboard.</summary>
    public ObservableCollection<ScoreCardViewModel> ScoreCards { get; }

    /// <summary>The findings matching the current filters.</summary>
    public ObservableCollection<Finding> Findings { get; }

    /// <summary>Objects affected by the selected finding.</summary>
    public ObservableCollection<AffectedObjectViewModel> AffectedObjects { get; }

    /// <summary>Severity filter options.</summary>
    public ObservableCollection<string> SeverityFilters { get; }

    /// <summary>Domain filter options.</summary>
    public ObservableCollection<string> DomainFilters { get; }

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private string _selectedSeverity = "All";

    [ObservableProperty]
    private string _selectedDomain = "All";

    [ObservableProperty]
    private bool _hideAnnotated;

    [ObservableProperty]
    private Finding? _selectedFinding;

    [ObservableProperty]
    private string? _operatorNotes;

    [ObservableProperty]
    private string? _justification;

    [ObservableProperty]
    private FindingDisposition _selectedDisposition = FindingDisposition.Open;

    /// <summary>Disposition options offered for the selected finding.</summary>
    public IReadOnlyList<FindingDisposition> Dispositions { get; } = Enum.GetValues<FindingDisposition>();

    /// <summary>Provider metric shown alongside, never blended into the posture score.</summary>
    [ObservableProperty]
    private string? _providerMetric;

    /// <summary>Baseline conformity, reported separately from the posture score.</summary>
    [ObservableProperty]
    private string? _baselineMetric;

    /// <inheritdoc />
    public void OnEntered() => Refresh();

    partial void OnSearchTextChanged(string value) => ApplyFilters();

    partial void OnSelectedSeverityChanged(string value) => ApplyFilters();

    partial void OnSelectedDomainChanged(string value) => ApplyFilters();

    partial void OnHideAnnotatedChanged(bool value) => ApplyFilters();

    partial void OnSelectedFindingChanged(Finding? value)
    {
        AffectedObjects.Clear();

        if (value is null)
        {
            OperatorNotes = null;
            Justification = null;
            SelectedDisposition = FindingDisposition.Open;
            return;
        }

        foreach (var affected in value.AffectedObjects)
        {
            AffectedObjects.Add(new AffectedObjectViewModel(
                affected.DisplayName,
                affected.ObjectType,
                affected.Detail));
        }

        OperatorNotes = value.OperatorNotes;
        Justification = value.Exception?.Justification;
        SelectedDisposition = value.Disposition;
    }

    /// <summary>Reloads scores and findings from the workspace.</summary>
    [RelayCommand]
    private void Refresh()
    {
        ScoreCards.Clear();

        if (_workspace.Session?.Scores is not { } scores)
        {
            return;
        }

        ScoreCards.Add(BuildCard("Overall", scores.Overall));

        foreach (var (domain, score) in scores.ByDomain.OrderBy(entry => entry.Key.ToString(), StringComparer.Ordinal))
        {
            ScoreCards.Add(BuildCard(Label(domain), score));
        }

        ProviderMetric = scores.MicrosoftSecureScore is { } provider
            ? $"{provider.Provider} {provider.MetricName}: {provider.Current:F0} of {provider.Maximum:F0} " +
              $"({provider.Percent}%). Shown separately; not blended into the posture score."
            : null;

        BaselineMetric = scores.BaselineConformity is { } baseline
            ? $"{baseline.ProductName} {baseline.BaselineVersion}: {baseline.ConformityPercent}% conformity. " +
              "Reported separately from the posture score."
            : null;

        _allFindings = [.. _workspace.Session.Findings];
        ApplyFilters();
    }

    /// <summary>Records the operator's disposition for the selected finding.</summary>
    [RelayCommand]
    private void SaveDisposition()
    {
        ClearMessages();

        if (SelectedFinding is not { } finding)
        {
            ErrorMessage = "Select a finding first.";
            return;
        }

        if (SelectedDisposition != FindingDisposition.Open && string.IsNullOrWhiteSpace(Justification))
        {
            ErrorMessage = "A justification is required when a disposition is recorded.";
            return;
        }

        try
        {
            var exception = SelectedDisposition == FindingDisposition.Open
                ? null
                : new FindingException
                {
                    Disposition = SelectedDisposition,
                    Justification = Justification!.Trim(),
                    RecordedBy = _workspace.Session?.Metadata.AssessorName ?? "Assessor",
                    RecordedAt = DateTimeOffset.UtcNow,
                };

            _workspace.RecordFindingDisposition(finding.FindingId, OperatorNotes, exception);
            _workspace.Evaluate();

            StatusMessage =
                "The disposition was recorded. It appears in the report as an annotation and the " +
                "raw score is unchanged.";

            Refresh();
        }
        catch (Exception ex)
        {
            ReportFailure("The disposition could not be recorded", ex);
        }
    }

    /// <summary>Moves to the compliance workspace.</summary>
    [RelayCommand]
    private void GoToCompliance() => _shell.GoTo(WorkflowStep.Compliance);

    /// <summary>Moves to the report builder.</summary>
    [RelayCommand]
    private void GoToReport() => _shell.GoTo(WorkflowStep.Report);

    private void ApplyFilters()
    {
        Findings.Clear();

        var query = _allFindings.AsEnumerable();

        if (!string.Equals(SelectedSeverity, "All", StringComparison.Ordinal)
            && Enum.TryParse<RuleSeverity>(SelectedSeverity, out var severity))
        {
            query = query.Where(finding => finding.Severity == severity);
        }

        if (!string.Equals(SelectedDomain, "All", StringComparison.Ordinal)
            && Enum.TryParse<RuleDomain>(SelectedDomain, out var domain))
        {
            query = query.Where(finding => finding.Domain == domain);
        }

        if (HideAnnotated)
        {
            query = query.Where(finding => !finding.IsAnnotated);
        }

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var term = SearchText.Trim();

            query = query.Where(finding =>
                finding.Title.Contains(term, StringComparison.OrdinalIgnoreCase)
                || finding.RuleId.Value.Contains(term, StringComparison.OrdinalIgnoreCase)
                || finding.Rationale.Contains(term, StringComparison.OrdinalIgnoreCase)
                || finding.AffectedObjects.Any(affected =>
                    affected.DisplayName.Contains(term, StringComparison.OrdinalIgnoreCase)));
        }

        foreach (var finding in query)
        {
            Findings.Add(finding);
        }
    }

    private static ScoreCardViewModel BuildCard(string label, PostureScore score) => new(
        label,
        score.Value?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "n/a",
        $"Coverage {score.CoveragePercent}%",
        score.IsProvisional);

    private static string Label(RuleDomain domain) => domain switch
    {
        RuleDomain.ActiveDirectory => "Active Directory",
        RuleDomain.Entra => "Microsoft Entra",
        RuleDomain.Hybrid => "Hybrid identity",
        _ => domain.ToString(),
    };
}
