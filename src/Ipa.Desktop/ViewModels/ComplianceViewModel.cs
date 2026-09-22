using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Compliance.Catalogue;
using Ipa.Contracts;
using Ipa.Contracts.Compliance;
using Ipa.Desktop.Services;

namespace Ipa.Desktop.ViewModels;

/// <summary>One control row in the readiness workspace.</summary>
public sealed partial class ControlRowViewModel : ObservableObject
{
    public ControlRowViewModel(ControlDefinition definition, ControlAssessment assessment)
    {
        Definition = definition;
        Assessment = assessment;
    }

    /// <summary>The catalogue definition.</summary>
    public ControlDefinition Definition { get; }

    /// <summary>The operator's working state.</summary>
    public ControlAssessment Assessment { get; }

    /// <summary>Control identifier.</summary>
    public string ControlId => Definition.ControlId;

    /// <summary>Tool-authored label.</summary>
    public string Label => Definition.ToolAuthoredLabel;

    /// <summary>Theme the control belongs to.</summary>
    public string Theme => Definition.Theme;

    /// <summary>Current status.</summary>
    public string Status => Contracts.Text.DisplayText.Humanise(Assessment.Status.ToString());

    /// <summary>The status the automated evidence suggests. Advisory only.</summary>
    public string Suggested => Assessment.Suggested switch
    {
        SuggestedStatus.SuggestSatisfied => "Evidence suggests satisfied",
        SuggestedStatus.SuggestPartial => "Evidence suggests partial",
        SuggestedStatus.SuggestUnsatisfied => "Evidence suggests unsatisfied",
        _ => "No automated evidence",
    };

    /// <summary>True once the operator has confirmed the status.</summary>
    public bool IsConfirmed => Assessment.OperatorConfirmed;

    /// <summary>Rules whose results were mapped to this control.</summary>
    public string MappedRules => string.Join(", ", Assessment.MappedRuleIds);
}

/// <summary>
/// The ISO/IEC 27001 readiness workspace. Automated evidence can suggest a status, but only an
/// operator confirmation records one, and every metric is labelled as readiness.
/// </summary>
public sealed partial class ComplianceViewModel : ViewModelBase, IWorkflowStepViewModel
{
    private readonly AssessmentWorkspace _workspace;
    private readonly MainWindowViewModel _shell;

    public ComplianceViewModel(AssessmentWorkspace workspace, MainWindowViewModel shell)
    {
        _workspace = workspace;
        _shell = shell;

        Controls = [];
        Themes = new ObservableCollection<string>(["All", .. IsoControlCatalogue.Themes]);
    }

    /// <inheritdoc />
    public override string Title => "ISO/IEC 27001 readiness";

    /// <inheritdoc />
    public override string Description => ProductInfo.IsoReadinessDisclaimer;

    /// <summary>The catalogue note about authorship, shown above the list.</summary>
    public string AuthorshipNote => IsoControlCatalogue.AuthorshipNote;

    /// <summary>The controls matching the current filter.</summary>
    public ObservableCollection<ControlRowViewModel> Controls { get; }

    /// <summary>Theme filter options.</summary>
    public ObservableCollection<string> Themes { get; }

    /// <summary>Status options the operator can record.</summary>
    public IReadOnlyList<ControlStatus> Statuses { get; } = Enum.GetValues<ControlStatus>();

    [ObservableProperty]
    private string _selectedTheme = "All";

    [ObservableProperty]
    private bool _showOnlyPending;

    [ObservableProperty]
    private ControlRowViewModel? _selectedControl;

    [ObservableProperty]
    private ControlStatus _statusToRecord = ControlStatus.NotAssessed;

    [ObservableProperty]
    private string? _controlNotes;

    [ObservableProperty]
    private string? _licensedText;

    [ObservableProperty]
    private string _evidenceCoverage = "0%";

    [ObservableProperty]
    private string _readiness = "0%";

    [ObservableProperty]
    private string _statusDistribution = string.Empty;

    /// <inheritdoc />
    public void OnEntered() => Refresh();

    partial void OnSelectedThemeChanged(string value) => Refresh();

    partial void OnShowOnlyPendingChanged(bool value) => Refresh();

    partial void OnSelectedControlChanged(ControlRowViewModel? value)
    {
        StatusToRecord = value?.Assessment.Status ?? ControlStatus.NotAssessed;
        ControlNotes = value?.Assessment.Notes;
        LicensedText = value?.Assessment.LicensedText;
    }

    /// <summary>Reloads controls and metrics.</summary>
    [RelayCommand]
    private void Refresh()
    {
        Controls.Clear();

        var assessments = _workspace.Compliance.Assessments.ToDictionary(
            assessment => assessment.ControlId,
            assessment => assessment,
            StringComparer.OrdinalIgnoreCase);

        foreach (var definition in IsoControlCatalogue.All)
        {
            if (!string.Equals(SelectedTheme, "All", StringComparison.Ordinal)
                && !string.Equals(definition.Theme, SelectedTheme, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var assessment = assessments.GetValueOrDefault(
                definition.ControlId,
                new ControlAssessment { ControlId = definition.ControlId });

            if (ShowOnlyPending
                && (assessment.Suggested == SuggestedStatus.None || assessment.OperatorConfirmed))
            {
                continue;
            }

            Controls.Add(new ControlRowViewModel(definition, assessment));
        }

        var metrics = _workspace.Compliance.ComputeMetrics();

        EvidenceCoverage = $"{metrics.EvidenceCoveragePercent}%";
        Readiness = $"{metrics.ReadinessPercent}%";

        StatusDistribution = string.Join(
            "  ",
            metrics.StatusDistribution
                .Where(entry => entry.Value > 0)
                .Select(entry => $"{Reporting.Html.HtmlReportComposer.SplitCamelCase(entry.Key.ToString())}: {entry.Value}"));
    }

    /// <summary>Records the operator's judgement for the selected control.</summary>
    [RelayCommand]
    private void ConfirmStatus()
    {
        ClearMessages();

        if (SelectedControl is not { } control)
        {
            ErrorMessage = "Select a control first.";
            return;
        }

        try
        {
            _workspace.RecordControlStatus(
                control.ControlId,
                StatusToRecord,
                _workspace.Session?.Metadata.AssessorName ?? "Assessor",
                ControlNotes);

            StatusMessage =
                $"{control.ControlId} recorded as {StatusToRecord} and confirmed by the assessor. " +
                "Automated evidence alone never sets a control's status.";

            Refresh();
        }
        catch (Exception ex)
        {
            ReportFailure("The control status could not be recorded", ex);
        }
    }

    /// <summary>Stores licensed control text the operator pasted from their own copy.</summary>
    [RelayCommand]
    private void SaveLicensedText()
    {
        ClearMessages();

        if (SelectedControl is not { } control)
        {
            ErrorMessage = "Select a control first.";
            return;
        }

        _workspace.Compliance.SetLicensedText(control.ControlId, LicensedText, DateTimeOffset.UtcNow);

        StatusMessage =
            "The text was stored inside this project only. It is never included in a release of " +
            "this product.";

        Refresh();
    }

    /// <summary>Moves to the report builder.</summary>
    [RelayCommand]
    private void GoToReport() => _shell.GoTo(WorkflowStep.Report);
}
