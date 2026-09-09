using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Contracts;
using Ipa.Desktop.Services;

namespace Ipa.Desktop.ViewModels;

/// <summary>
/// The application shell. It owns the workflow: which step is current, which steps are reachable,
/// and the view model behind each one.
/// </summary>
public sealed partial class MainWindowViewModel : ViewModelBase
{
    private readonly AssessmentWorkspace _workspace;

    public MainWindowViewModel(AssessmentWorkspace workspace)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        _workspace = workspace;

        Welcome = new WelcomeViewModel(workspace, this);
        Details = new AssessmentDetailsViewModel(workspace, this);
        Connections = new ConnectionsViewModel(workspace, this);
        Preflight = new PreflightViewModel(workspace, this);
        Scope = new ScopeViewModel(workspace, this);
        Collection = new CollectionViewModel(workspace, this);
        Findings = new FindingsViewModel(workspace, this);
        Compliance = new ComplianceViewModel(workspace, this);
        Report = new ReportViewModel(workspace, this);

        Steps =
        [
            new WorkflowStepViewModel(WorkflowStep.Welcome, "Start", 1),
            new WorkflowStepViewModel(WorkflowStep.Details, "Details", 2),
            new WorkflowStepViewModel(WorkflowStep.Connections, "Connect", 3),
            new WorkflowStepViewModel(WorkflowStep.Preflight, "Preflight", 4),
            new WorkflowStepViewModel(WorkflowStep.Scope, "Scope", 5),
            new WorkflowStepViewModel(WorkflowStep.Collection, "Collect", 6),
            new WorkflowStepViewModel(WorkflowStep.Findings, "Findings", 7),
            new WorkflowStepViewModel(WorkflowStep.Compliance, "ISO readiness", 8),
            new WorkflowStepViewModel(WorkflowStep.Report, "Report", 9),
        ];

        Current = Welcome;
        UpdateStepAvailability();
    }

    /// <inheritdoc />
    public override string Title => ProductInfo.Name;

    /// <summary>The workflow steps shown in the navigation rail.</summary>
    public ObservableCollection<WorkflowStepViewModel> Steps { get; }

    public WelcomeViewModel Welcome { get; }
    public AssessmentDetailsViewModel Details { get; }
    public ConnectionsViewModel Connections { get; }
    public PreflightViewModel Preflight { get; }
    public ScopeViewModel Scope { get; }
    public CollectionViewModel Collection { get; }
    public FindingsViewModel Findings { get; }
    public ComplianceViewModel Compliance { get; }
    public ReportViewModel Report { get; }

    /// <summary>The view model of the step being shown.</summary>
    [ObservableProperty]
    private ViewModelBase _current;

    /// <summary>The step being shown.</summary>
    [ObservableProperty]
    private WorkflowStep _currentStep = WorkflowStep.Welcome;

    /// <summary>Text shown in the status bar.</summary>
    [ObservableProperty]
    private string _shellStatus = "No assessment is open.";

    /// <summary>Navigates to a step, provided it is reachable.</summary>
    [RelayCommand]
    public void GoTo(WorkflowStep step)
    {
        var target = Steps.FirstOrDefault(candidate => candidate.Step == step);

        if (target is { IsEnabled: false })
        {
            return;
        }

        CurrentStep = step;

        Current = step switch
        {
            WorkflowStep.Welcome => Welcome,
            WorkflowStep.Details => Details,
            WorkflowStep.Connections => Connections,
            WorkflowStep.Preflight => Preflight,
            WorkflowStep.Scope => Scope,
            WorkflowStep.Collection => Collection,
            WorkflowStep.Findings => Findings,
            WorkflowStep.Compliance => Compliance,
            WorkflowStep.Report => Report,
            _ => Welcome,
        };

        foreach (var candidate in Steps)
        {
            candidate.IsCurrent = candidate.Step == step;
        }

        (Current as IWorkflowStepViewModel)?.OnEntered();
    }

    /// <summary>
    /// Recalculates which steps are reachable. A step that depends on collected evidence stays
    /// disabled until there is evidence, so the workflow cannot be entered out of order.
    /// </summary>
    public void UpdateStepAvailability()
    {
        var session = _workspace.Session;
        var hasSession = session is not null;
        var hasEvidence = session?.Evidence is not null;
        var hasResults = session?.RuleResults.Count > 0;

        foreach (var step in Steps)
        {
            step.IsEnabled = step.Step switch
            {
                WorkflowStep.Welcome => true,
                WorkflowStep.Details => hasSession,
                WorkflowStep.Connections => hasSession,
                WorkflowStep.Preflight => hasSession,
                WorkflowStep.Scope => hasSession,
                WorkflowStep.Collection => hasSession,
                WorkflowStep.Findings => hasEvidence,
                WorkflowStep.Compliance => hasResults,
                WorkflowStep.Report => hasResults,
                _ => false,
            };
        }

        ShellStatus = session is null
            ? "No assessment is open."
            : $"{session.Metadata.CustomerName} - {session.State}" +
              (_workspace.ProjectPath is { } path ? $" - saved to {Path.GetFileName(path)}" : " - not saved");
    }
}

/// <summary>A step in the navigation rail.</summary>
public sealed partial class WorkflowStepViewModel : ObservableObject
{
    public WorkflowStepViewModel(WorkflowStep step, string label, int number)
    {
        Step = step;
        Label = label;
        Number = number;
    }

    /// <summary>The step this entry navigates to.</summary>
    public WorkflowStep Step { get; }

    /// <summary>Label shown in the rail.</summary>
    public string Label { get; }

    /// <summary>Position in the workflow.</summary>
    public int Number { get; }

    /// <summary>True when the step can be entered.</summary>
    [ObservableProperty]
    private bool _isEnabled;

    /// <summary>True when the step is the one being shown.</summary>
    [ObservableProperty]
    private bool _isCurrent;
}

/// <summary>Implemented by step view models that need to refresh when they are shown.</summary>
public interface IWorkflowStepViewModel
{
    /// <summary>Called each time the step becomes the current one.</summary>
    void OnEntered();
}
