using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Contracts;
using Ipa.Desktop.Services;
using Ipa.Persistence.Session;

namespace Ipa.Desktop.ViewModels;

/// <summary>A session left behind by a previous run, offered for cleanup.</summary>
public sealed record StaleSessionViewModel(string Directory, string Description);

/// <summary>
/// The starting screen: begin an assessment, open a saved project, or clean up a session left
/// behind by a crash.
/// </summary>
public sealed partial class WelcomeViewModel : ViewModelBase, IWorkflowStepViewModel
{
    private readonly AssessmentWorkspace _workspace;
    private readonly MainWindowViewModel _shell;

    public WelcomeViewModel(AssessmentWorkspace workspace, MainWindowViewModel shell)
    {
        _workspace = workspace;
        _shell = shell;
        StaleSessions = [];
    }

    /// <inheritdoc />
    public override string Title => $"Welcome to {ProductInfo.Name}";

    /// <inheritdoc />
    public override string Description =>
        "Assess one Active Directory forest and one Microsoft Entra tenant. " +
        "Assessments are read-only, and nothing is written to disk unencrypted.";

    /// <summary>Sessions detected from a previous run.</summary>
    public ObservableCollection<StaleSessionViewModel> StaleSessions { get; }

    /// <summary>Path of a project the operator selected to open.</summary>
    [ObservableProperty]
    private string? _projectPath;

    /// <summary>Passphrase for the selected project. Held only while the project is opened.</summary>
    [ObservableProperty]
    private string? _projectPassphrase;

    /// <summary>True when a crash left a session behind.</summary>
    public bool HasStaleSessions => StaleSessions.Count > 0;

    /// <inheritdoc />
    public void OnEntered() => RefreshStaleSessions();

    /// <summary>Starts a new assessment and moves to the details step.</summary>
    [RelayCommand]
    private void StartNewAssessment()
    {
        ClearMessages();
        _shell.GoTo(WorkflowStep.Details);
    }

    /// <summary>Opens the selected project.</summary>
    [RelayCommand]
    private void OpenProject()
    {
        ClearMessages();

        if (string.IsNullOrWhiteSpace(ProjectPath))
        {
            ErrorMessage = "Select a project file first.";
            return;
        }

        if (string.IsNullOrEmpty(ProjectPassphrase))
        {
            ErrorMessage = "Enter the project passphrase.";
            return;
        }

        try
        {
            IsBusy = true;
            _workspace.OpenProject(ProjectPath, ProjectPassphrase);

            StatusMessage = $"Opened {Path.GetFileName(ProjectPath)}.";
            _shell.UpdateStepAvailability();
            _shell.GoTo(WorkflowStep.Findings);
        }
        catch (Exception ex)
        {
            ReportFailure("The project could not be opened", ex);
        }
        finally
        {
            // The passphrase is discarded as soon as the container has been opened.
            ProjectPassphrase = null;
            IsBusy = false;
        }
    }

    /// <summary>Deletes a session directory left behind by a crash.</summary>
    [RelayCommand]
    private void CleanupStaleSession(StaleSessionViewModel? session)
    {
        if (session is null)
        {
            return;
        }

        ClearMessages();

        if (AssessmentWorkspace.CleanupStaleSession(session.Directory))
        {
            StaleSessions.Remove(session);
            OnPropertyChanged(nameof(HasStaleSessions));
            StatusMessage = "The leftover session was deleted.";
        }
        else
        {
            ErrorMessage =
                "The leftover session could not be deleted. It may still be held open by another " +
                "instance of the application.";
        }
    }

    /// <summary>Rescans for sessions left behind by a previous run.</summary>
    [RelayCommand]
    private void RefreshStaleSessions()
    {
        StaleSessions.Clear();

        foreach (var session in AssessmentWorkspace.FindStaleSessions())
        {
            StaleSessions.Add(new StaleSessionViewModel(
                session.Directory,
                Describe(session)));
        }

        OnPropertyChanged(nameof(HasStaleSessions));
    }

    private static string Describe(CrashRecovery.StaleSession session)
    {
        var created = session.CreatedAt is { } timestamp
            ? timestamp.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture)
            : "an unknown time";

        var size = session.SizeBytes / 1024d / 1024d;

        return $"Session from {created}, {size:F1} MB. " +
               "This is working data from a run that did not close normally. " +
               "It is encrypted with a key that no longer exists, so it cannot be recovered.";
    }
}
