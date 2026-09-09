using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Collectors.Entra.Preflight;
using Ipa.Desktop.Services;

namespace Ipa.Desktop.ViewModels;

/// <summary>One preflight observation shown to the operator.</summary>
public sealed record PreflightRow(string Severity, string Title, string Detail, string? Remedy, string AffectedGroups);

/// <summary>
/// Shows what consent, directory roles and tenant licensing allow before collection starts, so a
/// missing prerequisite is a decision the operator makes rather than a gap they discover later.
/// </summary>
public sealed partial class PreflightViewModel : ViewModelBase, IWorkflowStepViewModel
{
    private readonly AssessmentWorkspace _workspace;
    private readonly MainWindowViewModel _shell;

    public PreflightViewModel(AssessmentWorkspace workspace, MainWindowViewModel shell)
    {
        _workspace = workspace;
        _shell = shell;
        Findings = [];
    }

    /// <inheritdoc />
    public override string Title => "Preflight";

    /// <inheritdoc />
    public override string Description =>
        "Prerequisites are checked before collection, so that anything missing is reported up front " +
        "rather than appearing as an unexplained gap in the results.";

    /// <summary>The preflight observations.</summary>
    public ObservableCollection<PreflightRow> Findings { get; }

    /// <summary>True when nothing blocks collection.</summary>
    public bool CanProceed => Findings.All(row => row.Severity != nameof(PreflightSeverity.Blocking));

    /// <summary>True when some checks will produce incomplete results.</summary>
    public bool IsDegraded => Findings.Any(row => row.Severity == nameof(PreflightSeverity.Degraded));

    /// <inheritdoc />
    public void OnEntered()
    {
        if (Findings.Count == 0)
        {
            ShowPendingState();
        }
    }

    /// <summary>Records a preflight report produced against a connected tenant.</summary>
    public void Apply(PreflightReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        Findings.Clear();

        foreach (var finding in report.Findings)
        {
            Findings.Add(new PreflightRow(
                finding.Severity.ToString(),
                finding.Title,
                finding.Detail,
                finding.Remedy,
                string.Join(", ", finding.AffectedGroups)));
        }

        OnPropertyChanged(nameof(CanProceed));
        OnPropertyChanged(nameof(IsDegraded));

        StatusMessage = report.CanProceed
            ? $"Preflight complete against permission manifest {report.PermissionManifestVersion}."
            : "Preflight found a blocking problem. Collection cannot start until it is resolved.";
    }

    /// <summary>Moves to the scope step.</summary>
    [RelayCommand]
    private void Continue()
    {
        ClearMessages();
        _shell.GoTo(WorkflowStep.Scope);
    }

    private void ShowPendingState()
    {
        Findings.Clear();

        var session = _workspace.Session;

        if (session?.Scope.IncludeEntra == true)
        {
            Findings.Add(new PreflightRow(
                nameof(PreflightSeverity.Ready),
                "Sign in to run the tenant preflight",
                "Consent, directory roles and tenant licensing are verified once the assessment has " +
                "signed in to the customer's tenant. Until then this list shows what will be checked.",
                "Sign in from the connection step.",
                "Every Entra check group"));
        }

        if (session?.Scope.IncludeActiveDirectory == true)
        {
            Findings.Add(new PreflightRow(
                nameof(PreflightSeverity.Ready),
                "Directory connectivity will be verified at collection",
                "The forest is discovered through the domain controller you named, and the transport " +
                "is validated before any credential is sent.",
                null,
                "Every Active Directory check group"));
        }

        OnPropertyChanged(nameof(CanProceed));
        OnPropertyChanged(nameof(IsDegraded));
    }
}
