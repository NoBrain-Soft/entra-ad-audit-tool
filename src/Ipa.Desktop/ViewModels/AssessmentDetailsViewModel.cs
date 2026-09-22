using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Contracts;
using Ipa.Contracts.Assessment;
using Ipa.Desktop.Services;

namespace Ipa.Desktop.ViewModels;

/// <summary>Captures the customer and assessor metadata that appears on the report.</summary>
public sealed partial class AssessmentDetailsViewModel : ViewModelBase, IWorkflowStepViewModel
{
    private readonly AssessmentWorkspace _workspace;
    private readonly MainWindowViewModel _shell;

    public AssessmentDetailsViewModel(AssessmentWorkspace workspace, MainWindowViewModel shell)
    {
        _workspace = workspace;
        _shell = shell;
    }

    /// <inheritdoc />
    public override string Title => "Assessment details";

    /// <inheritdoc />
    public override string Description =>
        "These details identify the engagement and appear on the report cover.";

    [ObservableProperty]
    private string _customerName = string.Empty;

    [ObservableProperty]
    private string? _customerReference;

    [ObservableProperty]
    private string _assessorName = string.Empty;

    [ObservableProperty]
    private string? _assessorCompany = ProductInfo.Vendor;

    [ObservableProperty]
    private string? _engagementReference;

    [ObservableProperty]
    private string? _scopeNotes;

    [ObservableProperty]
    private bool _includeActiveDirectory = true;

    [ObservableProperty]
    private bool _includeEntra = true;

    /// <summary>True when the scope selects no source at all.</summary>
    public bool HasNoSource => !IncludeActiveDirectory && !IncludeEntra;

    /// <summary>
    /// Explains what a single-source assessment means, shown as soon as one source is deselected.
    /// </summary>
    public string SourceNotice => (IncludeActiveDirectory, IncludeEntra) switch
    {
        (true, true) => "Both sources are in scope, so hybrid identity rules will be evaluated.",
        (true, false) => "Only Active Directory is in scope. The hybrid score is disabled and the " +
                         "report states that the Entra tenant was not assessed.",
        (false, true) => "Only Microsoft Entra is in scope. The hybrid score is disabled and the " +
                         "report states that the Active Directory forest was not assessed.",
        _ => "Select at least one source before continuing.",
    };

    /// <inheritdoc />
    public void OnEntered()
    {
        if (_workspace.Session is not { } session)
        {
            return;
        }

        CustomerName = session.Metadata.CustomerName;
        CustomerReference = session.Metadata.CustomerReference;
        AssessorName = session.Metadata.AssessorName;
        AssessorCompany = session.Metadata.AssessorCompany;
        EngagementReference = session.Metadata.EngagementReference;
        ScopeNotes = session.Metadata.ScopeNotes;
        IncludeActiveDirectory = session.Scope.IncludeActiveDirectory;
        IncludeEntra = session.Scope.IncludeEntra;
    }

    partial void OnIncludeActiveDirectoryChanged(bool value)
    {
        OnPropertyChanged(nameof(SourceNotice));
        OnPropertyChanged(nameof(HasNoSource));
    }

    partial void OnIncludeEntraChanged(bool value)
    {
        OnPropertyChanged(nameof(SourceNotice));
        OnPropertyChanged(nameof(HasNoSource));
    }

    /// <summary>Creates the assessment and moves on to the connection step.</summary>
    [RelayCommand]
    private void Continue()
    {
        ClearMessages();

        if (string.IsNullOrWhiteSpace(CustomerName))
        {
            ErrorMessage = "A customer name is required.";
            return;
        }

        if (string.IsNullOrWhiteSpace(AssessorName))
        {
            ErrorMessage = "An assessor name is required.";
            return;
        }

        if (HasNoSource)
        {
            ErrorMessage = "Select at least one identity source.";
            return;
        }

        try
        {
            IsBusy = true;

            var metadata = new AssessmentMetadata
            {
                CustomerName = CustomerName.Trim(),
                CustomerReference = CustomerReference?.Trim(),
                AssessorName = AssessorName.Trim(),
                AssessorCompany = AssessorCompany?.Trim(),
                EngagementReference = EngagementReference?.Trim(),
                ScopeNotes = ScopeNotes?.Trim(),
            };

            var scope = new AssessmentScope
            {
                IncludeActiveDirectory = IncludeActiveDirectory,
                IncludeEntra = IncludeEntra,
                SelectedGroups = Enum.GetValues<CheckGroup>(),
            };

            if (_workspace.HasSession)
            {
                // Returning to this step to correct a detail must not start over: creating a
                // second assessment would throw away the open one and everything collected.
                _workspace.UpdateDetails(metadata, scope);

                StatusMessage = "Details updated.";
            }
            else
            {
                _workspace.CreateAssessment(metadata, scope);

                StatusMessage = "Assessment created. Nothing has been written to disk unencrypted.";
            }

            _shell.UpdateStepAvailability();
            _shell.GoTo(WorkflowStep.Connections);
        }
        catch (Exception ex)
        {
            ReportFailure("The assessment could not be created", ex);
        }
        finally
        {
            IsBusy = false;
        }
    }
}
