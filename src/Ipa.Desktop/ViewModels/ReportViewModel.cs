using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Contracts;
using Ipa.Contracts.Reporting;
using Ipa.Desktop.Services;
using Ipa.Persistence.Security;
using Ipa.Reporting.Pdf;

namespace Ipa.Desktop.ViewModels;

/// <summary>A selectable report section.</summary>
public sealed partial class ReportSectionViewModel : ObservableObject
{
    public ReportSectionViewModel(ReportSection section, string label)
    {
        Section = section;
        Label = label;
    }

    /// <summary>The section this entry selects.</summary>
    public ReportSection Section { get; }

    /// <summary>Label shown in the list.</summary>
    public string Label { get; }

    /// <summary>True when the section is included.</summary>
    [ObservableProperty]
    private bool _isSelected = true;
}

/// <summary>
/// Configures the white-label report, states the privacy consequences of each option, and generates
/// the document. It also saves the assessment as an encrypted project.
/// </summary>
public sealed partial class ReportViewModel : ViewModelBase, IWorkflowStepViewModel
{
    private readonly AssessmentWorkspace _workspace;
    private readonly MainWindowViewModel _shell;

    public ReportViewModel(AssessmentWorkspace workspace, MainWindowViewModel shell)
    {
        _workspace = workspace;
        _shell = shell;

        Sections = [];
        Warnings = [];

        foreach (var section in Enum.GetValues<ReportSection>())
        {
            Sections.Add(new ReportSectionViewModel(
                section,
                Reporting.Html.HtmlReportComposer.SplitCamelCase(section.ToString())));
        }

        foreach (var entry in Sections)
        {
            entry.PropertyChanged += (_, _) => RefreshWarnings();
        }
    }

    /// <inheritdoc />
    public override string Title => "Report";

    /// <inheritdoc />
    public override string Description =>
        "The report is generated locally and never leaves this machine on its own.";

    /// <summary>The selectable sections.</summary>
    public ObservableCollection<ReportSectionViewModel> Sections { get; }

    /// <summary>Warnings the operator must see before exporting.</summary>
    public ObservableCollection<string> Warnings { get; }

    // White-label fields.

    [ObservableProperty]
    private string? _customerName;

    [ObservableProperty]
    private string? _assessorName;

    [ObservableProperty]
    private string? _assessorCompany;

    [ObservableProperty]
    private string _primaryColor = "#1f3a5f";

    [ObservableProperty]
    private string _secondaryColor = "#4b7bb5";

    [ObservableProperty]
    private string _confidentialityLabel = "Confidential";

    [ObservableProperty]
    private string? _productNameOverride;

    [ObservableProperty]
    private string _reportVersion = "1.0";

    [ObservableProperty]
    private string? _executiveNarrative;

    [ObservableProperty]
    private string? _signOffNames;

    [ObservableProperty]
    private string? _logoPath;

    // Privacy options, all off by default.

    [ObservableProperty]
    private bool _includeRawObjectAttributes;

    [ObservableProperty]
    private bool _includeFullAffectedObjectLists;

    [ObservableProperty]
    private bool _includeAttachments;

    [ObservableProperty]
    private int _affectedObjectSampleSize = 10;

    // Output.

    [ObservableProperty]
    private string? _outputPath;

    // Project saving.

    [ObservableProperty]
    private string? _projectPath;

    [ObservableProperty]
    private string? _projectPassphrase;

    [ObservableProperty]
    private string? _projectPassphraseConfirmation;

    [ObservableProperty]
    private string _passphraseStrength = "Enter a passphrase of at least twelve characters.";

    /// <inheritdoc />
    public void OnEntered()
    {
        if (_workspace.Session is { } session)
        {
            CustomerName ??= session.Metadata.CustomerName;
            AssessorName ??= session.Metadata.AssessorName;
            AssessorCompany ??= session.Metadata.AssessorCompany;

            OutputPath ??= Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                ReportGenerator.SuggestFileName(session.Metadata.CustomerName, DateTimeOffset.UtcNow));

            ProjectPath ??= Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                $"{session.Metadata.CustomerName}{ProductInfo.ProjectFileExtension}");
        }

        RefreshWarnings();
    }

    partial void OnIncludeRawObjectAttributesChanged(bool value) => RefreshWarnings();

    partial void OnIncludeFullAffectedObjectListsChanged(bool value) => RefreshWarnings();

    partial void OnIncludeAttachmentsChanged(bool value) => RefreshWarnings();

    partial void OnProjectPassphraseChanged(string? value) =>
        PassphraseStrength = value is null
            ? "Enter a passphrase of at least twelve characters."
            : PassphraseKeyDerivation.EvaluateStrength(value) switch
            {
                Ipa.Persistence.Security.PassphraseStrength.Unusable =>
                    "Too short. A project passphrase must be at least twelve characters.",
                Ipa.Persistence.Security.PassphraseStrength.Weak =>
                    "Weak. Add length or a wider mix of characters.",
                Ipa.Persistence.Security.PassphraseStrength.Acceptable =>
                    "Acceptable.",
                _ => "Strong.",
            };

    /// <summary>Builds the report profile from the current selection.</summary>
    public ReportProfile BuildProfile()
    {
        byte[]? logo = null;
        string? logoType = null;

        if (!string.IsNullOrWhiteSpace(LogoPath) && File.Exists(LogoPath))
        {
            logo = File.ReadAllBytes(LogoPath);

            logoType = Path.GetExtension(LogoPath).ToLowerInvariant() switch
            {
                ".png" => "image/png",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".gif" => "image/gif",
                ".webp" => "image/webp",
                _ => null,
            };

            if (logoType is null)
            {
                logo = null;
            }
        }

        return new ReportProfile
        {
            ProfileId = _workspace.ReportProfile.ProfileId,
            Name = "Configured report",
            Branding = new BrandingProfile
            {
                CustomerName = CustomerName,
                AssessorName = AssessorName,
                AssessorCompany = AssessorCompany,
                LogoBytes = logo,
                LogoMediaType = logoType,
                PrimaryColor = PrimaryColor,
                SecondaryColor = SecondaryColor,
                ConfidentialityLabel = ConfidentialityLabel,
                ProductNameOverride = ProductNameOverride,
            },
            Sections = Sections.Where(section => section.IsSelected).Select(section => section.Section).ToList(),
            AssessmentStartDate = _workspace.Session?.Metadata.PlannedStartDate,
            AssessmentEndDate = _workspace.Session?.Metadata.PlannedEndDate,
            ReportVersion = ReportVersion,
            ExecutiveNarrative = ExecutiveNarrative,
            SignOffNames = string.IsNullOrWhiteSpace(SignOffNames)
                ? []
                : SignOffNames.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            IncludeRawObjectAttributes = IncludeRawObjectAttributes,
            IncludeFullAffectedObjectLists = IncludeFullAffectedObjectLists,
            IncludeAttachments = IncludeAttachments,
            AffectedObjectSampleSize = Math.Clamp(AffectedObjectSampleSize, 1, 1000),
        };
    }

    /// <summary>Generates the report to the configured path.</summary>
    [RelayCommand]
    private async Task GenerateAsync()
    {
        ClearMessages();

        if (string.IsNullOrWhiteSpace(OutputPath))
        {
            ErrorMessage = "Choose where to write the report.";
            return;
        }

        if (_workspace.Session?.Scores is null)
        {
            ErrorMessage = "Evaluate the assessment before generating a report.";
            return;
        }

        try
        {
            IsBusy = true;
            _workspace.ReportProfile = BuildProfile();

            await _workspace.GenerateReportAsync(OutputPath, CancellationToken.None).ConfigureAwait(true);

            StatusMessage =
                $"The report was written to {OutputPath}. " + PdfRenderer.ExportWarning;
        }
        catch (Exception ex)
        {
            ReportFailure("The report could not be generated", ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Saves the assessment as an encrypted project.</summary>
    [RelayCommand]
    private void SaveProject()
    {
        ClearMessages();

        if (string.IsNullOrWhiteSpace(ProjectPath))
        {
            ErrorMessage = "Choose where to save the project.";
            return;
        }

        if (string.IsNullOrEmpty(ProjectPassphrase))
        {
            ErrorMessage = "Enter a passphrase for the project.";
            return;
        }

        if (!string.Equals(ProjectPassphrase, ProjectPassphraseConfirmation, StringComparison.Ordinal))
        {
            ErrorMessage = "The passphrases do not match.";
            return;
        }

        if (PassphraseKeyDerivation.EvaluateStrength(ProjectPassphrase)
            == Ipa.Persistence.Security.PassphraseStrength.Unusable)
        {
            ErrorMessage = "The passphrase is too short. Use at least twelve characters.";
            return;
        }

        try
        {
            IsBusy = true;
            _workspace.ReportProfile = BuildProfile();
            _workspace.SaveProject(ProjectPath, ProjectPassphrase, CustomerName);

            StatusMessage =
                $"The project was saved to {ProjectPath}. The passphrase is not stored anywhere: " +
                "without it the project cannot be opened.";

            _shell.UpdateStepAvailability();
        }
        catch (Exception ex)
        {
            ReportFailure("The project could not be saved", ex);
        }
        finally
        {
            // The passphrase is discarded as soon as the container has been written.
            ProjectPassphrase = null;
            ProjectPassphraseConfirmation = null;
            IsBusy = false;
        }
    }

    private void RefreshWarnings()
    {
        Warnings.Clear();

        foreach (var warning in ReportGenerator.ExportWarnings(BuildProfileForWarnings()))
        {
            Warnings.Add(warning);
        }
    }

    private ReportProfile BuildProfileForWarnings() => new()
    {
        ProfileId = "preview",
        Name = "preview",
        IncludeRawObjectAttributes = IncludeRawObjectAttributes,
        IncludeFullAffectedObjectLists = IncludeFullAffectedObjectLists,
        IncludeAttachments = IncludeAttachments,
    };
}
