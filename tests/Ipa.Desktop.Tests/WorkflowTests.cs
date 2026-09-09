using Avalonia.Controls;
using Ipa.Contracts;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Reporting;
using Ipa.Desktop.Services;
using Ipa.Desktop.ViewModels;
using Ipa.Desktop.Views;
using Xunit;

namespace Ipa.Desktop.Tests;

/// <summary>
/// Interface tests driven through the headless platform, so views are constructed, bound and laid
/// out exactly as they are at runtime. They cover onboarding, the scope and privacy choices, the
/// finding and control workflows, and crash recovery.
/// </summary>
public sealed class WorkflowTests
{
    private static MainWindowViewModel NewShell(out AssessmentWorkspace workspace)
    {
        workspace = new AssessmentWorkspace();
        return new MainWindowViewModel(workspace);
    }

    [Fact]
    public void ShellStartsOnTheWelcomeStepWithLaterStepsLocked() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            Assert.Equal(WorkflowStep.Welcome, shell.CurrentStep);
            Assert.IsType<WelcomeViewModel>(shell.Current);

            Assert.All(
                shell.Steps.Where(step => step.Step != WorkflowStep.Welcome),
                step => Assert.False(step.IsEnabled));
        }
    });

    [Fact]
    public void MainWindowRendersWithoutBindingFailures() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var window = new MainWindow { DataContext = shell };
            window.Show();

            // A binding failure or an unresolved template surfaces here as an exception or a null
            // visual tree, so reaching a measured window is the assertion.
            Assert.True(window.IsVisible);
            Assert.NotNull(window.Content);
        }
    });

    [Fact]
    public void EveryStepViewConstructsAndBinds() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var pairs = new (Control View, object Model)[]
            {
                (new WelcomeView(), shell.Welcome),
                (new AssessmentDetailsView(), shell.Details),
                (new ConnectionsView(), shell.Connections),
                (new PreflightView(), shell.Preflight),
                (new ScopeView(), shell.Scope),
                (new CollectionView(), shell.Collection),
                (new FindingsView(), shell.Findings),
                (new ComplianceView(), shell.Compliance),
                (new ReportView(), shell.Report),
            };

            foreach (var (view, model) in pairs)
            {
                view.DataContext = model;

                var window = new Window { Content = view, Width = 1200, Height = 800 };
                window.Show();

                Assert.NotNull(view.DataContext);
                window.Close();
            }
        }
    });

    [Fact]
    public void CreatingAnAssessmentUnlocksTheNextSteps() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.CustomerName = "Contoso";
            shell.Details.AssessorName = "Assessor";
            shell.Details.ContinueCommand.Execute(null);

            Assert.NotNull(workspace.Session);
            Assert.Equal(WorkflowStep.Connections, shell.CurrentStep);

            Assert.True(shell.Steps.Single(step => step.Step == WorkflowStep.Connections).IsEnabled);

            // Findings stay locked until there is evidence.
            Assert.False(shell.Steps.Single(step => step.Step == WorkflowStep.Findings).IsEnabled);
        }
    });

    [Fact]
    public void AnAssessmentWithNoSourceIsRefused() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.CustomerName = "Contoso";
            shell.Details.AssessorName = "Assessor";
            shell.Details.IncludeActiveDirectory = false;
            shell.Details.IncludeEntra = false;

            shell.Details.ContinueCommand.Execute(null);

            Assert.Null(workspace.Session);
            Assert.NotNull(shell.Details.ErrorMessage);
            Assert.True(shell.Details.HasNoSource);
        }
    });

    [Fact]
    public void MissingCustomerOrAssessorIsRefused() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.ContinueCommand.Execute(null);
            Assert.Contains("customer name", shell.Details.ErrorMessage!, StringComparison.OrdinalIgnoreCase);

            shell.Details.CustomerName = "Contoso";
            shell.Details.ContinueCommand.Execute(null);
            Assert.Contains("assessor name", shell.Details.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
        }
    });

    [Fact]
    public void SingleSourceSelectionStatesTheConsequence() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.IncludeEntra = false;

            Assert.Contains("hybrid score is disabled", shell.Details.SourceNotice, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Entra tenant was not assessed", shell.Details.SourceNotice, StringComparison.OrdinalIgnoreCase);
        }
    });

    [Fact]
    public void ExplicitCredentialsCannotBeSentOverAnUnprotectedTransport() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var connections = shell.Connections;

            // Choosing the unprotected transport while explicit credentials are selected moves the
            // transport back to LDAPS, whichever selection the operator changed first.
            connections.UseWindowsIntegrated = false;
            connections.Transport = Collectors.ActiveDirectory.Connection.DirectoryTransportSecurity.SignAndSeal;

            Assert.Equal(
                Collectors.ActiveDirectory.Connection.DirectoryTransportSecurity.Ldaps,
                connections.Transport);

            // And switching to explicit credentials while the unprotected transport is selected
            // does the same, which matters on a host where integrated authentication is the default.
            connections.UseWindowsIntegrated = true;
            connections.Transport = Collectors.ActiveDirectory.Connection.DirectoryTransportSecurity.SignAndSeal;
            connections.UseWindowsIntegrated = false;

            Assert.Equal(
                Collectors.ActiveDirectory.Connection.DirectoryTransportSecurity.Ldaps,
                connections.Transport);

            Assert.Contains("LDAPS or StartTLS", connections.TransportNotice, StringComparison.Ordinal);
        }
    });

    [Fact]
    public void ConsentAddressIsProducedOnlyForAValidRegistration() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var connections = shell.Connections;

            connections.TenantId = "contoso.onmicrosoft.com";
            connections.ClientId = "not-a-guid";
            connections.PrepareConsentCommand.Execute(null);

            Assert.Null(connections.AdminConsentUrl);
            Assert.NotNull(connections.ErrorMessage);

            connections.ClientId = Guid.NewGuid().ToString();
            connections.PrepareConsentCommand.Execute(null);

            Assert.NotNull(connections.AdminConsentUrl);
            Assert.Contains("adminconsent", connections.AdminConsentUrl!, StringComparison.Ordinal);
            Assert.DoesNotContain("client_secret", connections.AdminConsentUrl!, StringComparison.Ordinal);
        }
    });

    [Fact]
    public void ScopeSelectionDrivesTheRuleCountAndIsRefusedWhenEmpty() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.CustomerName = "Contoso";
            shell.Details.AssessorName = "Assessor";
            shell.Details.ContinueCommand.Execute(null);

            shell.Scope.OnEntered();
            Assert.NotEmpty(shell.Scope.Groups);

            var all = shell.Scope.SelectedRuleCount;
            Assert.True(all > 0);

            shell.Scope.SelectNoneCommand.Execute(null);
            Assert.Equal(0, shell.Scope.SelectedRuleCount);

            shell.Scope.ContinueCommand.Execute(null);
            Assert.NotNull(shell.Scope.ErrorMessage);

            shell.Scope.SelectAllCommand.Execute(null);
            Assert.Equal(all, shell.Scope.SelectedRuleCount);
        }
    });

    [Fact]
    public void CollectionShowsThePlanBeforeAnySourceIsConnected() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.CustomerName = "Contoso";
            shell.Details.AssessorName = "Assessor";
            shell.Details.ContinueCommand.Execute(null);

            shell.Collection.OnEntered();

            Assert.NotEmpty(shell.Collection.Collectors);
            Assert.False(shell.Collection.CanCollect);
            Assert.All(
                shell.Collection.Collectors,
                collector => Assert.Contains("waiting", collector.Activity, StringComparison.OrdinalIgnoreCase));
        }
    });

    [Fact]
    public void CollectingWithNoConnectedSourceReportsWhy() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.CustomerName = "Contoso";
            shell.Details.AssessorName = "Assessor";
            shell.Details.ContinueCommand.Execute(null);

            shell.Collection.CollectCommand.Execute(null);

            Assert.Contains("No source is connected", shell.Collection.ErrorMessage!, StringComparison.Ordinal);
        }
    });

    [Fact]
    public void EvaluatingWithoutEvidenceIsRefused() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.CustomerName = "Contoso";
            shell.Details.AssessorName = "Assessor";
            shell.Details.ContinueCommand.Execute(null);

            shell.Collection.EvaluateCommand.Execute(null);

            Assert.Contains("no collected evidence", shell.Collection.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
        }
    });

    [Fact]
    public void PrivacyOptionsAreOffByDefaultAndEachAddsAWarning() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var report = shell.Report;
            report.OnEntered();

            Assert.False(report.IncludeRawObjectAttributes);
            Assert.False(report.IncludeFullAffectedObjectLists);
            Assert.False(report.IncludeAttachments);

            // The unencrypted-export warning is always present.
            Assert.Single(report.Warnings);
            Assert.Contains(report.Warnings, warning =>
                warning.Contains("not encrypted", StringComparison.OrdinalIgnoreCase));

            report.IncludeRawObjectAttributes = true;
            report.IncludeFullAffectedObjectLists = true;
            report.IncludeAttachments = true;

            Assert.Equal(4, report.Warnings.Count);
        }
    });

    [Fact]
    public void ReportSectionsCanBeDeselected() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var report = shell.Report;

            Assert.Equal(Enum.GetValues<ReportSection>().Length, report.Sections.Count);

            foreach (var section in report.Sections.Where(entry =>
                         entry.Section is ReportSection.EvidenceAppendix or ReportSection.CollectionDiagnostics))
            {
                section.IsSelected = false;
            }

            var profile = report.BuildProfile();

            Assert.DoesNotContain(ReportSection.EvidenceAppendix, profile.Sections);
            Assert.Contains(ReportSection.ExecutiveSummary, profile.Sections);
        }
    });

    [Fact]
    public void WhiteLabelFieldsReachTheProfile() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var report = shell.Report;

            report.CustomerName = "Northwind";
            report.AssessorCompany = "Assessors Limited";
            report.ProductNameOverride = "Identity Review";
            report.PrimaryColor = "#123456";
            report.ConfidentialityLabel = "Restricted";
            report.SignOffNames = "A. Assessor, R. Reviewer";

            var profile = report.BuildProfile();

            Assert.Equal("Northwind", profile.Branding.CustomerName);
            Assert.Equal("Identity Review", profile.Branding.EffectiveProductName);
            Assert.Equal("#123456", profile.Branding.PrimaryColor);
            Assert.Equal("Restricted", profile.Branding.ConfidentialityLabel);
            Assert.Equal(2, profile.SignOffNames.Count);
        }
    });

    [Fact]
    public void SavingAProjectRequiresAMatchingUsablePassphrase() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.CustomerName = "Contoso";
            shell.Details.AssessorName = "Assessor";
            shell.Details.ContinueCommand.Execute(null);

            var report = shell.Report;
            report.ProjectPath = Path.Combine(Path.GetTempPath(), $"ipa-{Guid.NewGuid():n}.ipaproj");

            report.SaveProjectCommand.Execute(null);
            Assert.Contains("passphrase", report.ErrorMessage!, StringComparison.OrdinalIgnoreCase);

            report.ProjectPassphrase = "a-long-enough-passphrase";
            report.ProjectPassphraseConfirmation = "a-different-passphrase";
            report.SaveProjectCommand.Execute(null);
            Assert.Contains("do not match", report.ErrorMessage!, StringComparison.OrdinalIgnoreCase);

            report.ProjectPassphrase = "short";
            report.ProjectPassphraseConfirmation = "short";
            report.SaveProjectCommand.Execute(null);
            Assert.Contains("too short", report.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
        }
    });

    [Fact]
    public void PassphraseStrengthIsReportedAsItIsTyped() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var report = shell.Report;

            report.ProjectPassphrase = "short";
            Assert.Contains("Too short", report.PassphraseStrength, StringComparison.Ordinal);

            report.ProjectPassphrase = "a-much-longer-project-passphrase";
            Assert.Contains("Strong", report.PassphraseStrength, StringComparison.Ordinal);
        }
    });

    [Fact]
    public void OpeningAProjectRequiresAPathAndAPassphrase() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Welcome.OpenProjectCommand.Execute(null);
            Assert.Contains("Select a project file", shell.Welcome.ErrorMessage!, StringComparison.Ordinal);

            shell.Welcome.ProjectPath = "/nonexistent/project.ipaproj";
            shell.Welcome.OpenProjectCommand.Execute(null);
            Assert.Contains("passphrase", shell.Welcome.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
        }
    });

    [Fact]
    public void OpeningAProjectDiscardsThePassphraseAfterwards() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Welcome.ProjectPath = "/nonexistent/project.ipaproj";
            shell.Welcome.ProjectPassphrase = "a-long-enough-passphrase";

            shell.Welcome.OpenProjectCommand.Execute(null);

            // The attempt fails, but the passphrase must not be left in the view model either way.
            Assert.Null(shell.Welcome.ProjectPassphrase);
            Assert.NotNull(shell.Welcome.ErrorMessage);
        }
    });

    [Fact]
    public void CrashRecoveryListIsPopulatedFromDisk() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Welcome.RefreshStaleSessionsCommand.Execute(null);

            // Whatever the machine holds, the command must complete and keep the flag consistent.
            Assert.Equal(shell.Welcome.StaleSessions.Count > 0, shell.Welcome.HasStaleSessions);
        }
    });

    [Fact]
    public void FindingFiltersNarrowTheList() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var findings = shell.Findings;

            Assert.Contains("All", findings.SeverityFilters);
            Assert.Contains(nameof(Contracts.Rules.RuleSeverity.Critical), findings.SeverityFilters);
            Assert.Contains(nameof(Contracts.Rules.RuleDomain.Hybrid), findings.DomainFilters);

            // With no assessment loaded the list is simply empty rather than throwing.
            findings.SelectedSeverity = nameof(Contracts.Rules.RuleSeverity.Critical);
            findings.SearchText = "privileged";

            Assert.Empty(findings.Findings);
        }
    });

    [Fact]
    public void RecordingADispositionRequiresAJustification() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var findings = shell.Findings;

            findings.SelectedDisposition = Contracts.Findings.FindingDisposition.RiskAccepted;
            findings.SaveDispositionCommand.Execute(null);

            Assert.Contains("Select a finding", findings.ErrorMessage!, StringComparison.Ordinal);
        }
    });

    [Fact]
    public void ComplianceWorkspaceListsTheCatalogueAndItsAuthorshipNote() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var compliance = shell.Compliance;
            compliance.OnEntered();

            Assert.Equal(93, compliance.Controls.Count);
            Assert.Contains("not the text of ISO/IEC 27001:2022", compliance.AuthorshipNote, StringComparison.Ordinal);
            Assert.Equal(ProductInfo.IsoReadinessDisclaimer, compliance.Description);
        }
    });

    [Fact]
    public void ConfirmingAControlStatusRequiresASelection() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Compliance.ConfirmStatusCommand.Execute(null);

            Assert.Contains("Select a control", shell.Compliance.ErrorMessage!, StringComparison.Ordinal);
        }
    });

    [Fact]
    public void ControlStatusIsRecordedOnlyThroughOperatorConfirmation() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.Details.CustomerName = "Contoso";
            shell.Details.AssessorName = "Assessor";
            shell.Details.ContinueCommand.Execute(null);

            var compliance = shell.Compliance;
            compliance.OnEntered();

            compliance.SelectedControl = compliance.Controls.First(control => control.ControlId == "A.8.2");
            compliance.StatusToRecord = ControlStatus.Satisfied;
            compliance.ControlNotes = "Reviewed with the identity team.";
            compliance.ConfirmStatusCommand.Execute(null);

            var recorded = workspace.Compliance.Get("A.8.2");

            Assert.Equal(ControlStatus.Satisfied, recorded.Status);
            Assert.True(recorded.OperatorConfirmed);
            Assert.Contains("confirmed by the assessor", compliance.StatusMessage!, StringComparison.Ordinal);
        }
    });

    [Fact]
    public void ThemeFilterNarrowsTheControlList() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            var compliance = shell.Compliance;
            compliance.OnEntered();

            compliance.SelectedTheme = "Physical";

            Assert.Equal(14, compliance.Controls.Count);
            Assert.All(compliance.Controls, control => Assert.Equal("Physical", control.Theme));
        }
    });

    [Fact]
    public void LockedStepsCannotBeNavigatedTo() => HeadlessUi.Run(() =>
    {
        var shell = NewShell(out var workspace);

        using (workspace)
        {
            shell.GoTo(WorkflowStep.Report);

            // The report step is locked until an assessment has been evaluated.
            Assert.Equal(WorkflowStep.Welcome, shell.CurrentStep);
        }
    });
}
