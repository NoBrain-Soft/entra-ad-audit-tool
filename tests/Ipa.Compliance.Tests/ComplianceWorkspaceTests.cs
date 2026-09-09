using Ipa.Compliance;
using Ipa.Compliance.Catalogue;
using Ipa.Contracts;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Rules;
using Xunit;

namespace Ipa.Compliance.Tests;

/// <summary>
/// Tests for the ISO/IEC 27001 readiness workspace, including the rule that automated evidence can
/// suggest but never decide a control's status.
/// </summary>
public sealed class ComplianceWorkspaceTests
{
    private static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static RuleDefinition Definition(string id, params string[] controlIds) => new()
    {
        Id = new RuleId(id),
        Version = 1,
        Title = id,
        Domain = RuleDomain.ActiveDirectory,
        Group = CheckGroup.AdPrivilegedAccess,
        Severity = RuleSeverity.High,
        Weight = 6,
        Rationale = "rationale",
        Remediation = "remediation",
        FrameworkMappings = controlIds
            .Select(controlId => new FrameworkMapping
            {
                Framework = IsoControlCatalogue.Framework,
                ControlId = controlId,
                Relevance = "test mapping",
            })
            .ToList(),
    };

    private static RuleResult Result(string id, RuleStatus status) => new()
    {
        RuleId = new RuleId(id),
        RuleVersion = 1,
        Status = status,
        EvaluatedAt = Reference,
        Rationale = status.ToString(),
    };

    [Fact]
    public void CatalogueCoversTheAnnexAControlSet()
    {
        Assert.Equal(93, IsoControlCatalogue.All.Count);
        Assert.Equal(37, IsoControlCatalogue.ByTheme("Organisational").Count);
        Assert.Equal(8, IsoControlCatalogue.ByTheme("People").Count);
        Assert.Equal(14, IsoControlCatalogue.ByTheme("Physical").Count);
        Assert.Equal(34, IsoControlCatalogue.ByTheme("Technological").Count);
    }

    [Fact]
    public void CatalogueShipsIdentifiersAndToolAuthoredGuidanceOnly()
    {
        foreach (var control in IsoControlCatalogue.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(control.ControlId));
            Assert.False(string.IsNullOrWhiteSpace(control.ToolAuthoredLabel));
            Assert.False(string.IsNullOrWhiteSpace(control.ToolAuthoredGuidance));
        }

        Assert.Contains("not the text of ISO/IEC 27001:2022", IsoControlCatalogue.AuthorshipNote, StringComparison.Ordinal);
    }

    [Fact]
    public void ControlIdentifiersAreUnique()
    {
        var duplicates = IsoControlCatalogue.All
            .GroupBy(control => control.ControlId, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .ToList();

        Assert.Empty(duplicates);
    }

    [Fact]
    public void EveryControlStartsUnassessed()
    {
        var workspace = new ComplianceWorkspace();

        Assert.All(workspace.Assessments, assessment =>
        {
            Assert.Equal(ControlStatus.NotAssessed, assessment.Status);
            Assert.False(assessment.OperatorConfirmed);
        });

        var metrics = workspace.ComputeMetrics();
        Assert.Equal(0, metrics.AssessedControlCount);
        Assert.Equal(0, metrics.EvidenceCoveragePercent);
    }

    [Fact]
    public void AutomatedEvidenceSuggestsButNeverSetsAStatus()
    {
        var workspace = new ComplianceWorkspace();

        workspace.ApplyAutomatedEvidence(
            [Definition("AD-PRIV-001", "A.8.2")],
            [Result("AD-PRIV-001", RuleStatus.Pass)],
            Reference);

        var control = workspace.Get("A.8.2");

        Assert.Equal(SuggestedStatus.SuggestSatisfied, control.Suggested);
        Assert.Equal(ControlStatus.NotAssessed, control.Status);
        Assert.False(control.OperatorConfirmed);
        Assert.False(control.IsConfirmedSatisfied);
        Assert.Contains("AD-PRIV-001", control.MappedRuleIds);
    }

    [Fact]
    public void APassingControlCountsOnlyAfterOperatorConfirmation()
    {
        var workspace = new ComplianceWorkspace();

        workspace.ApplyAutomatedEvidence(
            [Definition("AD-PRIV-001", "A.8.2")],
            [Result("AD-PRIV-001", RuleStatus.Pass)],
            Reference);

        Assert.Equal(0, workspace.ComputeMetrics().ConfirmedSatisfiedCount);

        workspace.RecordStatus("A.8.2", ControlStatus.Satisfied, "assessor", Reference);

        var metrics = workspace.ComputeMetrics();
        Assert.Equal(1, metrics.ConfirmedSatisfiedCount);
        Assert.Equal(1, metrics.AssessedControlCount);
    }

    [Theory]
    [InlineData(RuleStatus.Pass, RuleStatus.Pass, SuggestedStatus.SuggestSatisfied)]
    [InlineData(RuleStatus.Fail, RuleStatus.Fail, SuggestedStatus.SuggestUnsatisfied)]
    [InlineData(RuleStatus.Pass, RuleStatus.Fail, SuggestedStatus.SuggestPartial)]
    public void SuggestionReflectsTheMappedResults(RuleStatus first, RuleStatus second, SuggestedStatus expected)
    {
        var suggestion = ComplianceWorkspace.Suggest([Result("A", first), Result("B", second)]);

        Assert.Equal(expected, suggestion);
    }

    [Fact]
    public void UncollectedEvidenceProducesNoSuggestion()
    {
        var suggestion = ComplianceWorkspace.Suggest(
            [Result("A", RuleStatus.NotCollected), Result("B", RuleStatus.NotApplicable)]);

        Assert.Equal(SuggestedStatus.None, suggestion);
    }

    [Fact]
    public void EvidenceCoverageIsAssessedOverApplicable()
    {
        var workspace = new ComplianceWorkspace();

        // Take every control out of scope except four, then assess two of them.
        foreach (var control in IsoControlCatalogue.All.Skip(4))
        {
            workspace.SetApplicability(control.ControlId, isApplicable: false, Reference);
        }

        var applicable = IsoControlCatalogue.All.Take(4).ToList();
        workspace.RecordStatus(applicable[0].ControlId, ControlStatus.Satisfied, "assessor", Reference);
        workspace.RecordStatus(applicable[1].ControlId, ControlStatus.Partial, "assessor", Reference);

        var metrics = workspace.ComputeMetrics();

        Assert.Equal(4, metrics.ApplicableControlCount);
        Assert.Equal(2, metrics.AssessedControlCount);
        Assert.Equal(1, metrics.ConfirmedSatisfiedCount);
        Assert.Equal(50, metrics.EvidenceCoveragePercent); // 2 of 4 applicable assessed
        Assert.Equal(50, metrics.ReadinessPercent);        // 1 of 2 assessed confirmed satisfied
    }

    [Fact]
    public void StatusDistributionCoversEveryControl()
    {
        var workspace = new ComplianceWorkspace();
        workspace.RecordStatus("A.8.2", ControlStatus.Satisfied, "assessor", Reference);
        workspace.SetApplicability("A.7.1", isApplicable: false, Reference);

        var metrics = workspace.ComputeMetrics();

        Assert.Equal(93, metrics.StatusDistribution.Values.Sum());
        Assert.Equal(1, metrics.StatusDistribution[ControlStatus.Satisfied]);
        Assert.Equal(1, metrics.StatusDistribution[ControlStatus.NotApplicable]);
    }

    [Fact]
    public void NotApplicableControlsAreExcludedFromBothMetrics()
    {
        var workspace = new ComplianceWorkspace();

        foreach (var control in IsoControlCatalogue.ByTheme("Physical"))
        {
            workspace.SetApplicability(control.ControlId, isApplicable: false, Reference);
        }

        var metrics = workspace.ComputeMetrics();

        Assert.Equal(93 - 14, metrics.ApplicableControlCount);
    }

    [Fact]
    public void AttestationsAndAttachmentsAreRecorded()
    {
        var workspace = new ComplianceWorkspace();

        workspace.AddAttestation(new Attestation
        {
            AttestationId = "att-1",
            ControlId = "A.6.3",
            Statement = "Annual awareness training completed by all staff.",
            AttestedBy = "Security Manager",
            AttestedAt = Reference,
            AttachmentIds = ["attachment-1"],
            ReviewDate = Reference.AddYears(1),
        });

        var control = workspace.Get("A.6.3");

        Assert.Single(control.Attestations);
        Assert.Equal("attachment-1", Assert.Single(control.AttachmentIds));
    }

    [Fact]
    public void OperatorSuppliedLicensedTextIsHeldAgainstTheControl()
    {
        var workspace = new ComplianceWorkspace();

        workspace.SetLicensedText("A.5.15", "Operator's licensed copy of the control text.", Reference);

        Assert.Equal("Operator's licensed copy of the control text.", workspace.Get("A.5.15").LicensedText);

        // Nothing in the shipped catalogue carries licensed text.
        Assert.All(new ComplianceWorkspace().Assessments, assessment => Assert.Null(assessment.LicensedText));
    }

    [Fact]
    public void PendingConfirmationListsSuggestedButUnconfirmedControls()
    {
        var workspace = new ComplianceWorkspace();

        workspace.ApplyAutomatedEvidence(
            [Definition("AD-PRIV-001", "A.8.2"), Definition("AD-POL-001", "A.5.17")],
            [Result("AD-PRIV-001", RuleStatus.Pass), Result("AD-POL-001", RuleStatus.Fail)],
            Reference);

        Assert.Equal(2, workspace.PendingConfirmation().Count);

        workspace.RecordStatus("A.8.2", ControlStatus.Satisfied, "assessor", Reference);

        Assert.Equal("A.5.17", Assert.Single(workspace.PendingConfirmation()).ControlId);
    }

    [Fact]
    public void MetricsCarryTheReadinessDisclaimer()
    {
        var metrics = new ComplianceWorkspace().ComputeMetrics();

        Assert.Equal(ProductInfo.IsoReadinessDisclaimer, metrics.Disclaimer);
        Assert.Contains("not a certification", metrics.Disclaimer, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExistingAssessmentsAreRestoredWhenAProjectIsReopened()
    {
        var saved = new ControlAssessment
        {
            ControlId = "A.8.2",
            Status = ControlStatus.Satisfied,
            OperatorConfirmed = true,
            Owner = "Identity Team",
            Notes = "Reviewed in the previous engagement.",
        };

        var workspace = new ComplianceWorkspace([saved]);
        var restored = workspace.Get("A.8.2");

        Assert.Equal(ControlStatus.Satisfied, restored.Status);
        Assert.Equal("Identity Team", restored.Owner);
        Assert.Equal(93, workspace.Assessments.Count);
    }
}
