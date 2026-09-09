using Ipa.Contracts;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Baselines;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Findings;
using Ipa.Contracts.Reporting;
using Ipa.Contracts.Rules;
using Ipa.Contracts.Scoring;
using Ipa.Reporting.Html;
using Ipa.Reporting.Model;
using Ipa.Reporting.Pdf;
using Xunit;

namespace Ipa.Reporting.Tests;

/// <summary>
/// Tests for report composition: escaping of untrusted values, determinism, section selection and
/// the privacy defaults that keep sensitive material out of an export unless it is asked for.
/// </summary>
public sealed class ReportCompositionTests
{
    private static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>A directory object whose name is markup, which must never become markup.</summary>
    private const string HostileName = "<script>alert('injected')</script>";

    private static ReportProfile Profile(Action<ReportProfile>? _ = null) => new()
    {
        ProfileId = "profile-1",
        Name = "Standard report",
        Branding = new BrandingProfile
        {
            CustomerName = "Contoso",
            AssessorName = "Assessor",
            AssessorCompany = "NoBrain Software",
            ConfidentialityLabel = "Confidential",
        },
        ReportVersion = "1.0",
    };

    private static ReportModel Model(
        ReportProfile? profile = null,
        IReadOnlyList<Finding>? findings = null,
        BaselineComparison? baseline = null)
    {
        var effectiveProfile = profile ?? Profile();

        var overall = new PostureScore
        {
            Scope = "Overall",
            PassedWeight = 40,
            EvaluatedWeight = 60,
            NotCollectedWeight = 3,
            ErrorWeight = 0,
            NotApplicableCount = 2,
            StatusCounts = new Dictionary<RuleStatus, int>
            {
                [RuleStatus.Pass] = 8,
                [RuleStatus.Fail] = 4,
                [RuleStatus.NotCollected] = 1,
            },
        };

        return new ReportModel
        {
            Metadata = new AssessmentMetadata
            {
                CustomerName = "Contoso",
                AssessorName = "Assessor",
                ScopeNotes = "One forest and one tenant.",
            },
            Scope = new AssessmentScope { IncludeActiveDirectory = true, IncludeEntra = true },
            Profile = effectiveProfile,
            Scores = new PostureScoreSet
            {
                Overall = overall,
                ByDomain = new Dictionary<RuleDomain, PostureScore> { [RuleDomain.ActiveDirectory] = overall },
                ByGroup = new Dictionary<CheckGroup, PostureScore> { [CheckGroup.AdPrivilegedAccess] = overall },
                RulePackVersion = "2026.09.1",
                CalculatedAt = Reference,
            },
            Findings = findings ?? [SampleFinding()],
            Results =
            [
                new RuleResult
                {
                    RuleId = new RuleId("AD-PRIV-001"), RuleVersion = 1, Status = RuleStatus.Fail,
                    EvaluatedAt = Reference, Rationale = "Six accounts hold tier-zero privilege.",
                },
            ],
            Exclusions =
            [
                new ReportExclusion
                {
                    RuleId = "EID-SS-001",
                    Title = "Microsoft Secure Score is reported separately",
                    Status = RuleStatus.NotCollected,
                    Availability = EvidenceAvailability.PermissionDenied,
                    Reason = "Secure Score requires a sensitive permission and a reader role.",
                },
            ],
            Roadmap = ReportModelBuilder.BuildRoadmap(findings ?? [SampleFinding()]),
            Readiness = new ReadinessMetrics
            {
                Framework = "ISO/IEC 27001:2022",
                ApplicableControlCount = 90,
                AssessedControlCount = 45,
                ConfirmedSatisfiedCount = 30,
                StatusDistribution = new Dictionary<ControlStatus, int>
                {
                    [ControlStatus.Satisfied] = 30,
                    [ControlStatus.Partial] = 10,
                    [ControlStatus.Unsatisfied] = 5,
                    [ControlStatus.NotAssessed] = 45,
                    [ControlStatus.NotApplicable] = 3,
                },
            },
            Controls =
            [
                new ControlAssessment
                {
                    ControlId = "A.8.2",
                    Status = ControlStatus.Satisfied,
                    OperatorConfirmed = true,
                    Owner = "Identity Team",
                    MappedRuleIds = ["AD-PRIV-001"],
                },
            ],
            ControlDefinitions =
            [
                new ControlDefinition
                {
                    Framework = "ISO/IEC 27001:2022",
                    ControlId = "A.8.2",
                    ToolAuthoredLabel = "Privileged access rights",
                    ToolAuthoredGuidance = "Automated.",
                    Theme = "Technological",
                },
            ],
            Diagnostics =
            [
                new CollectionDiagnostic
                {
                    Timestamp = Reference,
                    Severity = DiagnosticSeverity.Warning,
                    CollectorId = "ad.groupPolicy",
                    Message = "SYSVOL could not be reached.",
                },
            ],
            EvidenceRecords =
            [
                new EvidenceRecord
                {
                    EvidenceId = "ad.users",
                    Kind = EvidenceKind.DirectoryQuery,
                    Source = AssessmentSource.ActiveDirectory,
                    CollectorId = "ad.directory",
                    CollectedAt = Reference,
                    Summary = "1,204 user accounts",
                    Payload = "{\"sample\":\"raw attribute payload\"}",
                },
            ],
            Baseline = baseline,
            RulePackVersion = "2026.09.1",
            GeneratedAt = Reference,
            AcceptedExceptions = ["Pinned certificate accepted for dc01.corp.example"],
        };
    }

    private static Finding SampleFinding(string? title = null) => new()
    {
        FindingId = "AD-PRIV-001",
        RuleId = new RuleId("AD-PRIV-001"),
        RuleVersion = 1,
        Title = title ?? "Tier-zero group membership is limited",
        Severity = RuleSeverity.High,
        Domain = RuleDomain.ActiveDirectory,
        Group = CheckGroup.AdPrivilegedAccess,
        Status = RuleStatus.Fail,
        RiskExplanation = "Large membership widens the blast radius.",
        Remediation = "Reduce standing membership.",
        Rationale = "Six accounts hold tier-zero privilege.",
        AffectedObjects =
        [
            new AffectedObject
            {
                Identifier = "S-1-5-21-1-2-3-1105",
                DisplayName = "adm.alice",
                ObjectType = "user",
                Detail = "Effective tier-zero via CN=Domain Admins",
            },
        ],
        DetectedAt = Reference,
    };

    [Fact]
    public void ReportContainsEverySelectedSection()
    {
        var html = new HtmlReportComposer().Compose(Model());

        Assert.Contains("id=\"scope\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"summary\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"scores\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"findings\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"iso\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"exclusions\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"diagnostics\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"roadmap\"", html, StringComparison.Ordinal);
        Assert.Contains("id=\"evidence\"", html, StringComparison.Ordinal);
        Assert.Contains("Contents", html, StringComparison.Ordinal);
    }

    [Fact]
    public void DeselectedSectionsAreOmitted()
    {
        var profile = Profile() with
        {
            Sections = [ReportSection.Cover, ReportSection.ExecutiveSummary],
        };

        var html = new HtmlReportComposer().Compose(Model(profile));

        Assert.Contains("id=\"summary\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("id=\"diagnostics\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("id=\"evidence\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public void HostileObjectNamesAreEscapedRatherThanRendered()
    {
        var finding = SampleFinding() with
        {
            AffectedObjects =
            [
                new AffectedObject
                {
                    Identifier = "S-1-5-21-1-2-3-9999",
                    DisplayName = HostileName,
                    ObjectType = "user",
                    Detail = "<img src=x onerror=alert(1)>",
                },
            ],
        };

        var html = new HtmlReportComposer().Compose(Model(findings: [finding]));

        Assert.DoesNotContain("<script>alert", html, StringComparison.Ordinal);
        Assert.DoesNotContain("onerror=alert", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    [Fact]
    public void HostileFindingTitlesAreEscaped()
    {
        var finding = SampleFinding("</h3><script>steal()</script>");

        var html = new HtmlReportComposer().Compose(Model(findings: [finding]));

        Assert.DoesNotContain("<script>steal", html, StringComparison.Ordinal);
        Assert.Contains("&lt;/h3&gt;", html, StringComparison.Ordinal);
    }

    [Fact]
    public void HostileCustomerNameIsEscapedOnTheCover()
    {
        var profile = Profile() with
        {
            Branding = new BrandingProfile { CustomerName = HostileName },
        };

        var html = new HtmlReportComposer().Compose(Model(profile));

        Assert.DoesNotContain("<script>alert", html, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInjectedColourCannotEscapeTheStyleDeclaration()
    {
        var profile = Profile() with
        {
            Branding = new BrandingProfile
            {
                PrimaryColor = "red; } body { display:none } .x {",
                SecondaryColor = "#12",
            },
        };

        var html = new HtmlReportComposer().Compose(Model(profile));

        Assert.DoesNotContain("body { display:none }", html, StringComparison.Ordinal);
        Assert.Contains("--primary: #1f3a5f", html, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("#1f3a5f", "#1f3a5f")]
    [InlineData("#abc", "#abc")]
    [InlineData("red", "#000000")]
    [InlineData("javascript:alert(1)", "#000000")]
    [InlineData("#12345", "#000000")]
    [InlineData(null, "#000000")]
    public void OnlyHexadecimalColoursAreAccepted(string? value, string expected) =>
        Assert.Equal(expected, HtmlText.CssColor(value, "#000000"));

    [Theory]
    [InlineData("image/png", true)]
    [InlineData("image/jpeg", true)]
    [InlineData("image/svg+xml", false)]
    [InlineData("text/html", false)]
    public void OnlySafeImageTypesAreEmbedded(string mediaType, bool expected)
    {
        var uri = HtmlText.DataUri([1, 2, 3], mediaType);

        Assert.Equal(expected, uri is not null);
    }

    [Fact]
    public void CompositionIsDeterministic()
    {
        var model = Model();

        var first = new HtmlReportComposer().Compose(model);
        var second = new HtmlReportComposer().Compose(model);

        Assert.Equal(first, second);
    }

    [Fact]
    public void RawAttributesAreExcludedByDefault()
    {
        var html = new HtmlReportComposer().Compose(Model());

        Assert.DoesNotContain("raw attribute payload", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Effective tier-zero via", html, StringComparison.Ordinal);
    }

    [Fact]
    public void RawAttributesAppearOnlyWhenExplicitlyRequested()
    {
        var profile = Profile() with { IncludeRawObjectAttributes = true };

        var html = new HtmlReportComposer().Compose(Model(profile));

        Assert.Contains("raw attribute payload", html, StringComparison.Ordinal);
        Assert.Contains("Effective tier-zero via", html, StringComparison.Ordinal);
    }

    [Fact]
    public void AffectedObjectsAreSampledUnlessFullListsAreRequested()
    {
        var many = Enumerable.Range(1, 40)
            .Select(index => new AffectedObject
            {
                Identifier = $"S-1-5-21-1-2-3-{index}",
                DisplayName = $"account{index:00}",
                ObjectType = "user",
            })
            .ToList();

        var finding = SampleFinding() with { AffectedObjects = many };

        var sampled = new HtmlReportComposer().Compose(Model(findings: [finding]));

        Assert.Contains("account01", sampled, StringComparison.Ordinal);
        Assert.DoesNotContain("account40", sampled, StringComparison.Ordinal);
        Assert.Contains("Showing the first 10 of 40", sampled, StringComparison.Ordinal);

        var full = new HtmlReportComposer().Compose(
            Model(Profile() with { IncludeFullAffectedObjectLists = true }, [finding]));

        Assert.Contains("account40", full, StringComparison.Ordinal);
    }

    [Fact]
    public void ProvisionalScoresAreLabelledAndCompleteOnesAreNot()
    {
        // Sixty of sixty-three weight evaluated is 95% coverage, which is not provisional.
        Assert.DoesNotContain(
            "Provisional score",
            new HtmlReportComposer().Compose(Model()),
            StringComparison.Ordinal);

        var provisional = Model();
        var lowCoverage = provisional.Scores.Overall with { NotCollectedWeight = 40 };

        var html = new HtmlReportComposer().Compose(provisional with
        {
            Scores = provisional.Scores with
            {
                Overall = lowCoverage,
                ByDomain = new Dictionary<RuleDomain, PostureScore> { [RuleDomain.ActiveDirectory] = lowCoverage },
                ByGroup = new Dictionary<CheckGroup, PostureScore> { [CheckGroup.AdPrivilegedAccess] = lowCoverage },
            },
        });

        // Sixty of one hundred weight evaluated is 60% coverage, which is provisional.
        Assert.True(lowCoverage.IsProvisional);
        Assert.Contains("Provisional score", html, StringComparison.Ordinal);
        Assert.Contains("below 90%", html, StringComparison.Ordinal);
    }

    [Fact]
    public void SingleSourceAssessmentStatesTheMissingSource()
    {
        var model = Model() with
        {
            Scope = new AssessmentScope { IncludeActiveDirectory = true, IncludeEntra = false },
        };

        var html = new HtmlReportComposer().Compose(model);

        Assert.Contains("hybrid score is disabled", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not assessed", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IsoSectionCarriesTheReadinessDisclaimer()
    {
        var html = new HtmlReportComposer().Compose(Model());

        Assert.Contains(HtmlText.Escape(ProductInfo.IsoReadinessDisclaimer), html, StringComparison.Ordinal);
        Assert.Contains("copyright protected", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BaselineConformityIsLabelledAsASeparateMetric()
    {
        var comparison = new BaselineComparison
        {
            BaselineId = "b1",
            ProductName = "Windows Server 2022",
            BaselineVersion = "September 2024",
            PackageSha256 = new string('a', 64),
            ComparedAt = Reference,
            Rows =
            [
                new BaselineComparisonRow
                {
                    SettingKey = "k1", DisplayName = "LDAP signing", ExpectedValue = "2",
                    ObservedValue = "1", Outcome = BaselineComparisonOutcome.Different,
                },
            ],
        };

        var html = new HtmlReportComposer().Compose(Model(baseline: comparison));

        Assert.Contains("Separately reported metric", html, StringComparison.Ordinal);
        Assert.Contains("counted twice", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Windows Server 2022", html, StringComparison.Ordinal);
    }

    [Fact]
    public void ChartsCarryATextEquivalent()
    {
        var html = new HtmlReportComposer().Compose(Model());

        Assert.Contains("role=\"img\"", html, StringComparison.Ordinal);
        Assert.Contains("<desc", html, StringComparison.Ordinal);
        Assert.Contains("chart-data", html, StringComparison.Ordinal);
    }

    [Fact]
    public void ExportWarningsAlwaysIncludeTheUnencryptedExportNotice()
    {
        var warnings = ReportGenerator.ExportWarnings(Profile());

        Assert.Contains(warnings, warning => warning.Contains("not encrypted", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ExportWarningsGrowWithThePrivacyOptions()
    {
        var profile = Profile() with
        {
            IncludeRawObjectAttributes = true,
            IncludeFullAffectedObjectLists = true,
            IncludeAttachments = true,
        };

        var warnings = ReportGenerator.ExportWarnings(profile);

        Assert.Equal(4, warnings.Count);
        Assert.True(profile.RequiresPrivacyWarning);
    }

    [Fact]
    public void HeaderAndFooterTemplatesCarryPageNumbersAndTheConfidentialityLabel()
    {
        var options = new PdfRenderOptions { ConfidentialityLabel = "Restricted", CustomerName = "Contoso" };

        var footer = PdfRenderer.BuildFooterTemplate(options);
        var header = PdfRenderer.BuildHeaderTemplate(options);

        Assert.Contains("pageNumber", footer, StringComparison.Ordinal);
        Assert.Contains("totalPages", footer, StringComparison.Ordinal);
        Assert.Contains("Restricted", footer, StringComparison.Ordinal);
        Assert.Contains("Contoso", header, StringComparison.Ordinal);
    }

    [Fact]
    public void HeaderTemplateEscapesAHostileCustomerName()
    {
        var header = PdfRenderer.BuildHeaderTemplate(new PdfRenderOptions { CustomerName = HostileName });

        Assert.DoesNotContain("<script>", header, StringComparison.Ordinal);
    }

    [Fact]
    public void PaginationRulesAreDeclaredInTheStylesheet()
    {
        var html = new HtmlReportComposer().Compose(Model());

        Assert.Contains("page-break-before", html, StringComparison.Ordinal);
        Assert.Contains("page-break-inside: avoid", html, StringComparison.Ordinal);
        Assert.Contains("display: table-header-group", html, StringComparison.Ordinal);
    }

    [Fact]
    public void SuggestedFileNameIsSafeForTheFileSystem()
    {
        var name = ReportGenerator.SuggestFileName("Contoso / Ltd: <test>", Reference);

        Assert.DoesNotContain('/', name);
        Assert.DoesNotContain('<', name);
        Assert.DoesNotContain(':', name);
        Assert.EndsWith("20260301.pdf", name, StringComparison.Ordinal);
    }

    [Fact]
    public void RoadmapIsOrderedBySeverityThenByAffectedObjectCount()
    {
        var findings = new[]
        {
            SampleFinding("Low severity item") with { Severity = RuleSeverity.Low, RuleId = new RuleId("R-LOW") },
            SampleFinding("Critical item") with { Severity = RuleSeverity.Critical, RuleId = new RuleId("R-CRIT") },
            SampleFinding("High severity item") with { Severity = RuleSeverity.High, RuleId = new RuleId("R-HIGH") },
        };

        var roadmap = ReportModelBuilder.BuildRoadmap(findings);

        Assert.Equal(["R-CRIT", "R-HIGH", "R-LOW"], roadmap.Select(step => step.RuleId));
        Assert.Equal("Immediate", roadmap[0].Horizon);
    }

    [Fact]
    public void FalsePositivesAreExcludedFromTheRoadmap()
    {
        var findings = new[]
        {
            SampleFinding() with
            {
                Exception = new FindingException
                {
                    Disposition = FindingDisposition.FalsePositive,
                    Justification = "Not applicable to this environment.",
                    RecordedBy = "Assessor",
                    RecordedAt = Reference,
                },
            },
        };

        Assert.Empty(ReportModelBuilder.BuildRoadmap(findings));
    }

    [Fact]
    public void AnnotatedFindingsAreReportedWithTheirDisposition()
    {
        var finding = SampleFinding() with
        {
            Exception = new FindingException
            {
                Disposition = FindingDisposition.RiskAccepted,
                Justification = "Migration scheduled for the next quarter.",
                RecordedBy = "Assessor",
                RecordedAt = Reference,
            },
        };

        var html = new HtmlReportComposer().Compose(Model(findings: [finding]));

        Assert.Contains("Risk accepted", html, StringComparison.Ordinal);
        Assert.Contains("does not change the score", html, StringComparison.Ordinal);
    }
}
