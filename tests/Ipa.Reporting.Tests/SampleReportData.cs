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
using Ipa.Reporting.Model;

namespace Ipa.Reporting.Tests;

/// <summary>
/// Builds a full, sanitised sample report model. Every value is fabricated. The sample exercises a
/// large data set deliberately, so pagination, table headers and chart layout can be checked
/// visually before a release.
/// </summary>
public static class SampleReportData
{
    private static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Builds the sample model.</summary>
    public static ReportModel Build(int findingCount = 24, int affectedObjectsPerFinding = 60)
    {
        var findings = Enumerable.Range(1, findingCount)
            .Select(index => BuildFinding(index, affectedObjectsPerFinding))
            .ToList();

        var overall = BuildScore("Overall", 168, 240, 12, 0);

        return new ReportModel
        {
            Metadata = new AssessmentMetadata
            {
                CustomerName = "Northwind Traders",
                CustomerReference = "NWT-2026-01",
                AssessorName = "A. Assessor",
                AssessorCompany = "NoBrain Software",
                EngagementReference = "ENG-4417",
                ScopeNotes = "One production forest (northwind.example) and one Entra tenant.",
                PlannedStartDate = Reference.AddDays(-7),
                PlannedEndDate = Reference,
            },
            Scope = new AssessmentScope
            {
                IncludeActiveDirectory = true,
                IncludeEntra = true,
                SelectedGroups = Enum.GetValues<CheckGroup>(),
            },
            Profile = new ReportProfile
            {
                ProfileId = "sample",
                Name = "Full report",
                Branding = new BrandingProfile
                {
                    CustomerName = "Northwind Traders",
                    AssessorName = "A. Assessor",
                    AssessorCompany = "NoBrain Software",
                    ConfidentialityLabel = "Confidential - client copy",
                    PrimaryColor = "#1f3a5f",
                    SecondaryColor = "#4b7bb5",
                },
                ReportVersion = "1.0",
                AssessmentStartDate = Reference.AddDays(-7),
                AssessmentEndDate = Reference,
                ExecutiveNarrative =
                    "The assessment covered one Active Directory forest and one Microsoft Entra tenant. " +
                    "Privileged access and authentication carry the highest residual risk, and the " +
                    "remediation roadmap orders the work accordingly.",
                SignOffNames = ["A. Assessor", "R. Reviewer"],
            },
            Scores = new PostureScoreSet
            {
                Overall = overall,
                ByDomain = new Dictionary<RuleDomain, PostureScore>
                {
                    [RuleDomain.ActiveDirectory] = BuildScore("ActiveDirectory", 96, 140, 6, 0),
                    [RuleDomain.Entra] = BuildScore("Entra", 54, 78, 6, 0),
                    [RuleDomain.Hybrid] = BuildScore("Hybrid", 18, 22, 0, 0),
                },
                ByGroup = Enum.GetValues<CheckGroup>()
                    .Where(group => group is not (CheckGroup.BaselineConformity or CheckGroup.EntraSecureScore))
                    .ToDictionary(
                        group => group,
                        group => BuildScore(group.ToString(), 12 + (group.GetHashCode() % 5), 20, 2, 0)),
                RulePackVersion = "2026.09.1",
                CalculatedAt = Reference,
                MicrosoftSecureScore = new ProviderScore
                {
                    Provider = "Microsoft",
                    MetricName = "Microsoft Secure Score",
                    Current = 218,
                    Maximum = 462,
                    AsOf = Reference.AddDays(-1),
                },
            },
            Findings = findings,
            Results = findings
                .Select(finding => new RuleResult
                {
                    RuleId = finding.RuleId,
                    RuleVersion = 1,
                    Status = RuleStatus.Fail,
                    EvaluatedAt = Reference,
                    Rationale = finding.Rationale,
                })
                .ToList(),
            Exclusions =
            [
                new ReportExclusion
                {
                    RuleId = "EID-SS-001",
                    Title = "Microsoft Secure Score is reported separately",
                    Status = RuleStatus.NotCollected,
                    Availability = EvidenceAvailability.PermissionDenied,
                    Reason = "Secure Score requires a sensitive permission and an appropriate directory role.",
                },
                new ReportExclusion
                {
                    RuleId = "AD-CS-900",
                    Title = "Certificate authority host checks are outside the read-only scope",
                    Status = RuleStatus.NotCollected,
                    Availability = EvidenceAvailability.Unsupported,
                    Reason = "These checks require probing the certification authority host, which is out of scope.",
                },
            ],
            Roadmap = ReportModelBuilder.BuildRoadmap(findings),
            Readiness = new ReadinessMetrics
            {
                Framework = "ISO/IEC 27001:2022",
                ApplicableControlCount = 79,
                AssessedControlCount = 52,
                ConfirmedSatisfiedCount = 34,
                StatusDistribution = new Dictionary<ControlStatus, int>
                {
                    [ControlStatus.Satisfied] = 34,
                    [ControlStatus.Partial] = 12,
                    [ControlStatus.Unsatisfied] = 6,
                    [ControlStatus.NotAssessed] = 27,
                    [ControlStatus.NotApplicable] = 14,
                },
            },
            Controls = Enumerable.Range(1, 34)
                .Select(index => new ControlAssessment
                {
                    ControlId = $"A.8.{index}",
                    Status = index % 3 == 0 ? ControlStatus.Partial : ControlStatus.Satisfied,
                    OperatorConfirmed = index % 4 != 0,
                    Owner = "Identity Team",
                    MappedRuleIds = [$"AD-PRIV-{index:000}"],
                })
                .ToList(),
            ControlDefinitions = Enumerable.Range(1, 34)
                .Select(index => new ControlDefinition
                {
                    Framework = "ISO/IEC 27001:2022",
                    ControlId = $"A.8.{index}",
                    ToolAuthoredLabel = $"Technological control {index}",
                    ToolAuthoredGuidance = "Tool-authored guidance.",
                    Theme = "Technological",
                })
                .ToList(),
            Diagnostics = Enumerable.Range(1, 40)
                .Select(index => new CollectionDiagnostic
                {
                    Timestamp = Reference.AddSeconds(index),
                    Severity = index % 7 == 0 ? DiagnosticSeverity.Warning : DiagnosticSeverity.Information,
                    CollectorId = index % 2 == 0 ? "ad.directory" : "entra.directory",
                    Message = $"Stage {index} completed; {index * 37} object(s) read.",
                })
                .ToList(),
            EvidenceRecords = Enumerable.Range(1, 18)
                .Select(index => new EvidenceRecord
                {
                    EvidenceId = $"evidence.{index:000}",
                    Kind = EvidenceKind.DirectoryQuery,
                    Source = index % 2 == 0 ? AssessmentSource.ActiveDirectory : AssessmentSource.Entra,
                    CollectorId = "ad.directory",
                    CollectedAt = Reference,
                    Summary = $"Query {index} returned {index * 113} object(s).",
                })
                .ToList(),
            Baseline = BuildBaseline(),
            RulePackVersion = "2026.09.1",
            GeneratedAt = Reference,
            AcceptedExceptions = ["Pinned certificate accepted for dc01.northwind.example on 2026-02-24 by A. Assessor"],
        };
    }

    private static Finding BuildFinding(int index, int affectedObjects)
    {
        var severity = (index % 4) switch
        {
            0 => RuleSeverity.Critical,
            1 => RuleSeverity.High,
            2 => RuleSeverity.Medium,
            _ => RuleSeverity.Low,
        };

        return new Finding
        {
            FindingId = $"SAMPLE-{index:000}",
            RuleId = new RuleId($"SAMPLE-{index:000}"),
            RuleVersion = 1,
            Title = $"Sample finding {index}: a configuration weakness that needs attention",
            Severity = severity,
            Domain = index % 3 == 0 ? RuleDomain.Entra : RuleDomain.ActiveDirectory,
            Group = index % 3 == 0 ? CheckGroup.EntraPrivilegedAccess : CheckGroup.AdPrivilegedAccess,
            Status = RuleStatus.Fail,
            RiskExplanation =
                "This condition widens the set of principals able to reach privileged access, and it " +
                "is not visible in a routine group membership review.",
            Remediation =
                "Remove the unnecessary grant, re-review the resulting membership, and record the " +
                "outcome against the relevant control.",
            Rationale = $"{affectedObjects} object(s) meet the failing condition.",
            AffectedObjects = Enumerable.Range(1, affectedObjects)
                .Select(objectIndex => new AffectedObject
                {
                    Identifier = $"S-1-5-21-1111111111-2222222222-3333333333-{1000 + objectIndex}",
                    DisplayName = $"sample.account{objectIndex:000}",
                    ObjectType = "user",
                    Detail = $"Reached through nested group {objectIndex % 5}",
                })
                .ToList(),
            FrameworkMappings =
            [
                new FrameworkMapping
                {
                    Framework = "ISO/IEC 27001:2022",
                    ControlId = "A.8.2",
                    Relevance = "Restriction of privileged access rights.",
                },
            ],
            DetectedAt = Reference,
        };
    }

    private static BaselineComparison BuildBaseline() => new()
    {
        BaselineId = "sample-baseline",
        ProductName = "Windows Server 2022",
        BaselineVersion = "September 2024",
        PackageSha256 = new string('7', 64),
        ComparedAt = Reference,
        Rows = Enumerable.Range(1, 90)
            .Select(index => new BaselineComparisonRow
            {
                SettingKey = $"registry::software\\policies\\sample\\value{index:000}",
                DisplayName = $"Sample baseline setting {index}",
                ExpectedValue = (index % 3).ToString(System.Globalization.CultureInfo.InvariantCulture),
                ObservedValue = index % 4 == 0
                    ? null
                    : (index % 2).ToString(System.Globalization.CultureInfo.InvariantCulture),
                Outcome = (index % 4) switch
                {
                    0 => BaselineComparisonOutcome.NotConfigured,
                    1 => BaselineComparisonOutcome.Match,
                    2 => BaselineComparisonOutcome.Different,
                    _ => BaselineComparisonOutcome.Match,
                },
            })
            .ToList(),
    };

    private static PostureScore BuildScore(string scope, int passed, int evaluated, int notCollected, int errored) => new()
    {
        Scope = scope,
        PassedWeight = passed,
        EvaluatedWeight = evaluated,
        NotCollectedWeight = notCollected,
        ErrorWeight = errored,
        NotApplicableCount = 4,
        StatusCounts = new Dictionary<RuleStatus, int>
        {
            [RuleStatus.Pass] = passed / 6,
            [RuleStatus.Fail] = (evaluated - passed) / 6,
            [RuleStatus.NotCollected] = notCollected / 3,
            [RuleStatus.NotApplicable] = 4,
        },
    };
}
