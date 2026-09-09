using System.Globalization;
using System.Text;
using Ipa.Contracts;
using Ipa.Contracts.Baselines;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Findings;
using Ipa.Contracts.Reporting;
using Ipa.Contracts.Rules;
using Ipa.Reporting.Model;

namespace Ipa.Reporting.Html;

/// <summary>
/// Composes the report as a single self-contained HTML document.
/// </summary>
/// <remarks>
/// The output references nothing external: styles are inline, images are embedded as data URIs and
/// charts are inline graphics, so rendering works with no network access. Composition is
/// deterministic - the same model always produces the same bytes - and every value that originates
/// outside the product is escaped, so a directory object named with markup cannot become markup.
/// </remarks>
public sealed class HtmlReportComposer
{
    /// <summary>Number of affected objects listed when the profile has not requested full lists.</summary>
    public const int DefaultSampleSize = 10;

    /// <summary>Composes the report document.</summary>
    public string Compose(ReportModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var builder = new StringBuilder(64 * 1024);
        var sections = new List<(string Id, string Title)>();

        builder.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        builder.Append("<meta charset=\"utf-8\">\n");
        builder.Append(CultureInfo.InvariantCulture,
            $"<title>{HtmlText.Escape(model.Profile.Branding.EffectiveProductName)} - " +
            $"{HtmlText.Escape(model.Metadata.CustomerName)}</title>\n");
        builder.Append("<style>\n").Append(ReportStyles.Build(model.Profile.Branding)).Append("\n</style>\n");
        builder.Append("</head>\n<body>\n");

        AppendCover(builder, model);

        var body = new StringBuilder(48 * 1024);

        void Section(ReportSection section, string id, string title, Action<StringBuilder> content)
        {
            if (!model.Profile.HasSection(section))
            {
                return;
            }

            sections.Add((id, title));

            body.Append(CultureInfo.InvariantCulture, $"<section class=\"report-section\" id=\"{HtmlText.Escape(id)}\">");
            body.Append(CultureInfo.InvariantCulture, $"<h2>{HtmlText.Escape(title)}</h2>");
            content(body);
            body.Append("</section>\n");
        }

        Section(ReportSection.ScopeAndMethodology, "scope", "Scope and methodology", section => AppendScope(section, model));
        Section(ReportSection.ExecutiveSummary, "summary", "Executive summary", section => AppendExecutiveSummary(section, model));
        Section(ReportSection.ScoreAndCoverage, "scores", "Scores and coverage", section => AppendScores(section, model));
        Section(ReportSection.PrioritisedFindings, "findings", "Prioritised findings", section => AppendFindings(section, model));
        Section(ReportSection.ActiveDirectoryDetail, "ad", "Active Directory detail", section => AppendDomainDetail(section, model, RuleDomain.ActiveDirectory));
        Section(ReportSection.EntraDetail, "entra", "Microsoft Entra detail", section => AppendDomainDetail(section, model, RuleDomain.Entra));
        Section(ReportSection.HybridDetail, "hybrid", "Hybrid identity detail", section => AppendDomainDetail(section, model, RuleDomain.Hybrid));
        Section(ReportSection.BaselineComparison, "baseline", "Microsoft baseline comparison", section => AppendBaseline(section, model));
        Section(ReportSection.IsoReadiness, "iso", "ISO/IEC 27001 readiness", section => AppendReadiness(section, model));
        Section(ReportSection.Exclusions, "exclusions", "Exclusions and limitations", section => AppendExclusions(section, model));
        Section(ReportSection.CollectionDiagnostics, "diagnostics", "Collection diagnostics", section => AppendDiagnostics(section, model));
        Section(ReportSection.RemediationRoadmap, "roadmap", "Remediation roadmap", section => AppendRoadmap(section, model));
        Section(ReportSection.EvidenceAppendix, "evidence", "Evidence appendix", section => AppendEvidence(section, model));

        if (model.Profile.HasSection(ReportSection.ScopeAndMethodology) || sections.Count > 0)
        {
            AppendTableOfContents(builder, sections);
        }

        builder.Append(body);
        builder.Append("</body>\n</html>\n");

        return builder.ToString();
    }

    private static void AppendCover(StringBuilder builder, ReportModel model)
    {
        if (!model.Profile.HasSection(ReportSection.Cover))
        {
            return;
        }

        var branding = model.Profile.Branding;
        var logo = HtmlText.DataUri(branding.LogoBytes, branding.LogoMediaType);

        builder.Append("<header class=\"cover\">");

        if (logo is not null)
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"<img class=\"cover-logo\" src=\"{logo}\" alt=\"{HtmlText.Escape(branding.AssessorCompany ?? "Assessor")} logo\">");
        }

        builder.Append(CultureInfo.InvariantCulture,
            $"<p class=\"cover-product\">{HtmlText.Escape(branding.EffectiveProductName)}</p>");

        builder.Append(CultureInfo.InvariantCulture,
            $"<h1 class=\"cover-customer\">{HtmlText.Escape(branding.CustomerName ?? model.Metadata.CustomerName)}</h1>");

        builder.Append(CultureInfo.InvariantCulture, $"<p class=\"muted\">{HtmlText.Escape(ProductInfo.Descriptor)}</p>");

        builder.Append("<dl class=\"cover-meta\">");
        AppendDefinition(builder, "Assessor", branding.AssessorName ?? model.Metadata.AssessorName);
        AppendDefinition(builder, "Assessor company", branding.AssessorCompany ?? model.Metadata.AssessorCompany);
        AppendDefinition(builder, "Engagement reference", model.Metadata.EngagementReference);
        AppendDefinition(builder, "Assessment period", FormatPeriod(model));
        AppendDefinition(builder, "Report version", model.Profile.ReportVersion);
        AppendDefinition(builder, "Generated", model.GeneratedAt.ToString("u", CultureInfo.InvariantCulture));
        AppendDefinition(builder, "Rule pack", model.RulePackVersion);
        AppendDefinition(builder, "Application version", model.ApplicationVersion);
        builder.Append("</dl>");

        if (model.Profile.SignOffNames.Count > 0)
        {
            builder.Append("<p class=\"muted small\">Signed off by: ");
            builder.Append(HtmlText.Escape(string.Join(", ", model.Profile.SignOffNames)));
            builder.Append("</p>");
        }

        builder.Append(CultureInfo.InvariantCulture,
            $"<p class=\"confidentiality\">{HtmlText.Escape(branding.ConfidentialityLabel)}</p>");

        builder.Append("</header>\n");
    }

    private static void AppendTableOfContents(StringBuilder builder, IReadOnlyList<(string Id, string Title)> sections)
    {
        builder.Append("<nav class=\"toc report-section\" id=\"contents\" aria-label=\"Table of contents\">");
        builder.Append("<h2>Contents</h2><ol>");

        var number = 1;

        foreach (var (id, title) in sections)
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"<li><a href=\"#{HtmlText.Escape(id)}\">{number++}. {HtmlText.Escape(title)}</a></li>");
        }

        builder.Append("</ol></nav>\n");
    }

    private static void AppendScope(StringBuilder builder, ReportModel model)
    {
        builder.Append("<h3>Sources assessed</h3><ul>");

        builder.Append(CultureInfo.InvariantCulture,
            $"<li>Active Directory forest: {(model.Scope.IncludeActiveDirectory ? "assessed" : "<strong>not assessed</strong>")}</li>");

        builder.Append(CultureInfo.InvariantCulture,
            $"<li>Microsoft Entra tenant: {(model.Scope.IncludeEntra ? "assessed" : "<strong>not assessed</strong>")}</li>");

        builder.Append(CultureInfo.InvariantCulture,
            $"<li>Hybrid correlation: {(model.Scope.IncludeHybrid ? "assessed" : "<strong>disabled, because only one source was connected</strong>")}</li>");

        builder.Append("</ul>");

        if (!model.Scope.IncludeHybrid)
        {
            builder.Append("<div class=\"callout warning\"><strong>Single-source assessment.</strong> ");
            builder.Append("Hybrid identity rules require both an Active Directory forest and an Entra tenant. ");
            builder.Append("The hybrid score is disabled for this assessment and the missing source is stated above.</div>");
        }

        builder.Append("<h3>Method</h3>");
        builder.Append("<p>This assessment is read-only. It issues no directory or tenant write request of any kind: ");
        builder.Append("directory access is limited to searches, and cloud access uses read-only Microsoft Graph ");
        builder.Append("permissions only. No remediation is performed, no server is probed and no credential is retained.</p>");

        builder.Append("<p>Every age comparison uses a single reference instant fixed when the assessment started, ");
        builder.Append("so re-evaluating the same evidence with the same rule pack version reproduces the same ");
        builder.Append("scores exactly.</p>");

        builder.Append("<h3>Scoring</h3>");
        builder.Append("<p>Each rule carries a weight derived from its severity: critical 10, high 6, medium 3 and ");
        builder.Append("low 1. Informational rules carry no weight. A passed rule earns its full weight and a failed ");
        builder.Append("rule earns none. A rule that does not apply is excluded from the score entirely. A rule whose ");
        builder.Append("evidence could not be collected, or which errored, is excluded from the score but reduces ");
        builder.Append("weighted collection coverage. A score with coverage below 90% is labelled provisional.</p>");

        builder.Append("<p>Microsoft Secure Score and conformity with an imported Microsoft baseline are reported as ");
        builder.Append("separate, clearly attributed metrics. Neither is blended into the posture score, so no control ");
        builder.Append("is counted twice.</p>");

        if (model.Metadata.ScopeNotes is { Length: > 0 })
        {
            builder.Append("<h3>Scope notes</h3><p>");
            builder.Append(HtmlText.Escape(model.Metadata.ScopeNotes));
            builder.Append("</p>");
        }

        if (model.AcceptedExceptions.Count > 0)
        {
            builder.Append("<h3>Accepted exceptions</h3><ul>");

            foreach (var exception in model.AcceptedExceptions)
            {
                builder.Append(CultureInfo.InvariantCulture, $"<li>{HtmlText.Escape(exception)}</li>");
            }

            builder.Append("</ul>");
        }
    }

    private static void AppendExecutiveSummary(StringBuilder builder, ReportModel model)
    {
        var overall = model.Scores.Overall;

        if (!string.IsNullOrWhiteSpace(model.Profile.ExecutiveNarrative))
        {
            builder.Append("<p>").Append(HtmlText.Escape(model.Profile.ExecutiveNarrative)).Append("</p>");
        }

        var critical = model.Findings.Count(finding => finding.Severity == RuleSeverity.Critical);
        var high = model.Findings.Count(finding => finding.Severity == RuleSeverity.High);

        builder.Append(CultureInfo.InvariantCulture,
            $"<p>The overall identity posture score is <strong>{HtmlText.Escape(overall.Value?.ToString(CultureInfo.InvariantCulture) ?? "not available")}</strong> " +
            $"out of 100, at {overall.CoveragePercent.ToString(CultureInfo.InvariantCulture)}% weighted collection coverage. " +
            $"The assessment produced <strong>{critical.ToString(CultureInfo.InvariantCulture)}</strong> critical and " +
            $"<strong>{high.ToString(CultureInfo.InvariantCulture)}</strong> high severity finding(s).</p>");

        if (overall.IsProvisional)
        {
            builder.Append("<div class=\"callout warning\"><strong>Provisional score.</strong> ");
            builder.Append("Weighted collection coverage is below 90%, so parts of the environment were not assessed. ");
            builder.Append("The exclusions section states what was missing and why.</div>");
        }

        builder.Append("<div class=\"score-grid\">");
        builder.Append(AccessibleCharts.ScoreCard("Overall", overall.Value, overall.CoveragePercent, overall.IsProvisional, model.Profile.Branding.PrimaryColor));

        foreach (var (domain, score) in model.Scores.ByDomain.OrderBy(entry => entry.Key.ToString(), StringComparer.Ordinal))
        {
            builder.Append(AccessibleCharts.ScoreCard(
                DomainLabel(domain), score.Value, score.CoveragePercent, score.IsProvisional,
                model.Profile.Branding.SecondaryColor));
        }

        builder.Append("</div>");

        var severities = new[] { RuleSeverity.Critical, RuleSeverity.High, RuleSeverity.Medium, RuleSeverity.Low }
            .Select(severity => new ChartDatum(
                severity.ToString(),
                model.Findings.Count(finding => finding.Severity == severity),
                SeverityColour(severity)))
            .ToList();

        builder.Append(AccessibleCharts.BarChart(
            "Findings by severity",
            "The number of open findings in each severity band.",
            severities,
            "severity"));
    }

    private static void AppendScores(StringBuilder builder, ReportModel model)
    {
        builder.Append("<h3>Category scores</h3>");

        var categories = model.Scores.ByGroup
            .OrderBy(entry => entry.Key.ToString(), StringComparer.Ordinal)
            .Select(entry => new ChartDatum(
                SplitCamelCase(entry.Key.ToString()),
                entry.Value.Value ?? 0,
                model.Profile.Branding.SecondaryColor))
            .ToList();

        builder.Append(AccessibleCharts.BarChart(
            "Score by check group",
            "The posture score of each check group, from zero to one hundred.",
            categories,
            "categories"));

        builder.Append("<h3>Coverage by category</h3>");
        builder.Append("<table><thead><tr><th scope=\"col\">Check group</th><th scope=\"col\">Score</th>");
        builder.Append("<th scope=\"col\">Coverage</th><th scope=\"col\">Passed</th><th scope=\"col\">Failed</th>");
        builder.Append("<th scope=\"col\">Not collected</th><th scope=\"col\">Not applicable</th></tr></thead><tbody>");

        foreach (var (group, score) in model.Scores.ByGroup.OrderBy(entry => entry.Key.ToString(), StringComparer.Ordinal))
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td>{HtmlText.Escape(SplitCamelCase(group.ToString()))}</td>" +
                $"<td>{HtmlText.Escape(score.Value?.ToString(CultureInfo.InvariantCulture) ?? "n/a")}" +
                $"{(score.IsProvisional ? " <span class=\"badge medium\">Provisional</span>" : string.Empty)}</td>" +
                $"<td>{score.CoveragePercent.ToString(CultureInfo.InvariantCulture)}%</td>" +
                $"<td>{score.StatusCounts.GetValueOrDefault(RuleStatus.Pass).ToString(CultureInfo.InvariantCulture)}</td>" +
                $"<td>{score.StatusCounts.GetValueOrDefault(RuleStatus.Fail).ToString(CultureInfo.InvariantCulture)}</td>" +
                $"<td>{score.StatusCounts.GetValueOrDefault(RuleStatus.NotCollected).ToString(CultureInfo.InvariantCulture)}</td>" +
                $"<td>{score.NotApplicableCount.ToString(CultureInfo.InvariantCulture)}</td></tr>");
        }

        builder.Append("</tbody></table>");

        if (model.Scores.MicrosoftSecureScore is { } provider)
        {
            builder.Append("<h3>Provider metric</h3>");
            builder.Append("<div class=\"callout\"><strong>");
            builder.Append(HtmlText.Escape($"{provider.Provider} {provider.MetricName}"));
            builder.Append(":</strong> ");
            builder.Append(CultureInfo.InvariantCulture,
                $"{provider.Current.ToString("0.#", CultureInfo.InvariantCulture)} of " +
                $"{provider.Maximum.ToString("0.#", CultureInfo.InvariantCulture)} " +
                $"({provider.Percent.ToString(CultureInfo.InvariantCulture)}%) as of " +
                $"{provider.AsOf.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}. ");
            builder.Append("This is the provider's own measurement of a different control set. It is shown for ");
            builder.Append("context and is deliberately not blended into the posture score above.</div>");
        }
    }

    private void AppendFindings(StringBuilder builder, ReportModel model)
    {
        var open = model.Findings
            .OrderByDescending(finding => finding.Severity)
            .ThenBy(finding => finding.RuleId.Value, StringComparer.Ordinal)
            .ToList();

        if (open.Count == 0)
        {
            builder.Append("<p>No rule failed in the assessed scope.</p>");
            return;
        }

        foreach (var finding in open)
        {
            var severity = finding.Severity.ToString().ToLowerInvariant();

            builder.Append(CultureInfo.InvariantCulture, $"<div class=\"finding {severity}\">");
            builder.Append("<div class=\"finding-heading\">");
            builder.Append(CultureInfo.InvariantCulture, $"<h3>{HtmlText.Escape(finding.Title)}</h3>");
            builder.Append(CultureInfo.InvariantCulture,
                $"<span class=\"badge {severity}\">{HtmlText.Escape(finding.Severity.ToString())}</span>");
            builder.Append("</div>");

            builder.Append(CultureInfo.InvariantCulture,
                $"<p class=\"finding-id\">{HtmlText.Escape(finding.RuleId.Value)} " +
                $"(version {finding.RuleVersion.ToString(CultureInfo.InvariantCulture)}) - " +
                $"{HtmlText.Escape(SplitCamelCase(finding.Group.ToString()))}</p>");

            builder.Append("<p><strong>Observed:</strong> ").Append(HtmlText.Escape(finding.Rationale)).Append("</p>");
            builder.Append("<p><strong>Why it matters:</strong> ").Append(HtmlText.Escape(finding.RiskExplanation)).Append("</p>");
            builder.Append("<p><strong>Remediation:</strong> ").Append(HtmlText.Escape(finding.Remediation)).Append("</p>");

            AppendAffectedObjects(builder, model, finding);

            if (finding.FrameworkMappings.Count > 0)
            {
                builder.Append("<p class=\"small muted\"><strong>Framework mapping:</strong> ");
                builder.Append(HtmlText.Escape(string.Join(
                    ", ",
                    finding.FrameworkMappings.Select(mapping => $"{mapping.Framework} {mapping.ControlId}"))));
                builder.Append("</p>");
            }

            if (finding.OperatorNotes is { Length: > 0 })
            {
                builder.Append("<p class=\"small\"><strong>Assessor notes:</strong> ");
                builder.Append(HtmlText.Escape(finding.OperatorNotes));
                builder.Append("</p>");
            }

            if (finding.Exception is { } exception)
            {
                builder.Append("<p class=\"small\"><span class=\"badge annotated\">");
                builder.Append(HtmlText.Escape(SplitCamelCase(exception.Disposition.ToString())));
                builder.Append("</span> ");
                builder.Append(HtmlText.Escape(exception.Justification));
                builder.Append(CultureInfo.InvariantCulture,
                    $" Recorded by {HtmlText.Escape(exception.RecordedBy)} on " +
                    $"{exception.RecordedAt.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}. ");
                builder.Append("This annotation is reported but does not change the score.</p>");
            }

            builder.Append("</div>");
        }
    }

    private void AppendAffectedObjects(StringBuilder builder, ReportModel model, Finding finding)
    {
        if (finding.AffectedObjects.Count == 0)
        {
            return;
        }

        var limit = model.Profile.IncludeFullAffectedObjectLists
            ? finding.AffectedObjects.Count
            : Math.Min(model.Profile.AffectedObjectSampleSize, finding.AffectedObjects.Count);

        builder.Append(CultureInfo.InvariantCulture,
            $"<p class=\"small\"><strong>Affected objects:</strong> " +
            $"{finding.AffectedObjects.Count.ToString(CultureInfo.InvariantCulture)}</p>");

        builder.Append("<table><thead><tr><th scope=\"col\">Object</th><th scope=\"col\">Type</th>");

        if (model.Profile.IncludeRawObjectAttributes)
        {
            builder.Append("<th scope=\"col\">Detail</th>");
        }

        builder.Append("</tr></thead><tbody>");

        foreach (var affected in finding.AffectedObjects.Take(limit))
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td>{HtmlText.Escape(affected.DisplayName)}</td><td>{HtmlText.Escape(affected.ObjectType)}</td>");

            if (model.Profile.IncludeRawObjectAttributes)
            {
                // Raw detail appears only when the operator has explicitly opted in, having been
                // warned that it places directory attributes into an unencrypted export.
                builder.Append(CultureInfo.InvariantCulture, $"<td>{HtmlText.Escape(affected.Detail)}</td>");
            }

            builder.Append("</tr>");
        }

        builder.Append("</tbody></table>");

        if (limit < finding.AffectedObjects.Count)
        {
            builder.Append(
                $"<p class=\"small muted\">Showing the first {limit.ToString(CultureInfo.InvariantCulture)} of " +
                $"{finding.AffectedObjects.Count.ToString(CultureInfo.InvariantCulture)} affected object(s). " +
                "Enable full affected-object lists in the report profile to include the remainder.</p>");
        }
    }

    private static void AppendDomainDetail(StringBuilder builder, ReportModel model, RuleDomain domain)
    {
        if (!model.Scores.ByDomain.TryGetValue(domain, out var score))
        {
            builder.Append(
                $"<p>The {HtmlText.Escape(DomainLabel(domain))} source was not part of this assessment, so no result " +
                "is reported for it.</p>");

            return;
        }

        builder.Append("<div class=\"score-grid\">");
        builder.Append(AccessibleCharts.ScoreCard(
            DomainLabel(domain), score.Value, score.CoveragePercent, score.IsProvisional,
            model.Profile.Branding.PrimaryColor));
        builder.Append("</div>");

        builder.Append("<table><thead><tr><th scope=\"col\">Rule</th><th scope=\"col\">Title</th>");
        builder.Append("<th scope=\"col\">Status</th><th scope=\"col\">Observation</th></tr></thead><tbody>");

        var findingsById = model.Findings.ToDictionary(
            finding => finding.RuleId.Value,
            finding => finding,
            StringComparer.OrdinalIgnoreCase);

        foreach (var result in model.Results.OrderBy(result => result.RuleId.Value, StringComparer.Ordinal))
        {
            if (!findingsById.TryGetValue(result.RuleId.Value, out var finding))
            {
                continue;
            }

            if (finding.Domain != domain)
            {
                continue;
            }

            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td class=\"mono\">{HtmlText.Escape(result.RuleId.Value)}</td>" +
                $"<td>{HtmlText.Escape(finding.Title)}</td>" +
                $"<td><span class=\"badge {finding.Severity.ToString().ToLowerInvariant()}\">" +
                $"{HtmlText.Escape(result.Status.ToString())}</span></td>" +
                $"<td>{HtmlText.Escape(result.Rationale)}</td></tr>");
        }

        builder.Append("</tbody></table>");
    }

    private static void AppendBaseline(StringBuilder builder, ReportModel model)
    {
        if (model.Baseline is not { } comparison)
        {
            builder.Append("<p>No Microsoft security baseline was imported for this assessment, so no ");
            builder.Append("comparison is reported.</p>");
            return;
        }

        builder.Append("<div class=\"callout\"><strong>Separately reported metric.</strong> ");
        builder.Append("Baseline conformity measures a different and much larger control set than the posture ");
        builder.Append("rules. It is reported here on its own so that no setting is counted twice.</div>");

        builder.Append(CultureInfo.InvariantCulture,
            $"<p><strong>Baseline:</strong> {HtmlText.Escape(comparison.ProductName)} " +
            $"{HtmlText.Escape(comparison.BaselineVersion)}<br>" +
            $"<span class=\"small mono\">Package SHA-256: {HtmlText.Escape(comparison.PackageSha256)}</span></p>");

        var distribution = new List<ChartDatum>
        {
            new("Matching", comparison.MatchCount, "#2f6b4f"),
            new("Different", comparison.DifferentCount, "#cf5c36"),
            new("Not configured", comparison.NotConfiguredCount, "#c9a227"),
            new("Not comparable", comparison.NotComparableCount, "#5b5b5b"),
        };

        builder.Append(AccessibleCharts.RingChart(
            $"Baseline conformity: {comparison.ConformityPercent.ToString(CultureInfo.InvariantCulture)}%",
            "The proportion of comparable baseline settings that match the assessed environment.",
            distribution,
            "baseline"));

        var deviations = comparison.Rows
            .Where(row => row.Outcome is BaselineComparisonOutcome.Different or BaselineComparisonOutcome.NotConfigured)
            .OrderBy(row => row.SettingKey, StringComparer.Ordinal)
            .Take(200)
            .ToList();

        if (deviations.Count == 0)
        {
            builder.Append("<p>Every comparable setting matches the imported baseline.</p>");
            return;
        }

        builder.Append("<h3>Deviations</h3>");
        builder.Append("<table><thead><tr><th scope=\"col\">Setting</th><th scope=\"col\">Expected</th>");
        builder.Append("<th scope=\"col\">Observed</th><th scope=\"col\">Outcome</th></tr></thead><tbody>");

        foreach (var row in deviations)
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td>{HtmlText.Escape(row.DisplayName)}</td>" +
                $"<td class=\"mono\">{HtmlText.Escape(row.ExpectedValue)}</td>" +
                $"<td class=\"mono\">{HtmlText.Escape(row.ObservedValue ?? "not configured")}</td>" +
                $"<td>{HtmlText.Escape(SplitCamelCase(row.Outcome.ToString()))}</td></tr>");
        }

        builder.Append("</tbody></table>");
    }

    private static void AppendReadiness(StringBuilder builder, ReportModel model)
    {
        var readiness = model.Readiness;

        builder.Append("<div class=\"callout warning\"><strong>");
        builder.Append(HtmlText.Escape(ProductInfo.IsoReadinessDisclaimer));
        builder.Append("</strong> This section reports readiness against control identifiers only. ");
        builder.Append("The labels and guidance are written by this product; the text of the standard is ");
        builder.Append("copyright protected and is not reproduced here.</div>");

        builder.Append("<div class=\"score-grid\">");
        builder.Append(AccessibleCharts.ScoreCard(
            "Evidence coverage", readiness.EvidenceCoveragePercent, readiness.EvidenceCoveragePercent, false,
            model.Profile.Branding.SecondaryColor));
        builder.Append(AccessibleCharts.ScoreCard(
            "Readiness", readiness.ReadinessPercent, readiness.EvidenceCoveragePercent, false,
            model.Profile.Branding.PrimaryColor));
        builder.Append("</div>");

        builder.Append(
            $"<p>{readiness.AssessedControlCount.ToString(CultureInfo.InvariantCulture)} of " +
            $"{readiness.ApplicableControlCount.ToString(CultureInfo.InvariantCulture)} applicable control(s) have been " +
            $"assessed, and {readiness.ConfirmedSatisfiedCount.ToString(CultureInfo.InvariantCulture)} of those are " +
            "confirmed satisfied by the assessor.</p>");

        var distribution = readiness.StatusDistribution
            .OrderBy(entry => entry.Key.ToString(), StringComparer.Ordinal)
            .Select(entry => new ChartDatum(
                SplitCamelCase(entry.Key.ToString()),
                entry.Value,
                StatusColour(entry.Key)))
            .ToList();

        builder.Append(AccessibleCharts.RingChart(
            "Control status distribution",
            "The number of controls in each status.",
            distribution,
            "iso-status"));

        var definitions = model.ControlDefinitions.ToDictionary(
            definition => definition.ControlId,
            definition => definition,
            StringComparer.OrdinalIgnoreCase);

        builder.Append("<h3>Controls</h3>");
        builder.Append("<table><thead><tr><th scope=\"col\">Control</th><th scope=\"col\">Subject</th>");
        builder.Append("<th scope=\"col\">Status</th><th scope=\"col\">Confirmed</th>");
        builder.Append("<th scope=\"col\">Owner</th><th scope=\"col\">Mapped rules</th></tr></thead><tbody>");

        foreach (var control in model.Controls.Where(control => control.IsApplicable))
        {
            var definition = definitions.GetValueOrDefault(control.ControlId);

            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td class=\"mono\">{HtmlText.Escape(control.ControlId)}</td>" +
                $"<td>{HtmlText.Escape(definition?.ToolAuthoredLabel ?? string.Empty)}</td>" +
                $"<td>{HtmlText.Escape(SplitCamelCase(control.Status.ToString()))}</td>" +
                $"<td>{(control.OperatorConfirmed ? "Yes" : "No")}</td>" +
                $"<td>{HtmlText.Escape(control.Owner ?? string.Empty)}</td>" +
                $"<td class=\"mono small\">{HtmlText.Escape(string.Join(", ", control.MappedRuleIds))}</td></tr>");
        }

        builder.Append("</tbody></table>");
    }

    private static void AppendExclusions(StringBuilder builder, ReportModel model)
    {
        builder.Append("<p>Everything listed here was not evaluated. A rule that could not be evaluated is never ");
        builder.Append("reported as passing: it is excluded from the score, and where its evidence was expected but ");
        builder.Append("missing it also reduces weighted collection coverage.</p>");

        if (model.Exclusions.Count == 0)
        {
            builder.Append("<p>Every rule in the selected scope was evaluated.</p>");
            return;
        }

        builder.Append("<table><thead><tr><th scope=\"col\">Rule</th><th scope=\"col\">Title</th>");
        builder.Append("<th scope=\"col\">Status</th><th scope=\"col\">Reason</th></tr></thead><tbody>");

        foreach (var exclusion in model.Exclusions)
        {
            var status = exclusion.Availability is { } availability
                ? $"{SplitCamelCase(exclusion.Status.ToString())} ({SplitCamelCase(availability.ToString())})"
                : SplitCamelCase(exclusion.Status.ToString());

            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td class=\"mono\">{HtmlText.Escape(exclusion.RuleId)}</td>" +
                $"<td>{HtmlText.Escape(exclusion.Title)}</td>" +
                $"<td>{HtmlText.Escape(status)}</td>" +
                $"<td>{HtmlText.Escape(exclusion.Reason)}</td></tr>");
        }

        builder.Append("</tbody></table>");

        if (model.AnnotatedFindings.Count > 0)
        {
            builder.Append("<h3>Operator annotations</h3>");
            builder.Append("<p>These findings carry an operator disposition. The annotation is reported but the ");
            builder.Append("underlying score is unchanged.</p>");
            builder.Append("<table><thead><tr><th scope=\"col\">Rule</th><th scope=\"col\">Disposition</th>");
            builder.Append("<th scope=\"col\">Justification</th><th scope=\"col\">Recorded by</th></tr></thead><tbody>");

            foreach (var finding in model.AnnotatedFindings)
            {
                builder.Append(CultureInfo.InvariantCulture,
                    $"<tr><td class=\"mono\">{HtmlText.Escape(finding.RuleId.Value)}</td>" +
                    $"<td>{HtmlText.Escape(SplitCamelCase(finding.Disposition.ToString()))}</td>" +
                    $"<td>{HtmlText.Escape(finding.Exception?.Justification)}</td>" +
                    $"<td>{HtmlText.Escape(finding.Exception?.RecordedBy)}</td></tr>");
            }

            builder.Append("</tbody></table>");
        }
    }

    private static void AppendDiagnostics(StringBuilder builder, ReportModel model)
    {
        if (model.Diagnostics.Count == 0)
        {
            builder.Append("<p>Collection produced no diagnostics.</p>");
            return;
        }

        builder.Append("<p>The collection log explains what each collector reached and what it could not. ");
        builder.Append("Credentials, tokens and sensitive directory attributes are removed from these messages ");
        builder.Append("before they are recorded.</p>");

        builder.Append("<table><thead><tr><th scope=\"col\">Time</th><th scope=\"col\">Severity</th>");
        builder.Append("<th scope=\"col\">Collector</th><th scope=\"col\">Message</th></tr></thead><tbody>");

        foreach (var diagnostic in model.Diagnostics.Where(diagnostic => diagnostic.Severity >= DiagnosticSeverity.Information))
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td class=\"mono small\">{diagnostic.Timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}</td>" +
                $"<td>{HtmlText.Escape(diagnostic.Severity.ToString())}</td>" +
                $"<td class=\"mono small\">{HtmlText.Escape(diagnostic.CollectorId)}</td>" +
                $"<td>{HtmlText.Escape(diagnostic.Message)}</td></tr>");
        }

        builder.Append("</tbody></table>");
    }

    private static void AppendRoadmap(StringBuilder builder, ReportModel model)
    {
        if (model.Roadmap.Count == 0)
        {
            builder.Append("<p>No remediation is outstanding in the assessed scope.</p>");
            return;
        }

        builder.Append("<p>Steps are ordered by severity and then by the number of objects each finding affects, ");
        builder.Append("so the work that removes the most exposure appears first.</p>");

        builder.Append("<table><thead><tr><th scope=\"col\">#</th><th scope=\"col\">Finding</th>");
        builder.Append("<th scope=\"col\">Severity</th><th scope=\"col\">Objects</th>");
        builder.Append("<th scope=\"col\">Horizon</th><th scope=\"col\">Action</th></tr></thead><tbody>");

        foreach (var step in model.Roadmap)
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td>{step.Order.ToString(CultureInfo.InvariantCulture)}</td>" +
                $"<td>{HtmlText.Escape(step.Title)}<br><span class=\"mono small\">{HtmlText.Escape(step.RuleId)}</span></td>" +
                $"<td><span class=\"badge {step.Severity.ToString().ToLowerInvariant()}\">" +
                $"{HtmlText.Escape(step.Severity.ToString())}</span></td>" +
                $"<td>{step.AffectedObjectCount.ToString(CultureInfo.InvariantCulture)}</td>" +
                $"<td>{HtmlText.Escape(step.Horizon)}</td>" +
                $"<td>{HtmlText.Escape(step.Remediation)}</td></tr>");
        }

        builder.Append("</tbody></table>");
    }

    private static void AppendEvidence(StringBuilder builder, ReportModel model)
    {
        builder.Append("<p>Each entry records what was collected, by which collector and when. ");

        if (!model.Profile.IncludeRawObjectAttributes)
        {
            builder.Append("Raw attribute payloads are summarised rather than reproduced, because raw evidence was ");
            builder.Append("not requested for this report.");
        }
        else
        {
            builder.Append("Raw payloads are included because the report profile requested them.");
        }

        builder.Append("</p>");

        if (model.EvidenceRecords.Count == 0)
        {
            builder.Append("<p>No evidence records were retained for this assessment.</p>");
            return;
        }

        builder.Append("<table><thead><tr><th scope=\"col\">Identifier</th><th scope=\"col\">Source</th>");
        builder.Append("<th scope=\"col\">Collected</th><th scope=\"col\">Summary</th></tr></thead><tbody>");

        foreach (var record in model.EvidenceRecords.OrderBy(record => record.EvidenceId, StringComparer.Ordinal))
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td class=\"mono small\">{HtmlText.Escape(record.EvidenceId)}</td>" +
                $"<td>{HtmlText.Escape(record.Source.ToString())}</td>" +
                $"<td class=\"small\">{record.CollectedAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)}</td>" +
                $"<td>{HtmlText.Escape(record.Summary)}</td></tr>");

            if (model.Profile.IncludeRawObjectAttributes && record.Payload is { Length: > 0 })
            {
                builder.Append(CultureInfo.InvariantCulture,
                    $"<tr><td colspan=\"4\" class=\"mono small\">{HtmlText.Escape(record.Payload)}</td></tr>");
            }
        }

        builder.Append("</tbody></table>");
    }

    private static void AppendDefinition(StringBuilder builder, string term, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        builder.Append(CultureInfo.InvariantCulture,
            $"<dt>{HtmlText.Escape(term)}</dt><dd>{HtmlText.Escape(value)}</dd>");
    }

    private static string FormatPeriod(ReportModel model)
    {
        var start = model.Profile.AssessmentStartDate ?? model.Metadata.PlannedStartDate;
        var end = model.Profile.AssessmentEndDate ?? model.Metadata.PlannedEndDate;

        return (start, end) switch
        {
            (null, null) => string.Empty,
            (not null, null) => start!.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            (null, not null) => end!.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            _ => $"{start!.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)} to " +
                 $"{end!.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}",
        };
    }

    /// <summary>Inserts spaces into a camel-case identifier for display.</summary>
    public static string SplitCamelCase(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var builder = new StringBuilder(value.Length + 8);

        for (var index = 0; index < value.Length; index++)
        {
            if (index > 0 && char.IsUpper(value[index]) && !char.IsUpper(value[index - 1]))
            {
                builder.Append(' ');
                builder.Append(char.ToLowerInvariant(value[index]));
                continue;
            }

            builder.Append(value[index]);
        }

        return builder.ToString();
    }

    private static string DomainLabel(RuleDomain domain) => domain switch
    {
        RuleDomain.ActiveDirectory => "Active Directory",
        RuleDomain.Entra => "Microsoft Entra",
        RuleDomain.Hybrid => "Hybrid identity",
        _ => domain.ToString(),
    };

    private static string SeverityColour(RuleSeverity severity) => severity switch
    {
        RuleSeverity.Critical => "#a4243b",
        RuleSeverity.High => "#cf5c36",
        RuleSeverity.Medium => "#c9a227",
        RuleSeverity.Low => "#5a7d7c",
        _ => "#5b5b5b",
    };

    private static string StatusColour(ControlStatus status) => status switch
    {
        ControlStatus.Satisfied => "#2f6b4f",
        ControlStatus.Partial => "#c9a227",
        ControlStatus.Unsatisfied => "#a4243b",
        ControlStatus.NotApplicable => "#5b5b5b",
        _ => "#9aa5b1",
    };
}
