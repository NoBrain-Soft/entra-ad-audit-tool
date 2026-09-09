using Ipa.Contracts;
using Ipa.Contracts.Baselines;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;

namespace Ipa.Rules.Evaluators.Baseline;

/// <summary>
/// Reports conformity against the operator-imported Microsoft security baseline. The rule is
/// informational and carries no weight: baseline conformity is published as its own metric so
/// that a setting is never counted both here and in a posture rule.
/// </summary>
public sealed class BaselineConformityRule : RuleBase
{
    public override RuleDefinition Definition { get; } = RuleFactory.Create(
        id: "BAS-001",
        version: 1,
        title: "Group Policy conformity with the imported Microsoft baseline",
        domain: RuleDomain.ActiveDirectory,
        group: CheckGroup.BaselineConformity,
        severity: RuleSeverity.Informational,
        rationale: "The comparison shows how the assessed environment differs from the Microsoft " +
                   "security baseline the operator imported. It is reported as a separate metric " +
                   "because the baseline covers a different and much larger control set than the " +
                   "posture rules, and blending the two would count several settings twice.",
        remediation: "Review the settings that differ from the baseline, decide which deviations " +
                     "are justified for this environment, and record the rest as remediation items.",
        evidenceKeys: [EvidenceKeys.BaselineComparison],
        applicability: "Applies when the operator has imported a Microsoft Security Compliance Toolkit baseline.",
        mappings: [(RuleFactory.Iso27001, "A.8.9", "Configuration management against a defined baseline.")]);

    protected override RuleResult EvaluateCore(RuleEvaluationContext context)
    {
        var comparison = context.Evidence.BaselineComparison;

        if (comparison is null)
        {
            return NotCollected(
                context,
                EvidenceAvailability.NotSelected,
                "No Microsoft security baseline was imported for this assessment.");
        }

        var affected = comparison.Rows
            .Where(row => row.Outcome is BaselineComparisonOutcome.Different or BaselineComparisonOutcome.NotConfigured)
            .Select(row => new AffectedObject
            {
                Identifier = row.SettingKey,
                DisplayName = row.DisplayName,
                ObjectType = "baselineSetting",
                Source = AssessmentSource.ImportedBaseline,
                Detail = row.Outcome == BaselineComparisonOutcome.NotConfigured
                    ? $"Not configured; baseline expects {row.ExpectedValue}"
                    : $"Configured as {row.ObservedValue}; baseline expects {row.ExpectedValue}",
                Sensitivity = Sensitivity.Summary,
            })
            .ToList();

        return Pass(
            context,
            $"{comparison.MatchCount} of {comparison.ComparableCount} comparable setting(s) match " +
            $"the {comparison.ProductName} {comparison.BaselineVersion} baseline " +
            $"({comparison.ConformityPercent}% conformity). {comparison.DifferentCount} differ, " +
            $"{comparison.NotConfiguredCount} are not configured and {comparison.NotComparableCount} " +
            "could not be compared. Baseline conformity is reported separately from the posture score.",
            RuleHelpers.Cap(affected));
    }
}
