using Ipa.Contracts.Baselines;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.Baselines;

/// <summary>
/// Compares collected Group Policy content with an imported Microsoft baseline. The comparison is
/// deterministic and reported as its own metric, never folded into the posture score.
/// </summary>
public sealed class BaselineComparer
{
    /// <summary>Compares the baseline against every collected policy in the forest.</summary>
    /// <param name="baseline">The imported baseline.</param>
    /// <param name="policies">Collected Group Policy objects.</param>
    /// <param name="comparedAt">Timestamp recorded on the comparison.</param>
    /// <param name="sysvolAvailable">
    /// False when SYSVOL content could not be read, in which case registry and template settings
    /// are reported as not comparable rather than as missing from the environment.
    /// </param>
    public BaselineComparison Compare(
        ImportedBaseline baseline,
        IReadOnlyCollection<GroupPolicyObject> policies,
        DateTimeOffset comparedAt,
        bool sysvolAvailable = true)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(policies);

        var observedRegistry = new Dictionary<string, (string Value, List<string> Policies)>(StringComparer.OrdinalIgnoreCase);
        var observedTemplate = new Dictionary<string, (string Value, List<string> Policies)>(StringComparer.OrdinalIgnoreCase);

        foreach (var policy in policies)
        {
            foreach (var setting in policy.RegistrySettings)
            {
                var key = BaselineImporter.BuildRegistryKey(setting.KeyPath, setting.ValueName);
                Record(observedRegistry, key, setting.Value, policy.DisplayName);
            }

            foreach (var setting in policy.SecuritySettings)
            {
                var key = BaselineImporter.BuildTemplateKey(setting.Section, setting.Name);
                Record(observedTemplate, key, setting.Value, policy.DisplayName);
            }
        }

        var rows = new List<BaselineComparisonRow>(baseline.Settings.Count);

        foreach (var expected in baseline.Settings)
        {
            var lookup = expected.Kind switch
            {
                BaselineSettingKind.RegistryPolicy => observedRegistry,
                BaselineSettingKind.SecurityTemplate => observedTemplate,
                _ => null,
            };

            if (lookup is null)
            {
                rows.Add(new BaselineComparisonRow
                {
                    SettingKey = expected.SettingKey,
                    DisplayName = expected.DisplayName,
                    ExpectedValue = expected.ExpectedValue,
                    Outcome = BaselineComparisonOutcome.NotComparable,
                    Note = "Audit policy subcategories are not readable over the protocols this " +
                           "assessment uses, so the setting could not be compared.",
                });

                continue;
            }

            if (!sysvolAvailable)
            {
                rows.Add(new BaselineComparisonRow
                {
                    SettingKey = expected.SettingKey,
                    DisplayName = expected.DisplayName,
                    ExpectedValue = expected.ExpectedValue,
                    Outcome = BaselineComparisonOutcome.NotComparable,
                    Note = "SYSVOL policy content was not available, so the setting could not be compared.",
                });

                continue;
            }

            if (!lookup.TryGetValue(expected.SettingKey, out var observed))
            {
                rows.Add(new BaselineComparisonRow
                {
                    SettingKey = expected.SettingKey,
                    DisplayName = expected.DisplayName,
                    ExpectedValue = expected.ExpectedValue,
                    Outcome = BaselineComparisonOutcome.NotConfigured,
                });

                continue;
            }

            rows.Add(new BaselineComparisonRow
            {
                SettingKey = expected.SettingKey,
                DisplayName = expected.DisplayName,
                ExpectedValue = expected.ExpectedValue,
                ObservedValue = observed.Value,
                Outcome = ValuesMatch(expected, observed.Value)
                    ? BaselineComparisonOutcome.Match
                    : BaselineComparisonOutcome.Different,
                ConfiguringPolicies = observed.Policies,
            });
        }

        return new BaselineComparison
        {
            BaselineId = baseline.BaselineId,
            ProductName = baseline.ProductName,
            BaselineVersion = baseline.BaselineVersion,
            PackageSha256 = baseline.PackageSha256,
            ComparedAt = comparedAt,
            Rows = rows.OrderBy(row => row.SettingKey, StringComparer.Ordinal).ToList(),
        };
    }

    /// <summary>
    /// Compares an expected and an observed value. Trustee lists in privilege-rights settings are
    /// order independent, so they are compared as sets; everything else is compared as text with
    /// case and surrounding whitespace ignored.
    /// </summary>
    private static bool ValuesMatch(BaselineSetting expected, string observed)
    {
        if (expected.Kind == BaselineSettingKind.SecurityTemplate
            && expected.SettingKey.StartsWith("template::privilege rights::", StringComparison.OrdinalIgnoreCase))
        {
            var expectedTrustees = GroupPolicy.SecurityTemplateParser.ParseTrustees(expected.ExpectedValue)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var observedTrustees = GroupPolicy.SecurityTemplateParser.ParseTrustees(observed)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            return expectedTrustees.SetEquals(observedTrustees);
        }

        return string.Equals(
            expected.ExpectedValue.Trim(),
            observed.Trim(),
            StringComparison.OrdinalIgnoreCase);
    }

    private static void Record(
        Dictionary<string, (string Value, List<string> Policies)> map,
        string key,
        string value,
        string policyName)
    {
        if (map.TryGetValue(key, out var existing))
        {
            if (!existing.Policies.Contains(policyName, StringComparer.OrdinalIgnoreCase))
            {
                existing.Policies.Add(policyName);
            }

            // The last policy processed wins, mirroring Group Policy precedence for a duplicate value.
            map[key] = (value, existing.Policies);
            return;
        }

        map[key] = (value, [policyName]);
    }
}
