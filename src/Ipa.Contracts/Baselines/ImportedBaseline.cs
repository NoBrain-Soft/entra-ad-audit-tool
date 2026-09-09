namespace Ipa.Contracts.Baselines;

/// <summary>
/// A Microsoft Security Compliance Toolkit baseline package supplied by the operator.
/// The product never redistributes Microsoft baseline packages: the operator selects a package
/// they already hold, and only its parsed content, identity and hashes are retained.
/// </summary>
public sealed record ImportedBaseline
{
    /// <summary>Identifier assigned on import, stable within an assessment.</summary>
    public required string BaselineId { get; init; }

    /// <summary>File name of the package as selected by the operator.</summary>
    public required string SourceFileName { get; init; }

    /// <summary>SHA-256 of the imported package, recorded in the report and project manifest.</summary>
    public required string PackageSha256 { get; init; }

    /// <summary>Product identity preserved from the package, for example <c>Windows Server 2022</c>.</summary>
    public required string ProductName { get; init; }

    /// <summary>Baseline version preserved from the package, for example <c>Sept 2024</c>.</summary>
    public required string BaselineVersion { get; init; }

    public required DateTimeOffset ImportedAt { get; init; }

    /// <summary>Number of settings parsed from the package.</summary>
    public int SettingCount => Settings.Count;

    public IReadOnlyList<BaselineSetting> Settings { get; init; } = [];

    /// <summary>Per-entry SHA-256 of each parsed file, for integrity verification on reopen.</summary>
    public IReadOnlyDictionary<string, string> EntryHashes { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Notes recorded during import, such as entries skipped as unsupported.</summary>
    public IReadOnlyList<string> ImportNotes { get; init; } = [];
}

/// <summary>Where a baseline setting comes from within the package.</summary>
public enum BaselineSettingKind
{
    /// <summary>A registry value from a <c>registry.pol</c> file.</summary>
    RegistryPolicy,

    /// <summary>A security-template value, for example a password policy or user right.</summary>
    SecurityTemplate,

    /// <summary>An audit policy subcategory setting.</summary>
    AuditPolicy,
}

/// <summary>One expected setting from an imported baseline.</summary>
public sealed record BaselineSetting
{
    /// <summary>Stable key used to compare against collected Group Policy settings.</summary>
    public required string SettingKey { get; init; }

    public required BaselineSettingKind Kind { get; init; }

    /// <summary>Human-readable name shown in the comparison table.</summary>
    public required string DisplayName { get; init; }

    /// <summary>Value the baseline expects.</summary>
    public required string ExpectedValue { get; init; }

    /// <summary>Scope of the setting: <c>Computer</c> or <c>User</c>.</summary>
    public string Scope { get; init; } = "Computer";

    /// <summary>Package-relative path of the file the setting was parsed from.</summary>
    public required string SourceEntry { get; init; }
}

/// <summary>Outcome of comparing one baseline setting with the collected environment.</summary>
public enum BaselineComparisonOutcome
{
    /// <summary>The environment configures the setting to the expected value.</summary>
    Match,

    /// <summary>The environment configures the setting to a different value.</summary>
    Different,

    /// <summary>The environment does not configure the setting at all.</summary>
    NotConfigured,

    /// <summary>The setting could not be compared, for example because SYSVOL was unavailable.</summary>
    NotComparable,
}

/// <summary>One row of the baseline comparison table.</summary>
public sealed record BaselineComparisonRow
{
    public required string SettingKey { get; init; }
    public required string DisplayName { get; init; }
    public required string ExpectedValue { get; init; }
    public string? ObservedValue { get; init; }
    public required BaselineComparisonOutcome Outcome { get; init; }

    /// <summary>GPOs that configure the setting in the assessed environment.</summary>
    public IReadOnlyList<string> ConfiguringPolicies { get; init; } = [];

    public string? Note { get; init; }
}

/// <summary>
/// The result of comparing collected Group Policy against an imported baseline. Baseline
/// conformity is reported as its own metric and never folded into the posture score.
/// </summary>
public sealed record BaselineComparison
{
    public required string BaselineId { get; init; }
    public required string ProductName { get; init; }
    public required string BaselineVersion { get; init; }
    public required string PackageSha256 { get; init; }
    public required DateTimeOffset ComparedAt { get; init; }
    public IReadOnlyList<BaselineComparisonRow> Rows { get; init; } = [];

    public int MatchCount => Rows.Count(row => row.Outcome == BaselineComparisonOutcome.Match);

    public int DifferentCount => Rows.Count(row => row.Outcome == BaselineComparisonOutcome.Different);

    public int NotConfiguredCount => Rows.Count(row => row.Outcome == BaselineComparisonOutcome.NotConfigured);

    public int NotComparableCount => Rows.Count(row => row.Outcome == BaselineComparisonOutcome.NotComparable);

    /// <summary>Comparable rows, that is every row except those that could not be compared.</summary>
    public int ComparableCount => Rows.Count - NotComparableCount;

    /// <summary>
    /// Conformity as a whole percentage of comparable settings. Reported separately from the
    /// posture score to avoid double counting.
    /// </summary>
    public int ConformityPercent => ComparableCount == 0
        ? 0
        : (int)Math.Round(MatchCount * 100d / ComparableCount, MidpointRounding.AwayFromZero);
}
