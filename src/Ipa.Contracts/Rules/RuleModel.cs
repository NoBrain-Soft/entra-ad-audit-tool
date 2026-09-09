namespace Ipa.Contracts.Rules;

/// <summary>
/// Stable identifier of a rule, for example <c>AD-PRIV-001</c>. Rule identifiers never change:
/// a rule that is retired keeps its identifier and is marked as withdrawn in the pack.
/// </summary>
public readonly record struct RuleId(string Value)
{
    public override string ToString() => Value;

    public static implicit operator string(RuleId id) => id.Value;
}

/// <summary>Severity band. Determines the default (maximum) weight of a rule.</summary>
public enum RuleSeverity
{
    /// <summary>Informational rules carry zero weight and never influence a score.</summary>
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>Outcome of evaluating a rule against normalised evidence.</summary>
public enum RuleStatus
{
    /// <summary>The control is in place. Earns the full rule weight.</summary>
    Pass,

    /// <summary>The control is missing or misconfigured. Earns zero weight.</summary>
    Fail,

    /// <summary>The rule does not apply to this environment. Excluded from the score entirely.</summary>
    NotApplicable,

    /// <summary>
    /// Required evidence was not collected (not selected, denied, or unsupported).
    /// Excluded from the posture denominator; reduces weighted collection coverage.
    /// </summary>
    NotCollected,

    /// <summary>
    /// Evaluation failed unexpectedly. Excluded from the posture denominator;
    /// reduces weighted collection coverage.
    /// </summary>
    Error,
}

/// <summary>Assessment domain a rule belongs to. Drives the per-domain posture scores.</summary>
public enum RuleDomain
{
    ActiveDirectory,
    Entra,
    Hybrid,
}

/// <summary>Default weights per severity band. A rule may reduce, but never exceed, its band weight.</summary>
public static class SeverityWeights
{
    public const int Critical = 10;
    public const int High = 6;
    public const int Medium = 3;
    public const int Low = 1;
    public const int Informational = 0;

    /// <summary>Returns the maximum weight permitted for the supplied severity.</summary>
    public static int Maximum(RuleSeverity severity) => severity switch
    {
        RuleSeverity.Critical => Critical,
        RuleSeverity.High => High,
        RuleSeverity.Medium => Medium,
        RuleSeverity.Low => Low,
        RuleSeverity.Informational => Informational,
        _ => throw new ArgumentOutOfRangeException(nameof(severity), severity, "Unknown severity."),
    };
}

/// <summary>A citation supporting a rule's rationale or remediation guidance.</summary>
public sealed record ReferenceLink(string Title, string Url);

/// <summary>
/// Mapping from a rule to an external framework control. Only control identifiers and
/// tool-authored guidance are stored; no normative framework text is redistributed.
/// </summary>
public sealed record FrameworkMapping
{
    /// <summary>Framework identifier, for example <c>ISO/IEC 27001:2022</c>.</summary>
    public required string Framework { get; init; }

    /// <summary>Control identifier within the framework, for example <c>A.5.15</c>.</summary>
    public required string ControlId { get; init; }

    /// <summary>Tool-authored explanation of why this rule informs the control.</summary>
    public required string Relevance { get; init; }
}

/// <summary>
/// A data set a rule needs before it can be evaluated. When any requirement is unavailable
/// the rule yields <see cref="RuleStatus.NotCollected"/> rather than a pass.
/// </summary>
public sealed record EvidenceRequirement(string EvidenceKey, string Description);

/// <summary>
/// Immutable definition of a best-practice check. Definitions are versioned: changing the
/// evaluation semantics of a rule requires incrementing <see cref="Version"/> so that scores
/// remain reproducible against a recorded rule-pack version.
/// </summary>
public sealed record RuleDefinition
{
    public required RuleId Id { get; init; }

    /// <summary>Monotonic version of the rule's evaluation semantics.</summary>
    public required int Version { get; init; }

    public required string Title { get; init; }

    public required RuleDomain Domain { get; init; }

    public required CheckGroup Group { get; init; }

    public required RuleSeverity Severity { get; init; }

    /// <summary>
    /// Effective weight. Must be between zero and <see cref="SeverityWeights.Maximum"/> for
    /// the rule's severity; informational rules are always zero.
    /// </summary>
    public required int Weight { get; init; }

    /// <summary>Why the finding matters, in the tool's own words.</summary>
    public required string Rationale { get; init; }

    /// <summary>Operator-facing remediation guidance. The product never executes remediation.</summary>
    public required string Remediation { get; init; }

    /// <summary>Conditions under which the rule is applicable at all.</summary>
    public string Applicability { get; init; } = "Applies to every assessed environment of this domain.";

    public IReadOnlyList<ReferenceLink> References { get; init; } = [];

    public IReadOnlyList<EvidenceRequirement> RequiredEvidence { get; init; } = [];

    public IReadOnlyList<FrameworkMapping> FrameworkMappings { get; init; } = [];

    /// <summary>Permissions or protocol access required to collect the rule's evidence.</summary>
    public IReadOnlyList<string> RequiredPermissions { get; init; } = [];

    /// <summary>True when the rule is retired but retained so historical results still resolve.</summary>
    public bool IsWithdrawn { get; init; }

    /// <summary>Validates the invariants a rule pack must satisfy. Throws when violated.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Id.Value))
        {
            throw new InvalidOperationException("Rule identifier must not be empty.");
        }

        if (Version < 1)
        {
            throw new InvalidOperationException($"Rule {Id} must have a version of at least 1.");
        }

        if (Weight < 0)
        {
            throw new InvalidOperationException($"Rule {Id} has a negative weight.");
        }

        var maximum = SeverityWeights.Maximum(Severity);
        if (Weight > maximum)
        {
            throw new InvalidOperationException(
                $"Rule {Id} declares weight {Weight} which exceeds the {Severity} maximum of {maximum}.");
        }

        if (Severity == RuleSeverity.Informational && Weight != 0)
        {
            throw new InvalidOperationException($"Informational rule {Id} must have zero weight.");
        }

        if (string.IsNullOrWhiteSpace(Remediation))
        {
            throw new InvalidOperationException($"Rule {Id} must provide remediation guidance.");
        }
    }
}
