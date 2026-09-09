namespace Ipa.Contracts.Reporting;

/// <summary>A selectable section of the generated report.</summary>
public enum ReportSection
{
    Cover,
    ScopeAndMethodology,
    ExecutiveSummary,
    ScoreAndCoverage,
    PrioritisedFindings,
    ActiveDirectoryDetail,
    EntraDetail,
    HybridDetail,
    BaselineComparison,
    IsoReadiness,
    Exclusions,
    CollectionDiagnostics,
    RemediationRoadmap,
    EvidenceAppendix,
}

/// <summary>White-label branding applied to the generated report.</summary>
public sealed record BrandingProfile
{
    public string? CustomerName { get; init; }
    public string? AssessorName { get; init; }
    public string? AssessorCompany { get; init; }

    /// <summary>Logo bytes, embedded as a data URI. Never fetched from the network at render time.</summary>
    public byte[]? LogoBytes { get; init; }

    /// <summary>MIME type of <see cref="LogoBytes"/>, for example <c>image/png</c>.</summary>
    public string? LogoMediaType { get; init; }

    /// <summary>Primary accent colour as a CSS hex value.</summary>
    public string PrimaryColor { get; init; } = "#1f3a5f";

    /// <summary>Secondary accent colour as a CSS hex value.</summary>
    public string SecondaryColor { get; init; } = "#4b7bb5";

    /// <summary>Confidentiality label repeated in the page footer.</summary>
    public string ConfidentialityLabel { get; init; } = "Confidential";

    public string? ProductNameOverride { get; init; }

    /// <summary>Effective product name, honouring the white-label override.</summary>
    public string EffectiveProductName =>
        string.IsNullOrWhiteSpace(ProductNameOverride) ? ProductInfo.Name : ProductNameOverride;
}

/// <summary>
/// Everything that shapes one generated report: branding, section selection and the explicit
/// choices an operator must make before sensitive content is included.
/// </summary>
public sealed record ReportProfile
{
    public required string ProfileId { get; init; }
    public required string Name { get; init; }

    public BrandingProfile Branding { get; init; } = new();

    public IReadOnlyCollection<ReportSection> Sections { get; init; } =
        Enum.GetValues<ReportSection>();

    public DateTimeOffset? AssessmentStartDate { get; init; }
    public DateTimeOffset? AssessmentEndDate { get; init; }
    public string ReportVersion { get; init; } = "1.0";

    /// <summary>Operator-authored executive narrative inserted into the summary section.</summary>
    public string? ExecutiveNarrative { get; init; }

    /// <summary>Sign-off names printed on the cover page.</summary>
    public IReadOnlyList<string> SignOffNames { get; init; } = [];

    /// <summary>
    /// Include raw object attributes and membership lists. Off by default: enabling it triggers
    /// a privacy warning in the user interface before the report is generated.
    /// </summary>
    public bool IncludeRawObjectAttributes { get; init; }

    /// <summary>Include full affected-object lists rather than a capped sample.</summary>
    public bool IncludeFullAffectedObjectLists { get; init; }

    /// <summary>Include operator attachments in the evidence appendix.</summary>
    public bool IncludeAttachments { get; init; }

    /// <summary>Maximum affected objects listed per finding when full lists are not requested.</summary>
    public int AffectedObjectSampleSize { get; init; } = 10;

    public bool HasSection(ReportSection section) => Sections.Contains(section);

    /// <summary>True when the profile would place sensitive material into the exported PDF.</summary>
    public bool RequiresPrivacyWarning =>
        IncludeRawObjectAttributes || IncludeFullAffectedObjectLists || IncludeAttachments;
}
