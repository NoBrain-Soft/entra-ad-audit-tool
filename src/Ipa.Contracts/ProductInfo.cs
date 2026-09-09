namespace Ipa.Contracts;

/// <summary>
/// Central product identity. Every user-visible name, folder name and report string is
/// resolved from here so that the application can be re-branded for a release without
/// touching feature code.
/// </summary>
public static class ProductInfo
{
    /// <summary>Working product name. Change here to re-skin the whole application.</summary>
    public const string Name = "Identity Posture Assessor";

    /// <summary>Short name used for file names, directories and container extensions.</summary>
    public const string ShortName = "IdentityPostureAssessor";

    /// <summary>Vendor shown in reports, installers and about screens.</summary>
    public const string Vendor = "NoBrain Software";

    /// <summary>Application version. Recorded in every saved project and report.</summary>
    public const string Version = "1.0.0";

    /// <summary>Extension of the explicitly saved, encrypted project container.</summary>
    public const string ProjectFileExtension = ".ipaproj";

    /// <summary>Marketing-neutral descriptor used on report cover pages.</summary>
    public const string Descriptor = "Active Directory and Microsoft Entra ID posture assessment";

    /// <summary>
    /// Mandatory qualifier for all ISO/IEC 27001 output. The product performs a readiness
    /// assessment only; it is not a certification body and issues no audit opinion.
    /// </summary>
    public const string IsoReadinessDisclaimer =
        "Readiness assessment - not a certification or audit opinion.";

    /// <summary>Directory name used under the OS temporary path for ephemeral session state.</summary>
    public const string EphemeralDirectoryName = "IdentityPostureAssessor.Session";
}
