using System.Xml;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.GroupPolicy;

/// <summary>
/// Detects stored credentials in Group Policy Preferences files. Only the location and the
/// affected account are recorded: the obfuscated value itself is never read into the evidence
/// model, never logged and never written to a report.
/// </summary>
public static class PreferenceCredentialScanner
{
    /// <summary>Preference files known to carry a <c>cpassword</c> attribute.</summary>
    public static IReadOnlyList<string> CandidateFileNames { get; } =
    [
        "Groups.xml", "Services.xml", "ScheduledTasks.xml", "DataSources.xml",
        "Printers.xml", "Drives.xml",
    ];

    /// <summary>Largest preference file the scanner will read.</summary>
    public const int MaxFileBytes = 4 * 1024 * 1024;

    /// <summary>
    /// Scans one preference file. Returns an artefact for every element that carries a stored
    /// credential, or an empty list when the file is clean or cannot be parsed as XML.
    /// </summary>
    /// <param name="relativePath">SYSVOL-relative path, recorded in the finding.</param>
    /// <param name="content">Raw file bytes.</param>
    public static IReadOnlyList<GpoPreferencePasswordArtifact> Scan(string relativePath, ReadOnlySpan<byte> content)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);

        if (content.Length is 0 or > MaxFileBytes)
        {
            return [];
        }

        var artifacts = new List<GpoPreferencePasswordArtifact>();

        try
        {
            var settings = new XmlReaderSettings
            {
                // External entity resolution stays disabled: preference files are untrusted input
                // read from a share that many principals can write to.
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreComments = true,
                IgnoreWhitespace = true,
                CloseInput = true,
            };

            using var stream = new MemoryStream(content.ToArray(), writable: false);
            using var reader = XmlReader.Create(stream, settings);

            var elementPath = new Stack<string>();

            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.EndElement)
                {
                    if (elementPath.Count > 0)
                    {
                        elementPath.Pop();
                    }

                    continue;
                }

                if (reader.NodeType != XmlNodeType.Element)
                {
                    continue;
                }

                var isEmpty = reader.IsEmptyElement;
                elementPath.Push(reader.Name);

                var cpassword = reader.GetAttribute("cpassword");
                if (!string.IsNullOrEmpty(cpassword))
                {
                    artifacts.Add(new GpoPreferencePasswordArtifact
                    {
                        RelativePath = relativePath,
                        Element = string.Join('/', elementPath.Reverse()),
                        AccountName = reader.GetAttribute("userName")
                                      ?? reader.GetAttribute("accountName")
                                      ?? reader.GetAttribute("runAs"),
                    });
                }

                if (isEmpty)
                {
                    elementPath.Pop();
                }
            }
        }
        catch (XmlException)
        {
            // A preference file that is not well-formed XML carries no recoverable credential
            // information; the collector records a diagnostic separately.
            return [];
        }

        return artifacts;
    }
}
