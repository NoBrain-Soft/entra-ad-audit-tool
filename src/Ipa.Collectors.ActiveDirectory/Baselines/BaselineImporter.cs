using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Ipa.Collectors.ActiveDirectory.GroupPolicy;
using Ipa.Contracts.Baselines;

namespace Ipa.Collectors.ActiveDirectory.Baselines;

/// <summary>
/// Imports a Microsoft Security Compliance Toolkit baseline package selected by the operator.
/// </summary>
/// <remarks>
/// The product does not redistribute Microsoft baseline packages: the operator supplies a package
/// they already hold, and only the parsed settings, the package identity and its hashes are kept.
/// The reader is hardened against hostile archives - entry paths are validated against traversal,
/// and both the entry count and the decompressed size are capped.
/// </remarks>
public sealed partial class BaselineImporter
{
    /// <summary>Maximum number of entries the importer will read from an archive.</summary>
    public const int MaxEntries = 20_000;

    /// <summary>Maximum total decompressed bytes the importer will read.</summary>
    public const long MaxTotalUncompressedBytes = 512L * 1024 * 1024;

    /// <summary>Maximum size of a single entry.</summary>
    public const long MaxEntryBytes = 32L * 1024 * 1024;

    /// <summary>Maximum ratio of decompressed to compressed bytes before an entry is refused.</summary>
    public const int MaxCompressionRatio = 200;

    /// <summary>Imports a baseline package from a file path.</summary>
    public ImportedBaseline Import(string packagePath, DateTimeOffset importedAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);

        using var stream = File.OpenRead(packagePath);
        return Import(stream, Path.GetFileName(packagePath), importedAt);
    }

    /// <summary>Imports a baseline package from a stream.</summary>
    /// <param name="package">Seekable stream positioned at the start of the archive.</param>
    /// <param name="fileName">Original file name, preserved for the report.</param>
    /// <param name="importedAt">Import timestamp recorded in the project manifest.</param>
    public ImportedBaseline Import(Stream package, string fileName, DateTimeOffset importedAt)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        if (!package.CanSeek)
        {
            throw new ArgumentException("The baseline package stream must be seekable.", nameof(package));
        }

        package.Position = 0;
        var packageHash = Convert.ToHexString(SHA256.HashData(package)).ToLowerInvariant();
        package.Position = 0;

        var settings = new List<BaselineSetting>();
        var entryHashes = new Dictionary<string, string>(StringComparer.Ordinal);
        var notes = new List<string>();

        using var archive = new ZipArchive(package, ZipArchiveMode.Read, leaveOpen: true);

        if (archive.Entries.Count > MaxEntries)
        {
            throw new InvalidDataException(
                $"The baseline package contains {archive.Entries.Count} entries, above the limit of {MaxEntries}.");
        }

        long totalBytes = 0;

        foreach (var entry in archive.Entries)
        {
            if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\'))
            {
                continue;
            }

            if (!IsSafeEntryPath(entry.FullName))
            {
                notes.Add($"Refused entry with an unsafe path: {Sanitise(entry.FullName)}");
                continue;
            }

            var name = Path.GetFileName(entry.FullName);

            var isRegistryPolicy = name.Equals("registry.pol", StringComparison.OrdinalIgnoreCase);
            var isSecurityTemplate = name.Equals("GptTmpl.inf", StringComparison.OrdinalIgnoreCase);
            var isAuditPolicy = name.Equals("audit.csv", StringComparison.OrdinalIgnoreCase);

            if (!isRegistryPolicy && !isSecurityTemplate && !isAuditPolicy)
            {
                continue;
            }

            if (entry.Length > MaxEntryBytes)
            {
                notes.Add($"Skipped oversized entry {Sanitise(entry.FullName)} ({entry.Length} bytes).");
                continue;
            }

            if (entry.CompressedLength > 0 && entry.Length / Math.Max(entry.CompressedLength, 1) > MaxCompressionRatio)
            {
                notes.Add($"Skipped entry {Sanitise(entry.FullName)}: implausible compression ratio.");
                continue;
            }

            totalBytes += entry.Length;
            if (totalBytes > MaxTotalUncompressedBytes)
            {
                throw new InvalidDataException(
                    "The baseline package expands beyond the permitted total size and was not fully imported.");
            }

            var content = ReadEntry(entry);
            entryHashes[entry.FullName] = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

            if (isRegistryPolicy)
            {
                var scope = entry.FullName.Contains("/User/", StringComparison.OrdinalIgnoreCase)
                            || entry.FullName.Contains("\\User\\", StringComparison.OrdinalIgnoreCase)
                    ? "User"
                    : "Computer";

                var parsed = RegistryPolicyParser.Parse(content, scope == "Computer");
                notes.AddRange(parsed.Notes.Select(note => $"{Sanitise(entry.FullName)}: {note}"));

                settings.AddRange(parsed.Settings.Select(setting => new BaselineSetting
                {
                    SettingKey = BuildRegistryKey(setting.KeyPath, setting.ValueName),
                    Kind = BaselineSettingKind.RegistryPolicy,
                    DisplayName = $"{setting.KeyPath}\\{setting.ValueName}",
                    ExpectedValue = setting.Value,
                    Scope = scope,
                    SourceEntry = entry.FullName,
                }));
            }
            else if (isSecurityTemplate)
            {
                var parsed = SecurityTemplateParser.Parse(content);
                notes.AddRange(parsed.Notes.Select(note => $"{Sanitise(entry.FullName)}: {note}"));

                settings.AddRange(parsed.Settings.Select(setting => new BaselineSetting
                {
                    SettingKey = BuildTemplateKey(setting.Section, setting.Name),
                    Kind = BaselineSettingKind.SecurityTemplate,
                    DisplayName = $"{setting.Section}: {setting.Name}",
                    ExpectedValue = setting.Value,
                    Scope = "Computer",
                    SourceEntry = entry.FullName,
                }));
            }
            else
            {
                settings.AddRange(ParseAuditPolicy(content, entry.FullName, notes));
            }
        }

        var (product, version) = InferIdentity(fileName, archive);

        // The same setting can appear in several policy folders of one package; the last
        // occurrence wins, matching how Group Policy resolves duplicate values.
        var deduplicated = settings
            .GroupBy(setting => setting.SettingKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.Last())
            .OrderBy(setting => setting.SettingKey, StringComparer.Ordinal)
            .ToList();

        if (deduplicated.Count == 0)
        {
            notes.Add("No registry policy, security template or audit policy content was found in the package.");
        }

        return new ImportedBaseline
        {
            BaselineId = Guid.NewGuid().ToString("n"),
            SourceFileName = fileName,
            PackageSha256 = packageHash,
            ProductName = product,
            BaselineVersion = version,
            ImportedAt = importedAt,
            Settings = deduplicated,
            EntryHashes = entryHashes,
            ImportNotes = notes,
        };
    }

    /// <summary>Canonical comparison key for a registry policy value.</summary>
    public static string BuildRegistryKey(string keyPath, string valueName) =>
        $"registry::{keyPath.Replace('/', '\\').Trim('\\')}\\{valueName}".ToLowerInvariant();

    /// <summary>Canonical comparison key for a security template value.</summary>
    public static string BuildTemplateKey(string section, string name) =>
        $"template::{section}::{name}".ToLowerInvariant();

    /// <summary>Canonical comparison key for an audit policy subcategory.</summary>
    public static string BuildAuditKey(string subcategory) =>
        $"audit::{subcategory}".ToLowerInvariant();

    /// <summary>
    /// Rejects archive entry paths that are absolute, that traverse upwards, or that carry a
    /// drive or device qualifier. Nothing is written to disk during import, but a hostile path is
    /// still refused so that it can never reach a later extraction step.
    /// </summary>
    public static bool IsSafeEntryPath(string entryPath)
    {
        if (string.IsNullOrWhiteSpace(entryPath))
        {
            return false;
        }

        if (entryPath.Contains('\0'))
        {
            return false;
        }

        var normalised = entryPath.Replace('\\', '/');

        if (normalised.StartsWith('/') || normalised.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }

        if (normalised.Length >= 2 && char.IsLetter(normalised[0]) && normalised[1] == ':')
        {
            return false;
        }

        return normalised
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .All(segment => segment != ".." && segment != ".");
    }

    private static byte[] ReadEntry(ZipArchiveEntry entry)
    {
        using var entryStream = entry.Open();
        using var buffer = new MemoryStream();

        var limited = new byte[81920];
        long total = 0;
        int read;

        while ((read = entryStream.Read(limited, 0, limited.Length)) > 0)
        {
            total += read;
            if (total > MaxEntryBytes)
            {
                throw new InvalidDataException(
                    $"Entry {Sanitise(entry.FullName)} expanded beyond the permitted entry size.");
            }

            buffer.Write(limited, 0, read);
        }

        return buffer.ToArray();
    }

    private static IEnumerable<BaselineSetting> ParseAuditPolicy(
        byte[] content,
        string entryPath,
        List<string> notes)
    {
        var text = System.Text.Encoding.UTF8.GetString(content);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        if (lines.Length <= 1)
        {
            yield break;
        }

        var header = lines[0].Split(',');
        var subcategoryIndex = Array.FindIndex(header, column =>
            column.Trim().Equals("Subcategory", StringComparison.OrdinalIgnoreCase));
        var settingIndex = Array.FindIndex(header, column =>
            column.Trim().Equals("Setting Value", StringComparison.OrdinalIgnoreCase)
            || column.Trim().Equals("Inclusion Setting", StringComparison.OrdinalIgnoreCase));

        if (subcategoryIndex < 0 || settingIndex < 0)
        {
            notes.Add($"{Sanitise(entryPath)}: the audit policy header was not recognised.");
            yield break;
        }

        foreach (var line in lines.Skip(1))
        {
            var columns = line.Split(',');
            if (columns.Length <= Math.Max(subcategoryIndex, settingIndex))
            {
                continue;
            }

            var subcategory = columns[subcategoryIndex].Trim().Trim('"');
            var value = columns[settingIndex].Trim().Trim('"', '\r');

            if (subcategory.Length == 0)
            {
                continue;
            }

            yield return new BaselineSetting
            {
                SettingKey = BuildAuditKey(subcategory),
                Kind = BaselineSettingKind.AuditPolicy,
                DisplayName = $"Audit policy: {subcategory}",
                ExpectedValue = value,
                Scope = "Computer",
                SourceEntry = entryPath,
            };
        }
    }

    /// <summary>
    /// Recovers the product and version identity of the package. The Security Compliance Toolkit
    /// names its downloads after the product and release, for example
    /// <c>Windows Server 2022 Security Baseline.zip</c>, so the file name is the primary source and
    /// the archive's own folder names are the fallback.
    /// </summary>
    private static (string Product, string Version) InferIdentity(string fileName, ZipArchive archive)
    {
        var stem = Path.GetFileNameWithoutExtension(fileName);
        var match = PackageNamePattern().Match(stem);

        if (match.Success)
        {
            var product = match.Groups["product"].Value.Trim();
            var version = match.Groups["version"].Value.Trim();

            if (product.Length > 0)
            {
                return (product, version.Length > 0 ? version : "unspecified");
            }
        }

        var topLevel = archive.Entries
            .Select(entry => entry.FullName.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries))
            .Where(segments => segments.Length > 1)
            .Select(segments => segments[0])
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();

        return (topLevel ?? stem, "unspecified");
    }

    /// <summary>Removes control characters from an archive path before it reaches a log or report.</summary>
    private static string Sanitise(string value) =>
        new(value.Where(character => !char.IsControl(character)).Take(260).ToArray());

    [GeneratedRegex(
        @"^(?<product>.*?)(?:\s+Security\s+Baseline)?(?:\s+(?<version>v?\d[\w.\-]*|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s*\d{4}))?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PackageNamePattern();
}
