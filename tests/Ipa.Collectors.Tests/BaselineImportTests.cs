using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Ipa.Collectors.ActiveDirectory.Baselines;
using Ipa.Contracts.Baselines;
using Ipa.Contracts.Evidence;
using Xunit;

namespace Ipa.Collectors.Tests;

/// <summary>
/// Tests for importing an operator-supplied Microsoft security baseline package, including the
/// hostile-archive protections the importer must apply.
/// </summary>
public sealed class BaselineImportTests
{
    private static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static byte[] RegistryPolicyFile(params (string Key, string Value, uint Data)[] records)
    {
        using var stream = new MemoryStream();
        stream.Write("PReg"u8);
        Span<byte> word = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(word, 1);
        stream.Write(word);

        foreach (var (key, value, data) in records)
        {
            WriteChar(stream, '[');
            WriteString(stream, key);
            WriteChar(stream, ';');
            WriteString(stream, value);
            WriteChar(stream, ';');
            WriteUInt32(stream, 4);
            WriteChar(stream, ';');
            WriteUInt32(stream, 4);
            WriteChar(stream, ';');
            WriteUInt32(stream, data);
            WriteChar(stream, ']');
        }

        return stream.ToArray();

        static void WriteChar(Stream target, char value)
        {
            Span<byte> buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
            target.Write(buffer);
        }

        static void WriteString(Stream target, string value)
        {
            target.Write(Encoding.Unicode.GetBytes(value));
            WriteChar(target, '\0');
        }

        static void WriteUInt32(Stream target, uint value)
        {
            Span<byte> buffer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
            target.Write(buffer);
        }
    }

    private static MemoryStream BuildPackage(params (string Path, byte[] Content)[] entries)
    {
        var stream = new MemoryStream();

        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (path, content) in entries)
            {
                var entry = archive.CreateEntry(path, CompressionLevel.NoCompression);
                using var writer = entry.Open();
                writer.Write(content);
            }
        }

        stream.Position = 0;
        return stream;
    }

    [Fact]
    public void ImportsRegistryPolicyAndSecurityTemplateSettings()
    {
        using var package = BuildPackage(
            ("GPOs/{GUID}/DomainSysvol/GPO/Machine/registry.pol",
                RegistryPolicyFile((@"System\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity", 2))),
            ("GPOs/{GUID}/DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
                Encoding.Unicode.GetBytes("[System Access]\nMinimumPasswordLength = 14\n")));

        var baseline = new BaselineImporter().Import(package, "Windows Server 2022 Security Baseline.zip", Reference);

        Assert.Equal(2, baseline.SettingCount);
        Assert.Contains(baseline.Settings, setting => setting.Kind == BaselineSettingKind.RegistryPolicy);
        Assert.Contains(baseline.Settings, setting => setting.Kind == BaselineSettingKind.SecurityTemplate);
        Assert.Equal(64, baseline.PackageSha256.Length);
        Assert.Equal(Reference, baseline.ImportedAt);
    }

    [Fact]
    public void PreservesProductAndVersionIdentityFromTheFileName()
    {
        using var package = BuildPackage(
            ("GPOs/x/Machine/registry.pol", RegistryPolicyFile((@"Software\Test", "Value", 1))));

        var baseline = new BaselineImporter().Import(package, "Windows Server 2022 Security Baseline.zip", Reference);

        Assert.Equal("Windows Server 2022", baseline.ProductName);
    }

    [Fact]
    public void PackageHashIsStableAcrossImports()
    {
        var content = RegistryPolicyFile((@"Software\Test", "Value", 1));

        using var first = BuildPackage(("GPOs/x/Machine/registry.pol", content));
        using var second = new MemoryStream(first.ToArray());

        var a = new BaselineImporter().Import(first, "baseline.zip", Reference);
        var b = new BaselineImporter().Import(second, "baseline.zip", Reference);

        Assert.Equal(a.PackageSha256, b.PackageSha256);
        Assert.Equal(a.EntryHashes.Values, b.EntryHashes.Values);
    }

    [Theory]
    [InlineData("../../etc/passwd")]
    [InlineData("..\\..\\Windows\\System32\\config")]
    [InlineData("/etc/shadow")]
    [InlineData("C:/Windows/System32/registry.pol")]
    [InlineData("//server/share/registry.pol")]
    [InlineData("GPOs/../../escape/registry.pol")]
    public void TraversalPathsAreRejected(string path) =>
        Assert.False(BaselineImporter.IsSafeEntryPath(path));

    [Theory]
    [InlineData("GPOs/{GUID}/Machine/registry.pol")]
    [InlineData("GPOs\\{GUID}\\Machine\\registry.pol")]
    [InlineData("registry.pol")]
    public void OrdinaryPathsAreAccepted(string path) =>
        Assert.True(BaselineImporter.IsSafeEntryPath(path));

    [Fact]
    public void TraversalEntriesAreSkippedAndNoted()
    {
        using var package = BuildPackage(
            ("../../evil/registry.pol", RegistryPolicyFile((@"Software\Evil", "Value", 1))),
            ("GPOs/x/Machine/registry.pol", RegistryPolicyFile((@"Software\Good", "Value", 1))));

        var baseline = new BaselineImporter().Import(package, "baseline.zip", Reference);

        Assert.Single(baseline.Settings);
        Assert.Contains(baseline.Settings, setting => setting.DisplayName.Contains("Good", StringComparison.Ordinal));
        Assert.Contains(baseline.ImportNotes, note => note.Contains("unsafe path", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PackageWithNoRecognisedContentIsNoted()
    {
        using var package = BuildPackage(("Documentation/readme.txt", "nothing here"u8.ToArray()));

        var baseline = new BaselineImporter().Import(package, "baseline.zip", Reference);

        Assert.Empty(baseline.Settings);
        Assert.NotEmpty(baseline.ImportNotes);
    }

    [Fact]
    public void ComparisonReportsMatchesDifferencesAndMissingSettings()
    {
        using var package = BuildPackage(
            ("GPOs/x/Machine/registry.pol", RegistryPolicyFile(
                (@"System\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity", 2),
                (@"System\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 5),
                (@"System\CurrentControlSet\Services\LanManServer\Parameters", "RequireSecuritySignature", 1))));

        var baseline = new BaselineImporter().Import(package, "Windows Server 2022 Security Baseline.zip", Reference);

        var policies = new[]
        {
            new GroupPolicyObject
            {
                Guid = "A", DisplayName = "Domain Controller Hardening", DomainDnsName = "corp.example",
                RegistrySettings =
                [
                    new RegistryPolicySetting
                    {
                        KeyPath = @"System\CurrentControlSet\Services\NTDS\Parameters",
                        ValueName = "LDAPServerIntegrity", ValueType = 4, Value = "2",
                    },
                    new RegistryPolicySetting
                    {
                        KeyPath = @"System\CurrentControlSet\Control\Lsa",
                        ValueName = "LmCompatibilityLevel", ValueType = 4, Value = "3",
                    },
                ],
            },
        };

        var comparison = new BaselineComparer().Compare(baseline, policies, Reference);

        Assert.Equal(3, comparison.Rows.Count);
        Assert.Equal(1, comparison.MatchCount);
        Assert.Equal(1, comparison.DifferentCount);
        Assert.Equal(1, comparison.NotConfiguredCount);
        Assert.Equal(33, comparison.ConformityPercent);
    }

    [Fact]
    public void MissingSysvolMakesSettingsNotComparableRatherThanMissing()
    {
        using var package = BuildPackage(
            ("GPOs/x/Machine/registry.pol", RegistryPolicyFile((@"Software\Test", "Value", 1))));

        var baseline = new BaselineImporter().Import(package, "baseline.zip", Reference);

        var comparison = new BaselineComparer().Compare(baseline, [], Reference, sysvolAvailable: false);

        Assert.All(comparison.Rows, row => Assert.Equal(BaselineComparisonOutcome.NotComparable, row.Outcome));
        Assert.Equal(0, comparison.ComparableCount);
        Assert.Equal(0, comparison.ConformityPercent);
    }

    [Fact]
    public void PrivilegeRightTrusteesCompareAsAnUnorderedSet()
    {
        using var package = BuildPackage(
            ("GPOs/x/Machine/GptTmpl.inf",
                Encoding.Unicode.GetBytes("[Privilege Rights]\nSeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551\n")));

        var baseline = new BaselineImporter().Import(package, "baseline.zip", Reference);

        var policies = new[]
        {
            new GroupPolicyObject
            {
                Guid = "A", DisplayName = "Server Hardening", DomainDnsName = "corp.example",
                SecuritySettings =
                [
                    new SecurityTemplateSetting
                    {
                        Section = "Privilege Rights",
                        Name = "SeBackupPrivilege",
                        // The same trustees in the opposite order.
                        Value = "*S-1-5-32-551,*S-1-5-32-544",
                    },
                ],
            },
        };

        var comparison = new BaselineComparer().Compare(baseline, policies, Reference);

        Assert.Equal(BaselineComparisonOutcome.Match, Assert.Single(comparison.Rows).Outcome);
    }

    [Fact]
    public void AuditPolicySettingsAreReportedAsNotComparable()
    {
        using var package = BuildPackage(
            ("GPOs/x/Machine/audit.csv",
                "Machine Name,Policy Target,Subcategory,Setting Value\n,System,Logon,Success and Failure\n"u8.ToArray()));

        var baseline = new BaselineImporter().Import(package, "baseline.zip", Reference);
        var comparison = new BaselineComparer().Compare(baseline, [], Reference);

        Assert.Equal(BaselineComparisonOutcome.NotComparable, Assert.Single(comparison.Rows).Outcome);
    }
}
