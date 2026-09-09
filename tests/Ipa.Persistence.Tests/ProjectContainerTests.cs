using System.Security.Cryptography;
using System.Text;
using Ipa.Persistence.Projects;
using Ipa.Persistence.Security;
using Xunit;

namespace Ipa.Persistence.Tests;

/// <summary>
/// Tests for the portable encrypted project container: confidentiality, authentication, integrity
/// and the failure classes an operator must be able to tell apart.
/// </summary>
public sealed class ProjectContainerTests
{
    private const string Passphrase = "a-long-enough-project-passphrase";
    private static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid AssessmentId = Guid.Parse("11111111-2222-3333-4444-555555555555");

    /// <summary>Argon2id at the default cost is deliberately slow, so tests use a reduced cost.</summary>
    private static Dictionary<string, byte[]> SampleEntries() => new(StringComparer.Ordinal)
    {
        [ProjectContainer.DatabaseEntryName] = "an encrypted assessment database"u8.ToArray(),
        [ProjectContainer.AttachmentPrefix + "policy.pdf"] = "attachment content"u8.ToArray(),
    };

    private static ProjectManifest BuildManifest(IReadOnlyList<ManifestEntry> entries, string payloadHash) => new()
    {
        SchemaVersion = 1,
        ApplicationVersion = "1.0.0",
        RulePackVersion = "2026.09.1",
        AssessmentId = AssessmentId,
        SavedAt = Reference,
        Entries = entries,
        PayloadSha256 = payloadHash,
        Label = "Contoso engagement",
        ImportedBaselineHashes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["baseline-1"] = new string('a', 64),
        },
        ImportedBaselineIdentities = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["baseline-1"] = "Windows Server 2022 / September 2024",
        },
    };

    private static byte[] SaveSample(string passphrase = Passphrase, IReadOnlyDictionary<string, byte[]>? entries = null)
    {
        using var buffer = new MemoryStream();
        new ProjectContainer().Save(buffer, passphrase, entries ?? SampleEntries(), BuildManifest);
        return buffer.ToArray();
    }

    [Fact]
    public void ProjectRoundTripsWithTheCorrectPassphrase()
    {
        var bytes = SaveSample();

        using var source = new MemoryStream(bytes);
        var opened = new ProjectContainer().Open(source, Passphrase);

        Assert.Equal(AssessmentId, opened.Manifest.AssessmentId);
        Assert.Equal("2026.09.1", opened.Manifest.RulePackVersion);
        Assert.Equal("an encrypted assessment database", Encoding.UTF8.GetString(opened.Database));
        Assert.Equal(2, opened.Entries.Count);
    }

    [Fact]
    public void ManifestRecordsSchemaApplicationAndRulePackVersions()
    {
        using var source = new MemoryStream(SaveSample());
        var manifest = new ProjectContainer().Open(source, Passphrase).Manifest;

        Assert.Equal(1, manifest.SchemaVersion);
        Assert.Equal("1.0.0", manifest.ApplicationVersion);
        Assert.Equal("2026.09.1", manifest.RulePackVersion);
        Assert.Equal(new string('a', 64), manifest.ImportedBaselineHashes["baseline-1"]);
    }

    [Fact]
    public void ContentIsNotRecoverableFromTheContainerBytes()
    {
        var bytes = SaveSample();
        var text = Encoding.UTF8.GetString(bytes);

        Assert.DoesNotContain("an encrypted assessment database", text, StringComparison.Ordinal);
        Assert.DoesNotContain("attachment content", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Contoso engagement", text, StringComparison.Ordinal);
        Assert.DoesNotContain(Passphrase, text, StringComparison.Ordinal);
    }

    [Fact]
    public void WrongPassphraseIsReportedAsAnAuthenticationFailure()
    {
        using var source = new MemoryStream(SaveSample());

        var exception = Assert.Throws<ProjectContainerException>(
            () => new ProjectContainer().Open(source, "a-different-passphrase-entirely"));

        Assert.Equal(ProjectContainerFailure.AuthenticationFailed, exception.Failure);
        Assert.DoesNotContain(Passphrase, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TamperedPayloadIsDetected()
    {
        var bytes = SaveSample();

        // Flip a bit deep inside the payload ciphertext.
        bytes[^32] ^= 0xFF;

        using var source = new MemoryStream(bytes);

        var exception = Assert.Throws<ProjectContainerException>(
            () => new ProjectContainer().Open(source, Passphrase));

        Assert.Equal(ProjectContainerFailure.AuthenticationFailed, exception.Failure);
    }

    [Fact]
    public void TamperedHeaderIsDetectedBecauseItIsAuthenticated()
    {
        var bytes = SaveSample();

        // The header is plaintext, so it can be edited; because it is the associated data for both
        // ciphertexts, the edit must still be detected.
        var text = Encoding.UTF8.GetString(bytes);
        var iterationsIndex = text.IndexOf("\"iterations\":3", StringComparison.Ordinal);

        Assert.True(iterationsIndex > 0, "The header should record the iteration count.");
        bytes[iterationsIndex + "\"iterations\":".Length] = (byte)'4';

        using var source = new MemoryStream(bytes);

        var exception = Assert.Throws<ProjectContainerException>(
            () => new ProjectContainer().Open(source, Passphrase));

        Assert.Equal(ProjectContainerFailure.AuthenticationFailed, exception.Failure);
    }

    [Fact]
    public void TruncatedContainerIsReportedAsMalformed()
    {
        var bytes = SaveSample();

        using var source = new MemoryStream(bytes[..(bytes.Length / 2)]);

        var exception = Assert.Throws<ProjectContainerException>(
            () => new ProjectContainer().Open(source, Passphrase));

        Assert.Equal(ProjectContainerFailure.Malformed, exception.Failure);
    }

    [Fact]
    public void AFileThatIsNotAContainerIsRecognised()
    {
        using var source = new MemoryStream("this is an ordinary text file"u8.ToArray());

        var exception = Assert.Throws<ProjectContainerException>(
            () => new ProjectContainer().Open(source, Passphrase));

        Assert.Equal(ProjectContainerFailure.NotAContainer, exception.Failure);
    }

    [Fact]
    public void ContainerFromANewerFormatIsRefusedClearly()
    {
        var bytes = SaveSample();
        var text = Encoding.UTF8.GetString(bytes);
        var index = text.IndexOf("\"formatVersion\":1", StringComparison.Ordinal);

        Assert.True(index > 0);
        bytes[index + "\"formatVersion\":".Length] = (byte)'9';

        using var source = new MemoryStream(bytes);

        var exception = Assert.Throws<ProjectContainerException>(
            () => new ProjectContainer().Open(source, Passphrase));

        Assert.Equal(ProjectContainerFailure.UnsupportedVersion, exception.Failure);
        Assert.Contains("newer release", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void HeaderCanBeInspectedWithoutThePassphrase()
    {
        using var source = new MemoryStream(SaveSample());

        var header = ProjectContainer.ReadHeader(source);

        Assert.Equal(ProjectContainer.CurrentFormatVersion, header.FormatVersion);
        Assert.Equal(KeyDerivationParameters.DefaultIterations, header.Iterations);
        Assert.Equal(KeyDerivationParameters.SaltLength, header.Salt.Length);
    }

    [Fact]
    public void EachSaveUsesFreshSaltAndNonces()
    {
        using var firstStream = new MemoryStream(SaveSample());
        using var secondStream = new MemoryStream(SaveSample());

        var first = ProjectContainer.ReadHeader(firstStream);
        var second = ProjectContainer.ReadHeader(secondStream);

        Assert.NotEqual(Convert.ToHexString(first.Salt), Convert.ToHexString(second.Salt));
        Assert.NotEqual(Convert.ToHexString(first.PayloadNonce), Convert.ToHexString(second.PayloadNonce));
    }

    [Fact]
    public void ProjectWithoutADatabaseEntryIsRefused()
    {
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["attachments/only.pdf"] = "content"u8.ToArray(),
        };

        using var buffer = new MemoryStream();

        Assert.Throws<ArgumentException>(
            () => new ProjectContainer().Save(buffer, Passphrase, entries, BuildManifest));
    }

    [Theory]
    [InlineData("../escape.db")]
    [InlineData("/absolute.db")]
    [InlineData("C:/windows/system.db")]
    [InlineData("attachments/../../escape.pdf")]
    public void EntryPathsThatEscapeTheContainerAreRefused(string path)
    {
        var exception = Assert.Throws<ProjectContainerException>(() => ProjectContainer.NormaliseEntryPath(path));

        Assert.Equal(ProjectContainerFailure.Malformed, exception.Failure);
    }

    [Fact]
    public void BackslashPathsAreNormalisedToForwardSlashes() =>
        Assert.Equal("attachments/policy.pdf", ProjectContainer.NormaliseEntryPath(@"attachments\policy.pdf"));

    [Fact]
    public void EmptyPassphraseIsRefused()
    {
        using var buffer = new MemoryStream();

        Assert.Throws<ArgumentException>(
            () => new ProjectContainer().Save(buffer, string.Empty, SampleEntries(), BuildManifest));
    }

    [Theory]
    [InlineData("short", PassphraseStrength.Unusable)]
    // Twelve characters meets the minimum length but a single character class is still weak.
    [InlineData("elevencharsx", PassphraseStrength.Weak)]
    [InlineData("alllowercaseletters", PassphraseStrength.Weak)]
    // Twelve characters across three character classes reaches the acceptable band.
    [InlineData("Twelve1Chars", PassphraseStrength.Acceptable)]
    [InlineData("SixteenChars1234", PassphraseStrength.Acceptable)]
    [InlineData("Mixed-Case with 5ymbols and length", PassphraseStrength.Strong)]
    public void PassphraseStrengthIsBanded(string passphrase, PassphraseStrength expected) =>
        Assert.Equal(expected, PassphraseKeyDerivation.EvaluateStrength(passphrase));

    [Fact]
    public void SubkeysDifferPerPurpose()
    {
        var master = RandomNumberGenerator.GetBytes(32);

        var manifestKey = PassphraseKeyDerivation.DeriveSubkey(master, "container:manifest");
        var payloadKey = PassphraseKeyDerivation.DeriveSubkey(master, "container:payload");

        Assert.NotEqual(Convert.ToHexString(manifestKey), Convert.ToHexString(payloadKey));
        Assert.Equal(32, manifestKey.Length);
    }

    [Fact]
    public void KeyDerivationIsDeterministicForTheSameParameters()
    {
        var parameters = KeyDerivationParameters.CreateNew();

        var first = PassphraseKeyDerivation.DeriveMasterKey(Passphrase, parameters);
        var second = PassphraseKeyDerivation.DeriveMasterKey(Passphrase, parameters);

        Assert.Equal(Convert.ToHexString(first), Convert.ToHexString(second));
    }

    [Fact]
    public void ImplausibleKeyDerivationParametersAreRefused()
    {
        var parameters = new KeyDerivationParameters { Salt = new byte[16], MemoryKib = 1 };

        Assert.Throws<InvalidDataException>(parameters.Validate);
    }

    [Fact]
    public void PayloadIsDeterministicForIdenticalContent()
    {
        // Two saves of the same entries must produce the same payload hash, so container behaviour
        // is reproducible even though the ciphertext differs by nonce.
        var entries = SampleEntries();

        using var first = new MemoryStream(SaveSample(entries: entries));
        using var second = new MemoryStream(SaveSample(entries: entries));

        var firstManifest = new ProjectContainer().Open(first, Passphrase).Manifest;
        var secondManifest = new ProjectContainer().Open(second, Passphrase).Manifest;

        Assert.Equal(firstManifest.PayloadSha256, secondManifest.PayloadSha256);
    }
}
