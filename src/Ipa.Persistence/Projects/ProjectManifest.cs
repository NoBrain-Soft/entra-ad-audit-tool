using System.Text.Json.Serialization;

namespace Ipa.Persistence.Projects;

/// <summary>One file inside the container payload, with the hash used to verify it on open.</summary>
public sealed record ManifestEntry
{
    /// <summary>Payload-relative path, always using forward slashes.</summary>
    public required string Path { get; init; }

    /// <summary>Length in bytes before compression.</summary>
    public required long Length { get; init; }

    /// <summary>Lowercase hexadecimal SHA-256 of the entry content.</summary>
    public required string Sha256 { get; init; }
}

/// <summary>
/// The integrity manifest of a saved project. It records everything needed to decide whether a
/// project can be opened by this release, to detect tampering, and to reproduce the scores the
/// project contains.
/// </summary>
public sealed record ProjectManifest
{
    /// <summary>Schema version of the assessment database inside the container.</summary>
    public required int SchemaVersion { get; init; }

    /// <summary>Version of the application that wrote the container.</summary>
    public required string ApplicationVersion { get; init; }

    /// <summary>Rule-pack version the stored results were produced with.</summary>
    public required string RulePackVersion { get; init; }

    /// <summary>Assessment identifier, so a project always refers to one assessment.</summary>
    public required Guid AssessmentId { get; init; }

    /// <summary>When the container was written.</summary>
    public required DateTimeOffset SavedAt { get; init; }

    /// <summary>Hashes of imported baseline packages, keyed by baseline identifier.</summary>
    public IReadOnlyDictionary<string, string> ImportedBaselineHashes { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Product and version identity of each imported baseline, for the report.</summary>
    public IReadOnlyDictionary<string, string> ImportedBaselineIdentities { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>Every file in the payload with its hash.</summary>
    public IReadOnlyList<ManifestEntry> Entries { get; init; } = [];

    /// <summary>SHA-256 of the whole payload archive before encryption.</summary>
    public required string PayloadSha256 { get; init; }

    /// <summary>Free-text label the operator gave the project.</summary>
    public string? Label { get; init; }

    /// <summary>Customer name, duplicated here so a project can be identified without decrypting it.</summary>
    [JsonIgnore]
    public string? CustomerName { get; init; }
}

/// <summary>
/// The plaintext header of a container. It carries only what is needed to derive the key and locate
/// the ciphertext, and it is authenticated as associated data so it cannot be altered undetected.
/// </summary>
public sealed record ContainerHeader
{
    /// <summary>Container format version. Distinct from the database schema version.</summary>
    public required int FormatVersion { get; init; }

    /// <summary>Argon2id salt.</summary>
    public required byte[] Salt { get; init; }

    /// <summary>Argon2id memory cost in kibibytes.</summary>
    public required int MemoryKib { get; init; }

    /// <summary>Argon2id pass count.</summary>
    public required int Iterations { get; init; }

    /// <summary>Argon2id parallelism.</summary>
    public required int Parallelism { get; init; }

    /// <summary>Nonce for the manifest ciphertext.</summary>
    public required byte[] ManifestNonce { get; init; }

    /// <summary>Nonce for the payload ciphertext.</summary>
    public required byte[] PayloadNonce { get; init; }

    /// <summary>Length of the manifest ciphertext, excluding the authentication tag.</summary>
    public required int ManifestLength { get; init; }

    /// <summary>Length of the payload ciphertext, excluding the authentication tag.</summary>
    public required long PayloadLength { get; init; }
}
