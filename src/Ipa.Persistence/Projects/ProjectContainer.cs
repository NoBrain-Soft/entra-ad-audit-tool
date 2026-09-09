using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ipa.Persistence.Security;

namespace Ipa.Persistence.Projects;

/// <summary>Raised when a container cannot be opened. The message never reveals key material.</summary>
public sealed class ProjectContainerException : Exception
{
    public ProjectContainerException(string message, ProjectContainerFailure failure, Exception? inner = null)
        : base(message, inner) => Failure = failure;

    /// <summary>Why the container could not be opened, so the interface can respond appropriately.</summary>
    public ProjectContainerFailure Failure { get; }
}

/// <summary>Categories of container failure the user interface distinguishes.</summary>
public enum ProjectContainerFailure
{
    /// <summary>The file is not a project container at all.</summary>
    NotAContainer,

    /// <summary>The container was written by a newer release.</summary>
    UnsupportedVersion,

    /// <summary>The passphrase is wrong, or the file has been altered.</summary>
    AuthenticationFailed,

    /// <summary>The container decrypted but its contents do not match the manifest.</summary>
    IntegrityFailed,

    /// <summary>The file is truncated or otherwise malformed.</summary>
    Malformed,
}

/// <summary>The content of an opened project.</summary>
public sealed record OpenedProject
{
    /// <summary>The verified manifest.</summary>
    public required ProjectManifest Manifest { get; init; }

    /// <summary>Payload entries, keyed by their payload-relative path.</summary>
    public required IReadOnlyDictionary<string, byte[]> Entries { get; init; }

    /// <summary>The assessment database bytes.</summary>
    public byte[] Database => Entries.TryGetValue(ProjectContainer.DatabaseEntryName, out var bytes)
        ? bytes
        : throw new ProjectContainerException(
            "The container holds no assessment database.",
            ProjectContainerFailure.IntegrityFailed);
}

/// <summary>
/// Reads and writes the portable encrypted project container.
/// </summary>
/// <remarks>
/// Layout: an eight-byte magic value, a length-prefixed plaintext header carrying the format
/// version, the Argon2id parameters and the two nonces, then the AES-256-GCM manifest ciphertext
/// and the AES-256-GCM payload ciphertext. The header is authenticated as associated data for both
/// ciphertexts, so altering the declared parameters is detected. The manifest additionally records
/// a hash for every payload entry, which is verified after decryption, so a substitution inside a
/// correctly authenticated payload is still caught.
///
/// The passphrase is never written to the container, and the derived keys are wiped from memory
/// once the operation completes.
/// </remarks>
public sealed class ProjectContainer
{
    /// <summary>File magic identifying a container.</summary>
    public static ReadOnlySpan<byte> Magic => "IPAPROJ\0"u8;

    /// <summary>Current container format version.</summary>
    public const int CurrentFormatVersion = 1;

    /// <summary>Payload entry holding the assessment database.</summary>
    public const string DatabaseEntryName = "assessment.db";

    /// <summary>Prefix used for evidence attachment entries.</summary>
    public const string AttachmentPrefix = "attachments/";

    /// <summary>Maximum container size the reader will accept.</summary>
    public const long MaxContainerBytes = 4L * 1024 * 1024 * 1024;

    /// <summary>Maximum payload size after decompression.</summary>
    public const long MaxPayloadBytes = 8L * 1024 * 1024 * 1024;

    private const int NonceLength = 12;
    private const int TagLength = 16;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };

    /// <summary>Writes a project container to the supplied stream.</summary>
    /// <param name="destination">Writable stream that receives the container.</param>
    /// <param name="passphrase">Operator passphrase. Never stored.</param>
    /// <param name="entries">Payload entries, keyed by payload-relative path.</param>
    /// <param name="manifestFactory">
    /// Builds the manifest once the payload hashes are known, so the manifest always describes what
    /// was actually written.
    /// </param>
    public void Save(
        Stream destination,
        ReadOnlySpan<char> passphrase,
        IReadOnlyDictionary<string, byte[]> entries,
        Func<IReadOnlyList<ManifestEntry>, string, ProjectManifest> manifestFactory)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(manifestFactory);

        if (!entries.ContainsKey(DatabaseEntryName))
        {
            throw new ArgumentException(
                $"A project must contain the '{DatabaseEntryName}' entry.",
                nameof(entries));
        }

        var payload = BuildPayload(entries, out var manifestEntries);
        var payloadHash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        var manifest = manifestFactory(manifestEntries, payloadHash);

        var parameters = KeyDerivationParameters.CreateNew();
        var manifestNonce = RandomNumberGenerator.GetBytes(NonceLength);
        var payloadNonce = RandomNumberGenerator.GetBytes(NonceLength);
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);

        var header = new ContainerHeader
        {
            FormatVersion = CurrentFormatVersion,
            Salt = parameters.Salt,
            MemoryKib = parameters.MemoryKib,
            Iterations = parameters.Iterations,
            Parallelism = parameters.Parallelism,
            ManifestNonce = manifestNonce,
            PayloadNonce = payloadNonce,
            ManifestLength = manifestBytes.Length,
            PayloadLength = payload.Length,
        };

        var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header, JsonOptions);

        var masterKey = PassphraseKeyDerivation.DeriveMasterKey(passphrase, parameters);
        byte[]? manifestKey = null;
        byte[]? payloadKey = null;

        try
        {
            manifestKey = PassphraseKeyDerivation.DeriveSubkey(masterKey, "container:manifest");
            payloadKey = PassphraseKeyDerivation.DeriveSubkey(masterKey, "container:payload");

            var manifestCipher = new byte[manifestBytes.Length];
            var manifestTag = new byte[TagLength];

            using (var aes = new AesGcm(manifestKey, TagLength))
            {
                aes.Encrypt(manifestNonce, manifestBytes, manifestCipher, manifestTag, headerBytes);
            }

            var payloadCipher = new byte[payload.Length];
            var payloadTag = new byte[TagLength];

            using (var aes = new AesGcm(payloadKey, TagLength))
            {
                aes.Encrypt(payloadNonce, payload, payloadCipher, payloadTag, headerBytes);
            }

            destination.Write(Magic);
            WriteInt32(destination, headerBytes.Length);
            destination.Write(headerBytes);
            destination.Write(manifestCipher);
            destination.Write(manifestTag);
            destination.Write(payloadCipher);
            destination.Write(payloadTag);
            destination.Flush();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);

            if (manifestKey is not null)
            {
                CryptographicOperations.ZeroMemory(manifestKey);
            }

            if (payloadKey is not null)
            {
                CryptographicOperations.ZeroMemory(payloadKey);
            }

            CryptographicOperations.ZeroMemory(payload);
        }
    }

    /// <summary>Opens a container, verifying its authentication tags and its integrity manifest.</summary>
    public OpenedProject Open(Stream source, ReadOnlySpan<char> passphrase)
    {
        ArgumentNullException.ThrowIfNull(source);

        var container = ReadFully(source);

        if (container.Length < Magic.Length + 4 || !container.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new ProjectContainerException(
                "The file is not a project container.",
                ProjectContainerFailure.NotAContainer);
        }

        var offset = Magic.Length;
        var headerLength = BinaryPrimitives.ReadInt32LittleEndian(container.AsSpan(offset));
        offset += 4;

        if (headerLength is <= 0 or > 64 * 1024 || offset + headerLength > container.Length)
        {
            throw new ProjectContainerException(
                "The container header is malformed.",
                ProjectContainerFailure.Malformed);
        }

        var headerBytes = container.AsSpan(offset, headerLength).ToArray();
        offset += headerLength;

        ContainerHeader header;

        try
        {
            header = JsonSerializer.Deserialize<ContainerHeader>(headerBytes, JsonOptions)
                     ?? throw new ProjectContainerException(
                         "The container header is empty.",
                         ProjectContainerFailure.Malformed);
        }
        catch (JsonException ex)
        {
            throw new ProjectContainerException(
                "The container header could not be read.",
                ProjectContainerFailure.Malformed,
                ex);
        }

        if (header.FormatVersion > CurrentFormatVersion)
        {
            throw new ProjectContainerException(
                $"The project was saved by a newer release (container format {header.FormatVersion}). " +
                "Open it with that release, or upgrade this installation.",
                ProjectContainerFailure.UnsupportedVersion);
        }

        var parameters = new KeyDerivationParameters
        {
            Salt = header.Salt,
            MemoryKib = header.MemoryKib,
            Iterations = header.Iterations,
            Parallelism = header.Parallelism,
        };

        try
        {
            parameters.Validate();
        }
        catch (InvalidDataException ex)
        {
            throw new ProjectContainerException(ex.Message, ProjectContainerFailure.Malformed, ex);
        }

        if (header.ManifestLength < 0
            || header.PayloadLength < 0
            || header.PayloadLength > MaxPayloadBytes
            || offset + header.ManifestLength + TagLength + header.PayloadLength + TagLength > container.Length)
        {
            throw new ProjectContainerException(
                "The container is truncated.",
                ProjectContainerFailure.Malformed);
        }

        var manifestCipher = container.AsSpan(offset, header.ManifestLength).ToArray();
        offset += header.ManifestLength;
        var manifestTag = container.AsSpan(offset, TagLength).ToArray();
        offset += TagLength;

        var payloadCipher = container.AsSpan(offset, (int)header.PayloadLength).ToArray();
        offset += (int)header.PayloadLength;
        var payloadTag = container.AsSpan(offset, TagLength).ToArray();

        var masterKey = PassphraseKeyDerivation.DeriveMasterKey(passphrase, parameters);
        byte[]? manifestKey = null;
        byte[]? payloadKey = null;
        byte[]? payload = null;

        try
        {
            manifestKey = PassphraseKeyDerivation.DeriveSubkey(masterKey, "container:manifest");
            payloadKey = PassphraseKeyDerivation.DeriveSubkey(masterKey, "container:payload");

            var manifestBytes = new byte[header.ManifestLength];
            payload = new byte[header.PayloadLength];

            try
            {
                using (var aes = new AesGcm(manifestKey, TagLength))
                {
                    aes.Decrypt(header.ManifestNonce, manifestCipher, manifestTag, manifestBytes, headerBytes);
                }

                using (var aes = new AesGcm(payloadKey, TagLength))
                {
                    aes.Decrypt(header.PayloadNonce, payloadCipher, payloadTag, payload, headerBytes);
                }
            }
            catch (CryptographicException ex)
            {
                throw new ProjectContainerException(
                    "The project could not be opened. The passphrase is incorrect, or the file has " +
                    "been altered since it was saved.",
                    ProjectContainerFailure.AuthenticationFailed,
                    ex);
            }

            var manifest = JsonSerializer.Deserialize<ProjectManifest>(manifestBytes, JsonOptions)
                           ?? throw new ProjectContainerException(
                               "The project manifest is empty.",
                               ProjectContainerFailure.IntegrityFailed);

            var actualPayloadHash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(actualPayloadHash),
                    Encoding.ASCII.GetBytes(manifest.PayloadSha256)))
            {
                throw new ProjectContainerException(
                    "The project payload does not match the hash recorded in its manifest.",
                    ProjectContainerFailure.IntegrityFailed);
            }

            var entries = ExtractPayload(payload);
            VerifyEntries(manifest, entries);

            return new OpenedProject { Manifest = manifest, Entries = entries };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);

            if (manifestKey is not null)
            {
                CryptographicOperations.ZeroMemory(manifestKey);
            }

            if (payloadKey is not null)
            {
                CryptographicOperations.ZeroMemory(payloadKey);
            }

            if (payload is not null)
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
    }

    /// <summary>Reads only the plaintext header, for showing container details before unlocking.</summary>
    public static ContainerHeader ReadHeader(Stream source)
    {
        ArgumentNullException.ThrowIfNull(source);

        Span<byte> prefix = stackalloc byte[Magic.Length + 4];
        source.ReadExactly(prefix);

        if (!prefix[..Magic.Length].SequenceEqual(Magic))
        {
            throw new ProjectContainerException(
                "The file is not a project container.",
                ProjectContainerFailure.NotAContainer);
        }

        var headerLength = BinaryPrimitives.ReadInt32LittleEndian(prefix[Magic.Length..]);

        if (headerLength is <= 0 or > 64 * 1024)
        {
            throw new ProjectContainerException(
                "The container header is malformed.",
                ProjectContainerFailure.Malformed);
        }

        var headerBytes = new byte[headerLength];
        source.ReadExactly(headerBytes);

        return JsonSerializer.Deserialize<ContainerHeader>(headerBytes, JsonOptions)
               ?? throw new ProjectContainerException(
                   "The container header is empty.",
                   ProjectContainerFailure.Malformed);
    }

    private static byte[] BuildPayload(
        IReadOnlyDictionary<string, byte[]> entries,
        out IReadOnlyList<ManifestEntry> manifestEntries)
    {
        var manifest = new List<ManifestEntry>(entries.Count);
        using var buffer = new MemoryStream();

        // Entries are written in a stable order so that the payload of two saves of identical
        // content is byte identical, which makes container behaviour reproducible.
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (path, content) in entries.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                var normalised = NormaliseEntryPath(path);
                var entry = archive.CreateEntry(normalised, CompressionLevel.SmallestSize);

                // A fixed timestamp keeps the archive deterministic.
                entry.LastWriteTime = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

                using var writer = entry.Open();
                writer.Write(content);

                manifest.Add(new ManifestEntry
                {
                    Path = normalised,
                    Length = content.Length,
                    Sha256 = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(),
                });
            }
        }

        manifestEntries = manifest;
        return buffer.ToArray();
    }

    private static Dictionary<string, byte[]> ExtractPayload(byte[] payload)
    {
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        using var buffer = new MemoryStream(payload, writable: false);
        using var archive = new ZipArchive(buffer, ZipArchiveMode.Read);

        long total = 0;

        foreach (var entry in archive.Entries)
        {
            if (entry.FullName.EndsWith('/'))
            {
                continue;
            }

            var path = NormaliseEntryPath(entry.FullName);

            total += entry.Length;
            if (total > MaxPayloadBytes)
            {
                throw new ProjectContainerException(
                    "The project payload expands beyond the permitted size.",
                    ProjectContainerFailure.Malformed);
            }

            using var stream = entry.Open();
            using var content = new MemoryStream();
            stream.CopyTo(content);

            entries[path] = content.ToArray();
        }

        return entries;
    }

    private static void VerifyEntries(ProjectManifest manifest, IReadOnlyDictionary<string, byte[]> entries)
    {
        foreach (var declared in manifest.Entries)
        {
            if (!entries.TryGetValue(declared.Path, out var content))
            {
                throw new ProjectContainerException(
                    $"The project manifest lists '{declared.Path}', which is not present in the payload.",
                    ProjectContainerFailure.IntegrityFailed);
            }

            var actual = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(actual),
                    Encoding.ASCII.GetBytes(declared.Sha256)))
            {
                throw new ProjectContainerException(
                    $"The content of '{declared.Path}' does not match the hash in the manifest.",
                    ProjectContainerFailure.IntegrityFailed);
            }
        }

        var undeclared = entries.Keys
            .Except(manifest.Entries.Select(entry => entry.Path), StringComparer.Ordinal)
            .ToList();

        if (undeclared.Count > 0)
        {
            throw new ProjectContainerException(
                $"The payload contains {undeclared.Count} entr(ies) that the manifest does not declare.",
                ProjectContainerFailure.IntegrityFailed);
        }
    }

    /// <summary>
    /// Normalises a payload path and refuses anything that could escape a directory when the
    /// operator later exports attachments to disk.
    /// </summary>
    public static string NormaliseEntryPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var value = path.Replace('\\', '/');

        // An absolute path, a drive qualifier or a traversal segment is refused outright rather
        // than normalised away: inside a container each is anomalous, and silently rewriting one
        // would hide the anomaly from the operator.
        if (value.Contains('\0')
            || value.StartsWith('/')
            || value.Split('/').Any(segment => segment is ".." or ".")
            || (value.Length >= 2 && char.IsLetter(value[0]) && value[1] == ':'))
        {
            throw new ProjectContainerException(
                "A project entry path is not permitted.",
                ProjectContainerFailure.Malformed);
        }

        return value;
    }

    private static void WriteInt32(Stream stream, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    private static byte[] ReadFully(Stream source)
    {
        if (source.CanSeek && source.Length > MaxContainerBytes)
        {
            throw new ProjectContainerException(
                "The container exceeds the maximum supported size.",
                ProjectContainerFailure.Malformed);
        }

        using var buffer = new MemoryStream();
        source.CopyTo(buffer);
        return buffer.ToArray();
    }
}
