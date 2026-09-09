using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Ipa.Persistence.Security;

/// <summary>
/// Argon2id parameters recorded in a container so that a project saved by one release can still be
/// opened by another. Parameters are stored with the file rather than assumed, which is what lets
/// the cost be raised in a future release without breaking existing projects.
/// </summary>
public sealed record KeyDerivationParameters
{
    /// <summary>Random salt. Unique per container.</summary>
    public required byte[] Salt { get; init; }

    /// <summary>Memory cost in kibibytes.</summary>
    public int MemoryKib { get; init; } = DefaultMemoryKib;

    /// <summary>Number of passes over memory.</summary>
    public int Iterations { get; init; } = DefaultIterations;

    /// <summary>Degree of parallelism.</summary>
    public int Parallelism { get; init; } = DefaultParallelism;

    /// <summary>Default memory cost: 64 mebibytes.</summary>
    public const int DefaultMemoryKib = 64 * 1024;

    /// <summary>Default pass count.</summary>
    public const int DefaultIterations = 3;

    /// <summary>Default parallelism.</summary>
    public const int DefaultParallelism = 4;

    /// <summary>Length of the salt in bytes.</summary>
    public const int SaltLength = 16;

    /// <summary>Creates parameters with a fresh random salt.</summary>
    public static KeyDerivationParameters CreateNew() => new()
    {
        Salt = RandomNumberGenerator.GetBytes(SaltLength),
    };

    /// <summary>Rejects parameters that are outside the accepted range.</summary>
    public void Validate()
    {
        if (Salt is null || Salt.Length < 8)
        {
            throw new InvalidDataException("The container declares an unusable key derivation salt.");
        }

        if (MemoryKib is < 8 * 1024 or > 4 * 1024 * 1024)
        {
            throw new InvalidDataException($"The container declares an unsupported memory cost of {MemoryKib} KiB.");
        }

        if (Iterations is < 1 or > 64)
        {
            throw new InvalidDataException($"The container declares an unsupported iteration count of {Iterations}.");
        }

        if (Parallelism is < 1 or > 64)
        {
            throw new InvalidDataException($"The container declares an unsupported parallelism of {Parallelism}.");
        }
    }
}

/// <summary>
/// Derives container keys from an operator passphrase using Argon2id.
/// </summary>
/// <remarks>
/// The passphrase is never stored, and neither is the derived key: both exist only for the duration
/// of a save or open operation and are wiped from memory afterwards. A memory-hard derivation is
/// used so that a stolen project file resists offline guessing.
/// </remarks>
public static class PassphraseKeyDerivation
{
    /// <summary>Length of the derived master key in bytes.</summary>
    public const int KeyLength = 32;

    /// <summary>Derives the master key. The caller is responsible for wiping the result.</summary>
    public static byte[] DeriveMasterKey(ReadOnlySpan<char> passphrase, KeyDerivationParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        parameters.Validate();

        if (passphrase.IsEmpty)
        {
            throw new ArgumentException("A project passphrase is required.", nameof(passphrase));
        }

        var passphraseBytes = Encoding.UTF8.GetBytes(passphrase.ToArray());

        try
        {
            using var argon = new Argon2id(passphraseBytes)
            {
                Salt = parameters.Salt,
                MemorySize = parameters.MemoryKib,
                Iterations = parameters.Iterations,
                DegreeOfParallelism = parameters.Parallelism,
            };

            return argon.GetBytes(KeyLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    /// <summary>
    /// Derives a purpose-specific subkey from the master key, so that the manifest, the payload and
    /// the database are never encrypted under the same key.
    /// </summary>
    public static byte[] DeriveSubkey(ReadOnlySpan<byte> masterKey, string purpose, int length = KeyLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);

        var subkey = new byte[length];

        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            masterKey,
            subkey,
            salt: ReadOnlySpan<byte>.Empty,
            info: Encoding.UTF8.GetBytes(purpose));

        return subkey;
    }

    /// <summary>Measures the strength of a passphrase so the user interface can warn about weak ones.</summary>
    public static PassphraseStrength EvaluateStrength(ReadOnlySpan<char> passphrase)
    {
        if (passphrase.Length == 0)
        {
            return PassphraseStrength.Unusable;
        }

        var hasLower = false;
        var hasUpper = false;
        var hasDigit = false;
        var hasOther = false;

        foreach (var character in passphrase)
        {
            if (char.IsLower(character))
            {
                hasLower = true;
            }
            else if (char.IsUpper(character))
            {
                hasUpper = true;
            }
            else if (char.IsDigit(character))
            {
                hasDigit = true;
            }
            else
            {
                hasOther = true;
            }
        }

        var classes = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasOther ? 1 : 0);

        return passphrase.Length switch
        {
            < 12 => PassphraseStrength.Unusable,
            < 16 when classes < 3 => PassphraseStrength.Weak,
            < 16 => PassphraseStrength.Acceptable,
            < 24 when classes < 2 => PassphraseStrength.Weak,
            < 24 => PassphraseStrength.Acceptable,
            _ => PassphraseStrength.Strong,
        };
    }
}

/// <summary>Strength bands used by the passphrase prompt.</summary>
public enum PassphraseStrength
{
    /// <summary>Too short to be accepted: the minimum is twelve characters.</summary>
    Unusable,

    /// <summary>Accepted with a warning.</summary>
    Weak,

    /// <summary>Meets the recommended minimum.</summary>
    Acceptable,

    /// <summary>Comfortably above the recommended minimum.</summary>
    Strong,
}
