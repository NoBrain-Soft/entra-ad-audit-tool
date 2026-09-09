using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Ipa.Persistence.Session;

/// <summary>
/// The temporary encrypted database that holds an assessment while it is being worked on.
/// </summary>
/// <remarks>
/// The database is encrypted with SQLCipher under a random key generated in memory at startup. The
/// key is never written anywhere, so the file is unreadable the moment the process ends. On a normal
/// exit the file and its directory are deleted; after a crash the leftover directory is detectable
/// by <see cref="CrashRecovery"/>, which offers the operator a cleanup rather than leaving assessment
/// data on disk.
/// </remarks>
public sealed class EphemeralSessionStore : IDisposable
{
    private readonly byte[] _key;
    private readonly string _directory;
    private bool _disposed;

    private EphemeralSessionStore(string directory, string databasePath, byte[] key)
    {
        _directory = directory;
        _key = key;
        DatabasePath = databasePath;
    }

    /// <summary>Path of the temporary database file.</summary>
    public string DatabasePath { get; }

    /// <summary>Directory holding the session, deleted on disposal.</summary>
    public string Directory => _directory;

    /// <summary>Creates a fresh ephemeral session under the operating system temporary directory.</summary>
    public static EphemeralSessionStore Create(Guid assessmentId, string? rootDirectory = null)
    {
        var root = rootDirectory ?? Path.Combine(Path.GetTempPath(), Contracts.ProductInfo.EphemeralDirectoryName);
        var directory = Path.Combine(root, assessmentId.ToString("n"));

        System.IO.Directory.CreateDirectory(directory);
        RestrictDirectoryAccess(directory);

        var databasePath = Path.Combine(directory, "session.db");

        // A 256-bit key from the platform generator, held only in memory for the process lifetime.
        var key = RandomNumberGenerator.GetBytes(32);

        var store = new EphemeralSessionStore(directory, databasePath, key);

        try
        {
            CrashRecovery.WriteMarker(directory, assessmentId);

            using var connection = store.OpenConnection();
            Schema.AssessmentSchema.Initialise(connection);

            return store;
        }
        catch
        {
            store.Dispose();
            throw;
        }
    }

    /// <summary>Opens a connection to the encrypted session database.</summary>
    public SqliteConnection OpenConnection()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        SqliteInitialiser.EnsureInitialised();

        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            Password = Convert.ToHexString(_key),
        };

        var connection = new SqliteConnection(builder.ConnectionString);
        connection.Open();

        // The key is supplied as a raw hexadecimal blob so that no key derivation is applied to it:
        // it is already a full-strength random key.
        using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;";
            pragma.ExecuteNonQuery();
        }

        return connection;
    }

    /// <summary>Reads the whole database file, for writing it into a saved project container.</summary>
    public byte[] SnapshotDatabase()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        SqliteInitialiser.EnsureInitialised();

        // A checkpoint flushes the write-ahead log so the snapshot is a complete database.
        using (var connection = OpenConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
            command.ExecuteNonQuery();
        }

        SqliteConnection.ClearAllPools();
        return File.ReadAllBytes(DatabasePath);
    }

    /// <summary>Restores a database snapshot from an opened project into this session.</summary>
    public void RestoreDatabase(byte[] snapshot, ReadOnlySpan<char> projectPassphrase)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ObjectDisposedException.ThrowIf(_disposed, this);

        SqliteInitialiser.EnsureInitialised();
        SqliteConnection.ClearAllPools();

        var restored = Path.Combine(_directory, "restored.db");
        File.WriteAllBytes(restored, snapshot);

        try
        {
            // The snapshot arrives already decrypted from the container, so it is re-encrypted into
            // the session database under this session's ephemeral key.
            using var source = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = restored,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ConnectionString);

            source.Open();

            using var destination = OpenConnection();
            source.BackupDatabase(destination);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            TryDelete(restored);
        }
    }

    /// <summary>Deletes the session directory and wipes the key from memory.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        SqliteConnection.ClearAllPools();
        CryptographicOperations.ZeroMemory(_key);

        try
        {
            if (System.IO.Directory.Exists(_directory))
            {
                System.IO.Directory.Delete(_directory, recursive: true);
            }
        }
        catch (IOException)
        {
            // A file still held open by the operating system is left for crash recovery to clean up
            // on the next start rather than failing the shutdown.
        }
        catch (UnauthorizedAccessException)
        {
            // As above: cleanup is retried on the next start.
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // Left for crash recovery.
        }
    }

    /// <summary>
    /// Restricts the session directory to the current user where the platform supports it. On Linux
    /// this sets owner-only permissions; on Windows the temporary directory is already per-user.
    /// </summary>
    private static void RestrictDirectoryAccess(string directory)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(
                directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (IOException)
        {
            // A file system that does not support permissions leaves the directory as created.
        }
    }
}

/// <summary>Initialises the SQLCipher provider exactly once per process.</summary>
public static class SqliteInitialiser
{
    private static readonly Lock Gate = new();
    private static bool _initialised;

    /// <summary>Registers the SQLCipher-backed provider with the data access layer.</summary>
    public static void EnsureInitialised()
    {
        if (_initialised)
        {
            return;
        }

        lock (Gate)
        {
            if (_initialised)
            {
                return;
            }

            SQLitePCL.Batteries_V2.Init();
            _initialised = true;
        }
    }
}

/// <summary>
/// Detects and cleans up ephemeral sessions left behind by a crash. Assessment data is never meant
/// to survive a session, so a leftover directory is offered for deletion at the next start.
/// </summary>
public static class CrashRecovery
{
    /// <summary>Name of the marker file written into each session directory.</summary>
    public const string MarkerFileName = "session.marker.json";

    /// <summary>A session directory left behind by a previous run.</summary>
    /// <param name="Directory">Path of the leftover directory.</param>
    /// <param name="AssessmentId">Assessment the session belonged to, when readable.</param>
    /// <param name="CreatedAt">When the session was created.</param>
    /// <param name="SizeBytes">Total size of the leftover files.</param>
    public sealed record StaleSession(string Directory, Guid? AssessmentId, DateTimeOffset? CreatedAt, long SizeBytes);

    /// <summary>Writes the marker that identifies a live session directory.</summary>
    public static void WriteMarker(string directory, Guid assessmentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        var marker = new
        {
            assessmentId,
            createdAt = DateTimeOffset.UtcNow,
            processId = Environment.ProcessId,
            applicationVersion = Contracts.ProductInfo.Version,
        };

        File.WriteAllText(Path.Combine(directory, MarkerFileName), JsonSerializer.Serialize(marker));
    }

    /// <summary>Finds session directories left behind by a previous run.</summary>
    public static IReadOnlyList<StaleSession> FindStaleSessions(string? rootDirectory = null)
    {
        var root = rootDirectory ?? Path.Combine(Path.GetTempPath(), Contracts.ProductInfo.EphemeralDirectoryName);

        if (!System.IO.Directory.Exists(root))
        {
            return [];
        }

        var sessions = new List<StaleSession>();

        foreach (var directory in System.IO.Directory.EnumerateDirectories(root))
        {
            var markerPath = Path.Combine(directory, MarkerFileName);
            Guid? assessmentId = null;
            DateTimeOffset? createdAt = null;

            if (File.Exists(markerPath))
            {
                try
                {
                    using var document = JsonDocument.Parse(File.ReadAllText(markerPath));

                    if (document.RootElement.TryGetProperty("assessmentId", out var id)
                        && Guid.TryParse(id.GetString(), out var parsed))
                    {
                        assessmentId = parsed;
                    }

                    if (document.RootElement.TryGetProperty("createdAt", out var created)
                        && created.TryGetDateTimeOffset(out var timestamp))
                    {
                        createdAt = timestamp;
                    }
                }
                catch (JsonException)
                {
                    // An unreadable marker still identifies a directory that should be cleaned up.
                }
            }

            long size = 0;

            try
            {
                size = System.IO.Directory
                    .EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                    .Sum(file => new FileInfo(file).Length);
            }
            catch (IOException)
            {
                // A partially deleted directory still counts as stale.
            }

            sessions.Add(new StaleSession(directory, assessmentId, createdAt, size));
        }

        return sessions;
    }

    /// <summary>Deletes a stale session directory. Returns true when nothing is left behind.</summary>
    public static bool Cleanup(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        try
        {
            if (System.IO.Directory.Exists(directory))
            {
                System.IO.Directory.Delete(directory, recursive: true);
            }

            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
}
