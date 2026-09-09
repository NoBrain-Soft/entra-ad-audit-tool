using System.Net;
using Ipa.Collectors.ActiveDirectory.Connection;
using SMBLibrary;
using SMBLibrary.Client;

namespace Ipa.Collectors.ActiveDirectory.Sysvol;

/// <summary>A file discovered while walking a SYSVOL policy folder.</summary>
public sealed record SysvolFile(string RelativePath, long Length);

/// <summary>
/// Reads policy content from the SYSVOL share over SMB2. The client is fully managed: it never
/// shells out to a mount command and never mounts a share on the host, so it behaves identically
/// on Windows and on Linux and leaves no state behind on the operator's machine.
/// </summary>
public sealed class SysvolClient : IDisposable
{
    private readonly SMB2Client _client = new();
    private ISMBFileStore? _share;
    private bool _connected;

    /// <summary>Largest file the client will read from SYSVOL.</summary>
    public const int MaxFileBytes = 16 * 1024 * 1024;

    /// <summary>Maximum directory depth walked below a policy folder.</summary>
    public const int MaxDepth = 12;

    /// <summary>Maximum number of files enumerated per policy folder.</summary>
    public const int MaxFilesPerPolicy = 5_000;

    /// <summary>Connects to the SYSVOL share of a domain controller.</summary>
    /// <param name="server">Domain controller host name.</param>
    /// <param name="credential">
    /// Explicit credentials, or null to use an empty credential set. SMB2 is negotiated with
    /// signing required so that content cannot be altered in transit.
    /// </param>
    public void Connect(string server, DirectoryCredential? credential)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(server);

        var addresses = Dns.GetHostAddresses(server);
        if (addresses.Length == 0)
        {
            throw new InvalidOperationException($"The host '{server}' did not resolve to an address.");
        }

        if (!_client.Connect(addresses[0], SMBTransportType.DirectTCPTransport))
        {
            throw new InvalidOperationException($"Could not establish an SMB2 connection to '{server}'.");
        }

        _connected = true;

        var network = credential?.ToNetworkCredential();
        var status = _client.Login(
            network?.Domain ?? string.Empty,
            network?.UserName ?? string.Empty,
            network?.Password ?? string.Empty);

        if (status != NTStatus.STATUS_SUCCESS)
        {
            throw new InvalidOperationException($"SMB2 authentication to '{server}' failed with {status}.");
        }

        _share = _client.TreeConnect("SYSVOL", out var treeStatus);

        if (treeStatus != NTStatus.STATUS_SUCCESS || _share is null)
        {
            throw new InvalidOperationException($"Could not connect to the SYSVOL share on '{server}': {treeStatus}.");
        }
    }

    /// <summary>Lists the files beneath a path on the share, walking subdirectories.</summary>
    /// <param name="basePath">Share-relative path, for example <c>contoso.com/Policies/{GUID}</c>.</param>
    /// <param name="cancellationToken">Cancellation token honoured between directory reads.</param>
    public IReadOnlyList<SysvolFile> ListFiles(string basePath, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(basePath);
        EnsureConnected();

        var files = new List<SysvolFile>();
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((Normalise(basePath), 0));

        while (queue.Count > 0 && files.Count < MaxFilesPerPolicy)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var (path, depth) = queue.Dequeue();

            if (depth > MaxDepth)
            {
                continue;
            }

            var status = _share!.CreateFile(
                out var handle,
                out _,
                path,
                AccessMask.GENERIC_READ,
                SMBLibrary.FileAttributes.Directory,
                ShareAccess.Read | ShareAccess.Write,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_DIRECTORY_FILE,
                null);

            if (status != NTStatus.STATUS_SUCCESS)
            {
                continue;
            }

            try
            {
                var queryStatus = _share.QueryDirectory(out var entries, handle, "*", FileInformationClass.FileDirectoryInformation);

                if (queryStatus != NTStatus.STATUS_SUCCESS)
                {
                    continue;
                }

                foreach (var information in entries.OfType<FileDirectoryInformation>())
                {
                    if (information.FileName is "." or "..")
                    {
                        continue;
                    }

                    var childPath = path.Length == 0
                        ? information.FileName
                        : $"{path}\\{information.FileName}";

                    if (information.FileAttributes.HasFlag(SMBLibrary.FileAttributes.Directory))
                    {
                        queue.Enqueue((childPath, depth + 1));
                        continue;
                    }

                    files.Add(new SysvolFile(childPath, information.EndOfFile));

                    if (files.Count >= MaxFilesPerPolicy)
                    {
                        break;
                    }
                }
            }
            finally
            {
                _share.CloseFile(handle);
            }
        }

        return files;
    }

    /// <summary>Reads a file from the share, refusing anything above the size limit.</summary>
    public byte[] ReadFile(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        EnsureConnected();

        var status = _share!.CreateFile(
            out var handle,
            out _,
            Normalise(path),
            AccessMask.GENERIC_READ,
            SMBLibrary.FileAttributes.Normal,
            ShareAccess.Read | ShareAccess.Write,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
            null);

        if (status != NTStatus.STATUS_SUCCESS)
        {
            throw new IOException($"Could not open '{path}' on the SYSVOL share: {status}.");
        }

        try
        {
            using var buffer = new MemoryStream();
            long offset = 0;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var readStatus = _share.ReadFile(out var data, handle, offset, (int)_client.MaxReadSize);

                if (readStatus == NTStatus.STATUS_END_OF_FILE || data is null || data.Length == 0)
                {
                    break;
                }

                if (readStatus != NTStatus.STATUS_SUCCESS)
                {
                    throw new IOException($"Reading '{path}' from SYSVOL failed with {readStatus}.");
                }

                if (buffer.Length + data.Length > MaxFileBytes)
                {
                    throw new IOException($"The file '{path}' exceeds the {MaxFileBytes} byte read limit.");
                }

                buffer.Write(data, 0, data.Length);
                offset += data.Length;
            }

            return buffer.ToArray();
        }
        finally
        {
            _share.CloseFile(handle);
        }
    }

    /// <summary>True when a file exists on the share.</summary>
    public bool FileExists(string path)
    {
        EnsureConnected();

        var status = _share!.CreateFile(
            out var handle,
            out _,
            Normalise(path),
            AccessMask.GENERIC_READ,
            SMBLibrary.FileAttributes.Normal,
            ShareAccess.Read | ShareAccess.Write,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
            null);

        if (status != NTStatus.STATUS_SUCCESS)
        {
            return false;
        }

        _share.CloseFile(handle);
        return true;
    }

    /// <summary>
    /// Converts a UNC or slash-separated path into the backslash-separated, share-relative form the
    /// SMB layer expects, and refuses any path that tries to escape the share.
    /// </summary>
    public static string Normalise(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var value = path.Replace('/', '\\');

        // A universal naming convention path names the host and the share before the content:
        // \\server\SYSVOL\domain\Policies\... The share layer addresses paths relative to the
        // share, so the first two segments are removed before the leading separators are trimmed.
        if (value.StartsWith(@"\\", StringComparison.Ordinal))
        {
            var segments = value.TrimStart('\\').Split('\\', 3);
            value = segments.Length == 3 ? segments[2] : string.Empty;
        }

        value = value.Trim('\\');

        if (value.Split('\\').Any(segment => segment == ".."))
        {
            throw new ArgumentException("The SYSVOL path must not traverse above the share root.", nameof(path));
        }

        return value;
    }

    private void EnsureConnected()
    {
        if (_share is null)
        {
            throw new InvalidOperationException("The SYSVOL client is not connected.");
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_share is not null)
        {
            _share.Disconnect();
            _share = null;
        }

        if (_connected)
        {
            _client.Logoff();
            _client.Disconnect();
            _connected = false;
        }
    }
}
