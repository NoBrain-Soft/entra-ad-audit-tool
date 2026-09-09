using System.Text.Json;
using Ipa.Contracts;
using Ipa.Contracts.Assessment;
using Ipa.Persistence;
using Ipa.Persistence.Projects;
using Ipa.Persistence.Schema;
using Ipa.Persistence.Session;

namespace Ipa.Core.Projects;

/// <summary>Summary of a project shown before it is unlocked.</summary>
public sealed record ProjectSummary
{
    public required string FilePath { get; init; }
    public required int FormatVersion { get; init; }
    public required long SizeBytes { get; init; }
    public required DateTimeOffset LastModified { get; init; }

    /// <summary>True when this release can open a container of this format version.</summary>
    public bool IsSupported { get; init; }
}

/// <summary>
/// Saves and opens encrypted projects.
/// </summary>
/// <remarks>
/// Assessments are ephemeral by default: nothing survives the session unless the operator
/// explicitly saves a project. Saving writes the session database and any evidence attachments into
/// one portable encrypted container; opening restores them into a fresh ephemeral session, so a
/// project is never worked on in place and an interrupted session cannot corrupt a saved file.
/// </remarks>
public sealed class ProjectService
{
    private readonly ProjectContainer _container = new();

    /// <summary>Saves a session to an encrypted project container.</summary>
    /// <param name="session">The assessment to save.</param>
    /// <param name="store">The ephemeral store holding the working database.</param>
    /// <param name="filePath">Destination path.</param>
    /// <param name="passphrase">Operator passphrase. Never stored.</param>
    /// <param name="attachments">Evidence attachments, keyed by attachment identifier.</param>
    /// <param name="label">Optional project label.</param>
    public void Save(
        AssessmentSession session,
        EphemeralSessionStore store,
        string filePath,
        ReadOnlySpan<char> passphrase,
        IReadOnlyDictionary<string, byte[]>? attachments = null,
        string? label = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [ProjectContainer.DatabaseEntryName] = store.SnapshotDatabase(),
        };

        foreach (var (attachmentId, content) in attachments ?? new Dictionary<string, byte[]>())
        {
            entries[ProjectContainer.AttachmentPrefix + attachmentId] = content;
        }

        var baselineHashes = new Dictionary<string, string>(StringComparer.Ordinal);
        var baselineIdentities = new Dictionary<string, string>(StringComparer.Ordinal);

        if (session.Baseline is { } baseline)
        {
            baselineHashes[baseline.BaselineId] = baseline.PackageSha256;
            baselineIdentities[baseline.BaselineId] = $"{baseline.ProductName} / {baseline.BaselineVersion}";
        }

        // The container is written to a temporary file next to the destination and moved into place
        // only once it is complete, so an interrupted save never destroys an existing project.
        var temporaryPath = filePath + ".partial";

        try
        {
            using (var destination = File.Create(temporaryPath))
            {
                _container.Save(
                    destination,
                    passphrase,
                    entries,
                    (manifestEntries, payloadHash) => new ProjectManifest
                    {
                        SchemaVersion = AssessmentSchema.CurrentVersion,
                        ApplicationVersion = ProductInfo.Version,
                        RulePackVersion = session.RulePackVersion ?? "unknown",
                        AssessmentId = session.AssessmentId,
                        SavedAt = DateTimeOffset.UtcNow,
                        Entries = manifestEntries,
                        PayloadSha256 = payloadHash,
                        Label = label,
                        ImportedBaselineHashes = baselineHashes,
                        ImportedBaselineIdentities = baselineIdentities,
                    });
            }

            File.Move(temporaryPath, filePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    /// <summary>
    /// Opens a project into a fresh ephemeral session. The returned store owns the working copy and
    /// deletes it on disposal, exactly as a new assessment would.
    /// </summary>
    public OpenProjectResult Open(string filePath, ReadOnlySpan<char> passphrase, string? sessionRoot = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        using var source = File.OpenRead(filePath);
        var opened = _container.Open(source, passphrase);

        if (!AssessmentSchema.CanOpen(opened.Manifest.SchemaVersion, out var reason))
        {
            throw new ProjectContainerException(reason!, ProjectContainerFailure.UnsupportedVersion);
        }

        var store = EphemeralSessionStore.Create(opened.Manifest.AssessmentId, sessionRoot);

        try
        {
            store.RestoreDatabase(opened.Database, passphrase);

            using (var connection = store.OpenConnection())
            {
                // Applies any migrations between the project's schema version and this release.
                AssessmentSchema.Initialise(connection);
            }

            var attachments = opened.Entries
                .Where(entry => entry.Key.StartsWith(ProjectContainer.AttachmentPrefix, StringComparison.Ordinal))
                .ToDictionary(
                    entry => entry.Key[ProjectContainer.AttachmentPrefix.Length..],
                    entry => entry.Value,
                    StringComparer.Ordinal);

            return new OpenProjectResult
            {
                Store = store,
                Manifest = opened.Manifest,
                Attachments = attachments,
            };
        }
        catch
        {
            store.Dispose();
            throw;
        }
    }

    /// <summary>Reads the header of a project file without unlocking it.</summary>
    public static ProjectSummary Describe(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var info = new FileInfo(filePath);

        using var source = File.OpenRead(filePath);
        var header = ProjectContainer.ReadHeader(source);

        return new ProjectSummary
        {
            FilePath = filePath,
            FormatVersion = header.FormatVersion,
            SizeBytes = info.Length,
            LastModified = info.LastWriteTimeUtc,
            IsSupported = header.FormatVersion <= ProjectContainer.CurrentFormatVersion,
        };
    }

    /// <summary>Deletes a saved project. Used by the explicit delete action in the project browser.</summary>
    public static void Delete(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        if (File.Exists(filePath))
        {
            File.Delete(filePath);
        }
    }

    /// <summary>Rebuilds a session from a restored project database.</summary>
    public static AssessmentSession Rehydrate(AssessmentRepository repository, ProjectManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(manifest);

        var stored = repository.LoadAssessment()
                     ?? throw new ProjectContainerException(
                         "The project's database holds no assessment.",
                         ProjectContainerFailure.IntegrityFailed);

        var evidence = repository.LoadEvidence(stored.Id);
        var results = repository.LoadRuleResults(stored.Id);
        var controls = repository.LoadControlAssessments(stored.Id);
        var diagnostics = repository.LoadDiagnostics(stored.Id);
        var baselines = repository.LoadBaselines(stored.Id);
        var profiles = repository.LoadReportProfiles(stored.Id);

        return new AssessmentSession
        {
            AssessmentId = stored.Id,
            Metadata = stored.Metadata,
            Scope = stored.Scope,
            State = stored.State,
            CreatedAt = stored.CreatedAt,
            ReferenceTime = stored.ReferenceTime,
            RulePackVersion = stored.RulePackVersion ?? manifest.RulePackVersion,
            Evidence = evidence,
            RuleResults = results,
            ControlAssessments = controls,
            Diagnostics = diagnostics,
            Baseline = baselines.FirstOrDefault(),
            ReportProfile = profiles.FirstOrDefault(),
        };
    }
}

/// <summary>The result of opening a project.</summary>
public sealed record OpenProjectResult : IDisposable
{
    /// <summary>The ephemeral session holding the restored working copy.</summary>
    public required EphemeralSessionStore Store { get; init; }

    /// <summary>The verified manifest.</summary>
    public required ProjectManifest Manifest { get; init; }

    /// <summary>Evidence attachments, keyed by attachment identifier.</summary>
    public required IReadOnlyDictionary<string, byte[]> Attachments { get; init; }

    /// <inheritdoc />
    public void Dispose() => Store.Dispose();
}
