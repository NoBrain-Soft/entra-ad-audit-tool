using Ipa.Contracts;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Rules;
using Ipa.Persistence;
using Ipa.Persistence.Schema;
using Ipa.Persistence.Session;
using Xunit;

namespace Ipa.Persistence.Tests;

/// <summary>
/// Tests for the ephemeral session database: it must be encrypted, it must be deleted on a normal
/// exit, and what it leaves behind after a crash must be detectable and removable.
/// </summary>
public sealed class SessionStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "ipa-tests-" + Guid.NewGuid().ToString("n"));

    private static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static AssessmentSession NewSession(Guid id) => new()
    {
        AssessmentId = id,
        Metadata = new AssessmentMetadata { CustomerName = "Contoso", AssessorName = "Assessor" },
        Scope = new AssessmentScope { IncludeActiveDirectory = true, IncludeEntra = true },
        CreatedAt = Reference,
        ReferenceTime = Reference,
        RulePackVersion = "2026.09.1",
    };

    [Fact]
    public void SessionDatabaseIsCreatedWithTheCurrentSchema()
    {
        var assessmentId = Guid.NewGuid();
        using var store = EphemeralSessionStore.Create(assessmentId, _root);

        Assert.True(File.Exists(store.DatabasePath));

        using var connection = store.OpenConnection();
        Assert.Equal(AssessmentSchema.CurrentVersion, AssessmentSchema.ReadVersion(connection));
    }

    [Fact]
    public void SessionDatabaseIsNotReadableWithoutTheSessionKey()
    {
        var assessmentId = Guid.NewGuid();
        string databasePath;

        using (var store = EphemeralSessionStore.Create(assessmentId, _root))
        {
            var repository = new AssessmentRepository(store);
            repository.SaveAssessment(NewSession(assessmentId));

            databasePath = store.DatabasePath;

            // The file header of an encrypted database must not be the SQLite magic string, which
            // is what proves the content is not sitting in plaintext on disk.
            var header = File.ReadAllBytes(databasePath).Take(16).ToArray();
            var text = System.Text.Encoding.ASCII.GetString(header);

            Assert.DoesNotContain("SQLite format 3", text, StringComparison.Ordinal);
        }

        Assert.False(File.Exists(databasePath));
    }

    [Fact]
    public void DisposingTheStoreRemovesTheSessionDirectory()
    {
        var assessmentId = Guid.NewGuid();
        string directory;

        using (var store = EphemeralSessionStore.Create(assessmentId, _root))
        {
            directory = store.Directory;
            Assert.True(Directory.Exists(directory));
        }

        Assert.False(Directory.Exists(directory));
    }

    [Fact]
    public void StaleSessionsAreDetectedAndCanBeCleanedUp()
    {
        var assessmentId = Guid.NewGuid();
        var directory = Path.Combine(_root, assessmentId.ToString("n"));

        // Simulate a crash: the directory and marker survive but the store was never disposed.
        Directory.CreateDirectory(directory);
        CrashRecovery.WriteMarker(directory, assessmentId);
        File.WriteAllBytes(Path.Combine(directory, "session.db"), new byte[4096]);

        var stale = CrashRecovery.FindStaleSessions(_root);

        var session = Assert.Single(stale);
        Assert.Equal(assessmentId, session.AssessmentId);
        Assert.True(session.SizeBytes > 0);

        Assert.True(CrashRecovery.Cleanup(session.Directory));
        Assert.Empty(CrashRecovery.FindStaleSessions(_root));
    }

    [Fact]
    public void NoStaleSessionsAreReportedWhenTheRootIsAbsent() =>
        Assert.Empty(CrashRecovery.FindStaleSessions(Path.Combine(_root, "never-created")));

    [Fact]
    public void AssessmentRoundTripsThroughTheRepository()
    {
        var assessmentId = Guid.NewGuid();
        using var store = EphemeralSessionStore.Create(assessmentId, _root);
        var repository = new AssessmentRepository(store);

        repository.SaveAssessment(NewSession(assessmentId));

        var loaded = repository.LoadAssessment();

        Assert.NotNull(loaded);
        Assert.Equal(assessmentId, loaded!.Value.Id);
        Assert.Equal("Contoso", loaded.Value.Metadata.CustomerName);
        Assert.True(loaded.Value.Scope.IncludeHybrid);
        Assert.Equal("2026.09.1", loaded.Value.RulePackVersion);
    }

    [Fact]
    public void RuleResultsRoundTrip()
    {
        var assessmentId = Guid.NewGuid();
        using var store = EphemeralSessionStore.Create(assessmentId, _root);
        var repository = new AssessmentRepository(store);
        repository.SaveAssessment(NewSession(assessmentId));

        var results = new[]
        {
            new RuleResult
            {
                RuleId = new RuleId("AD-PRIV-001"), RuleVersion = 1, Status = RuleStatus.Fail,
                EvaluatedAt = Reference, Rationale = "Too many administrators.",
                AffectedObjects =
                [
                    new AffectedObject
                    {
                        Identifier = "S-1-5-21-1-2-3-1105", DisplayName = "admin", ObjectType = "user",
                    },
                ],
            },
            new RuleResult
            {
                RuleId = new RuleId("EID-CA-001"), RuleVersion = 1, Status = RuleStatus.NotCollected,
                EvaluatedAt = Reference, Rationale = "Consent missing.",
                Availability = Contracts.EvidenceAvailability.PermissionDenied,
            },
        };

        repository.SaveRuleResults(assessmentId, results);
        var loaded = repository.LoadRuleResults(assessmentId);

        Assert.Equal(2, loaded.Count);
        Assert.Equal(RuleStatus.Fail, loaded[0].Status);
        Assert.Single(loaded[0].AffectedObjects);
        Assert.Equal(Contracts.EvidenceAvailability.PermissionDenied, loaded[1].Availability);
    }

    [Fact]
    public void SavingRuleResultsReplacesThePreviousSet()
    {
        var assessmentId = Guid.NewGuid();
        using var store = EphemeralSessionStore.Create(assessmentId, _root);
        var repository = new AssessmentRepository(store);
        repository.SaveAssessment(NewSession(assessmentId));

        repository.SaveRuleResults(assessmentId,
        [
            new RuleResult
            {
                RuleId = new RuleId("A"), RuleVersion = 1, Status = RuleStatus.Pass,
                EvaluatedAt = Reference, Rationale = "first",
            },
        ]);

        repository.SaveRuleResults(assessmentId,
        [
            new RuleResult
            {
                RuleId = new RuleId("B"), RuleVersion = 1, Status = RuleStatus.Fail,
                EvaluatedAt = Reference, Rationale = "second",
            },
        ]);

        var loaded = repository.LoadRuleResults(assessmentId);

        Assert.Equal("B", Assert.Single(loaded).RuleId.Value);
    }

    [Fact]
    public void FindingWorkflowRoundTrips()
    {
        var assessmentId = Guid.NewGuid();
        using var store = EphemeralSessionStore.Create(assessmentId, _root);
        var repository = new AssessmentRepository(store);
        repository.SaveAssessment(NewSession(assessmentId));

        repository.SaveFindingWorkflow(
            assessmentId,
            "AD-PRIV-001",
            "Reviewed with the identity team.",
            new Contracts.Findings.FindingException
            {
                Disposition = Contracts.Findings.FindingDisposition.RiskAccepted,
                Justification = "Compensating control in place until the migration completes.",
                RecordedBy = "Assessor",
                RecordedAt = Reference,
                ReviewDate = Reference.AddMonths(3),
            });

        var (notes, exceptions) = repository.LoadFindingWorkflow(assessmentId);

        Assert.Equal("Reviewed with the identity team.", notes["AD-PRIV-001"]);
        Assert.Equal(Contracts.Findings.FindingDisposition.RiskAccepted, exceptions["AD-PRIV-001"].Disposition);
    }

    [Fact]
    public void ControlAssessmentsAndAttestationsRoundTrip()
    {
        var assessmentId = Guid.NewGuid();
        using var store = EphemeralSessionStore.Create(assessmentId, _root);
        var repository = new AssessmentRepository(store);
        repository.SaveAssessment(NewSession(assessmentId));

        repository.SaveControlAssessments(assessmentId,
        [
            new ControlAssessment
            {
                ControlId = "A.8.2",
                Status = ControlStatus.Satisfied,
                OperatorConfirmed = true,
                Owner = "Identity Team",
                MappedRuleIds = ["AD-PRIV-001"],
                Attestations =
                [
                    new Attestation
                    {
                        AttestationId = "att-1", ControlId = "A.8.2",
                        Statement = "Quarterly privileged access review completed.",
                        AttestedBy = "Security Manager", AttestedAt = Reference,
                    },
                ],
            },
        ]);

        var loaded = Assert.Single(repository.LoadControlAssessments(assessmentId));

        Assert.Equal(ControlStatus.Satisfied, loaded.Status);
        Assert.True(loaded.OperatorConfirmed);
        Assert.Equal("AD-PRIV-001", Assert.Single(loaded.MappedRuleIds));
        Assert.Equal("att-1", Assert.Single(loaded.Attestations).AttestationId);
    }

    [Fact]
    public void DiagnosticsAppendInOrder()
    {
        var assessmentId = Guid.NewGuid();
        using var store = EphemeralSessionStore.Create(assessmentId, _root);
        var repository = new AssessmentRepository(store);
        repository.SaveAssessment(NewSession(assessmentId));

        repository.AppendDiagnostics(assessmentId,
        [
            new CollectionDiagnostic
            {
                Timestamp = Reference, Severity = DiagnosticSeverity.Information,
                CollectorId = "ad.directory", Message = "first",
            },
        ]);

        repository.AppendDiagnostics(assessmentId,
        [
            new CollectionDiagnostic
            {
                Timestamp = Reference.AddSeconds(1), Severity = DiagnosticSeverity.Warning,
                CollectorId = "ad.groupPolicy", Message = "second",
            },
        ]);

        var loaded = repository.LoadDiagnostics(assessmentId);

        Assert.Equal(2, loaded.Count);
        Assert.Equal("first", loaded[0].Message);
        Assert.Equal("second", loaded[1].Message);
    }

    [Fact]
    public void SchemaRefusesToOpenANewerDatabase()
    {
        Assert.False(AssessmentSchema.CanOpen(AssessmentSchema.CurrentVersion + 1, out var reason));
        Assert.Contains("supports up to", reason!, StringComparison.Ordinal);

        Assert.True(AssessmentSchema.CanOpen(AssessmentSchema.CurrentVersion, out _));
        Assert.False(AssessmentSchema.CanOpen(0, out _));
    }

    [Fact]
    public void SchemaInitialisationIsIdempotent()
    {
        var assessmentId = Guid.NewGuid();
        using var store = EphemeralSessionStore.Create(assessmentId, _root);

        using var connection = store.OpenConnection();

        // Running the migration path again on an already current database must be a no-op.
        AssessmentSchema.Initialise(connection);

        Assert.Equal(AssessmentSchema.CurrentVersion, AssessmentSchema.ReadVersion(connection));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException)
            {
                // The test root is under the temporary directory and is cleaned up by the platform.
            }
        }
    }
}
