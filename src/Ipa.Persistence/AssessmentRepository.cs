using System.Text.Json;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Baselines;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Findings;
using Ipa.Contracts.Reporting;
using Ipa.Contracts.Rules;
using Ipa.Persistence.Session;
using Microsoft.Data.Sqlite;

namespace Ipa.Persistence;

/// <summary>
/// Reads and writes assessment state in the encrypted session database.
/// </summary>
/// <remarks>
/// Nothing this class writes is a credential: Active Directory passwords, Microsoft Graph tokens and
/// project passphrases have no column anywhere in the schema. Evidence records arrive already
/// redacted from the collectors.
/// </remarks>
public sealed class AssessmentRepository
{
    private readonly EphemeralSessionStore _store;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public AssessmentRepository(EphemeralSessionStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    /// <summary>Creates or replaces the assessment row.</summary>
    public void SaveAssessment(AssessmentSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = """
            INSERT INTO assessment (assessment_id, created_at, reference_time, state,
                                    application_version, rule_pack_version, metadata_json, scope_json)
            VALUES ($id, $created, $reference, $state, $version, $pack, $metadata, $scope)
            ON CONFLICT(assessment_id) DO UPDATE SET
                state = excluded.state,
                rule_pack_version = excluded.rule_pack_version,
                metadata_json = excluded.metadata_json,
                scope_json = excluded.scope_json;
            """;

        command.Parameters.AddWithValue("$id", session.AssessmentId.ToString("n"));
        command.Parameters.AddWithValue("$created", session.CreatedAt.ToString("o"));
        command.Parameters.AddWithValue("$reference", session.ReferenceTime.ToString("o"));
        command.Parameters.AddWithValue("$state", session.State.ToString());
        command.Parameters.AddWithValue("$version", session.ApplicationVersion);
        command.Parameters.AddWithValue("$pack", (object?)session.RulePackVersion ?? DBNull.Value);
        command.Parameters.AddWithValue("$metadata", JsonSerializer.Serialize(session.Metadata, JsonOptions));
        command.Parameters.AddWithValue("$scope", JsonSerializer.Serialize(session.Scope, JsonOptions));

        command.ExecuteNonQuery();
    }

    /// <summary>Loads the assessment row, or null when the database is empty.</summary>
    public (Guid Id, AssessmentMetadata Metadata, AssessmentScope Scope, AssessmentState State,
        DateTimeOffset CreatedAt, DateTimeOffset ReferenceTime, string? RulePackVersion)? LoadAssessment()
    {
        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = """
            SELECT assessment_id, created_at, reference_time, state, rule_pack_version, metadata_json, scope_json
            FROM assessment LIMIT 1;
            """;

        using var reader = command.ExecuteReader();

        if (!reader.Read())
        {
            return null;
        }

        return (
            Guid.Parse(reader.GetString(0)),
            JsonSerializer.Deserialize<AssessmentMetadata>(reader.GetString(5), JsonOptions)!,
            JsonSerializer.Deserialize<AssessmentScope>(reader.GetString(6), JsonOptions)!,
            Enum.Parse<AssessmentState>(reader.GetString(3)),
            DateTimeOffset.Parse(reader.GetString(1), System.Globalization.CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(reader.GetString(2), System.Globalization.CultureInfo.InvariantCulture),
            reader.IsDBNull(4) ? null : reader.GetString(4));
    }

    /// <summary>Stores the normalised evidence document for the assessment.</summary>
    public void SaveEvidence(Guid assessmentId, NormalizedEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = """
            INSERT INTO normalised_evidence (assessment_id, document, written_at)
            VALUES ($id, $document, $written)
            ON CONFLICT(assessment_id) DO UPDATE SET
                document = excluded.document, written_at = excluded.written_at;
            """;

        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));
        command.Parameters.AddWithValue("$document", JsonSerializer.SerializeToUtf8Bytes(evidence, JsonOptions));
        command.Parameters.AddWithValue("$written", DateTimeOffset.UtcNow.ToString("o"));

        command.ExecuteNonQuery();
    }

    /// <summary>Loads the normalised evidence document, or null when none has been stored.</summary>
    public NormalizedEvidence? LoadEvidence(Guid assessmentId)
    {
        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = "SELECT document FROM normalised_evidence WHERE assessment_id = $id;";
        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        using var reader = command.ExecuteReader();

        if (!reader.Read())
        {
            return null;
        }

        using var stream = reader.GetStream(0);
        return JsonSerializer.Deserialize<NormalizedEvidence>(stream, JsonOptions);
    }

    /// <summary>Replaces the stored rule results for an assessment.</summary>
    public void SaveRuleResults(Guid assessmentId, IReadOnlyCollection<RuleResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        using var connection = _store.OpenConnection();
        using var transaction = connection.BeginTransaction();

        using (var clear = connection.CreateCommand())
        {
            clear.Transaction = transaction;
            clear.CommandText = "DELETE FROM rule_result WHERE assessment_id = $id;";
            clear.Parameters.AddWithValue("$id", assessmentId.ToString("n"));
            clear.ExecuteNonQuery();
        }

        foreach (var result in results)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;

            command.CommandText = """
                INSERT INTO rule_result (assessment_id, rule_id, rule_version, status, availability,
                                         evaluated_at, rationale, detail_json)
                VALUES ($assessment, $rule, $version, $status, $availability, $evaluated, $rationale, $detail);
                """;

            command.Parameters.AddWithValue("$assessment", assessmentId.ToString("n"));
            command.Parameters.AddWithValue("$rule", result.RuleId.Value);
            command.Parameters.AddWithValue("$version", result.RuleVersion);
            command.Parameters.AddWithValue("$status", result.Status.ToString());
            command.Parameters.AddWithValue("$availability", (object?)result.Availability?.ToString() ?? DBNull.Value);
            command.Parameters.AddWithValue("$evaluated", result.EvaluatedAt.ToString("o"));
            command.Parameters.AddWithValue("$rationale", result.Rationale);
            command.Parameters.AddWithValue("$detail", JsonSerializer.Serialize(result, JsonOptions));

            command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>Loads the stored rule results.</summary>
    public IReadOnlyList<RuleResult> LoadRuleResults(Guid assessmentId)
    {
        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = "SELECT detail_json FROM rule_result WHERE assessment_id = $id ORDER BY rule_id;";
        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        var results = new List<RuleResult>();

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var result = JsonSerializer.Deserialize<RuleResult>(reader.GetString(0), JsonOptions);

            if (result is not null)
            {
                results.Add(result);
            }
        }

        return results;
    }

    /// <summary>Stores the operator's workflow state for one finding.</summary>
    public void SaveFindingWorkflow(Guid assessmentId, string findingId, string? notes, FindingException? exception)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(findingId);

        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = """
            INSERT INTO finding_workflow (assessment_id, finding_id, notes, disposition, justification,
                                          recorded_by, recorded_at, review_date)
            VALUES ($assessment, $finding, $notes, $disposition, $justification, $by, $at, $review)
            ON CONFLICT(assessment_id, finding_id) DO UPDATE SET
                notes = excluded.notes,
                disposition = excluded.disposition,
                justification = excluded.justification,
                recorded_by = excluded.recorded_by,
                recorded_at = excluded.recorded_at,
                review_date = excluded.review_date;
            """;

        command.Parameters.AddWithValue("$assessment", assessmentId.ToString("n"));
        command.Parameters.AddWithValue("$finding", findingId);
        command.Parameters.AddWithValue("$notes", (object?)notes ?? DBNull.Value);
        command.Parameters.AddWithValue("$disposition", (object?)exception?.Disposition.ToString() ?? DBNull.Value);
        command.Parameters.AddWithValue("$justification", (object?)exception?.Justification ?? DBNull.Value);
        command.Parameters.AddWithValue("$by", (object?)exception?.RecordedBy ?? DBNull.Value);
        command.Parameters.AddWithValue("$at", (object?)exception?.RecordedAt.ToString("o") ?? DBNull.Value);
        command.Parameters.AddWithValue("$review", (object?)exception?.ReviewDate?.ToString("o") ?? DBNull.Value);

        command.ExecuteNonQuery();
    }

    /// <summary>Loads finding notes and exceptions, keyed by finding identifier.</summary>
    public (Dictionary<string, string> Notes, Dictionary<string, FindingException> Exceptions) LoadFindingWorkflow(
        Guid assessmentId)
    {
        var notes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var exceptions = new Dictionary<string, FindingException>(StringComparer.OrdinalIgnoreCase);

        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = """
            SELECT finding_id, notes, disposition, justification, recorded_by, recorded_at, review_date
            FROM finding_workflow WHERE assessment_id = $id;
            """;

        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var findingId = reader.GetString(0);

            if (!reader.IsDBNull(1))
            {
                notes[findingId] = reader.GetString(1);
            }

            if (!reader.IsDBNull(2) && !reader.IsDBNull(3) && !reader.IsDBNull(4) && !reader.IsDBNull(5))
            {
                exceptions[findingId] = new FindingException
                {
                    Disposition = Enum.Parse<FindingDisposition>(reader.GetString(2)),
                    Justification = reader.GetString(3),
                    RecordedBy = reader.GetString(4),
                    RecordedAt = DateTimeOffset.Parse(reader.GetString(5), System.Globalization.CultureInfo.InvariantCulture),
                    ReviewDate = reader.IsDBNull(6)
                        ? null
                        : DateTimeOffset.Parse(reader.GetString(6), System.Globalization.CultureInfo.InvariantCulture),
                };
            }
        }

        return (notes, exceptions);
    }

    /// <summary>Replaces the stored compliance control assessments.</summary>
    public void SaveControlAssessments(Guid assessmentId, IReadOnlyCollection<ControlAssessment> assessments)
    {
        ArgumentNullException.ThrowIfNull(assessments);

        using var connection = _store.OpenConnection();
        using var transaction = connection.BeginTransaction();

        using (var clear = connection.CreateCommand())
        {
            clear.Transaction = transaction;
            clear.CommandText = "DELETE FROM control_assessment WHERE assessment_id = $id;";
            clear.Parameters.AddWithValue("$id", assessmentId.ToString("n"));
            clear.ExecuteNonQuery();
        }

        foreach (var assessment in assessments)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;

            command.CommandText = """
                INSERT INTO control_assessment (assessment_id, control_id, is_applicable, status, suggested,
                                                operator_confirmed, owner, notes, licensed_text, mapped_rules,
                                                evidence_refs, attachment_ids, review_date, updated_at)
                VALUES ($assessment, $control, $applicable, $status, $suggested, $confirmed, $owner, $notes,
                        $licensed, $rules, $refs, $attachments, $review, $updated);
                """;

            command.Parameters.AddWithValue("$assessment", assessmentId.ToString("n"));
            command.Parameters.AddWithValue("$control", assessment.ControlId);
            command.Parameters.AddWithValue("$applicable", assessment.IsApplicable ? 1 : 0);
            command.Parameters.AddWithValue("$status", assessment.Status.ToString());
            command.Parameters.AddWithValue("$suggested", assessment.Suggested.ToString());
            command.Parameters.AddWithValue("$confirmed", assessment.OperatorConfirmed ? 1 : 0);
            command.Parameters.AddWithValue("$owner", (object?)assessment.Owner ?? DBNull.Value);
            command.Parameters.AddWithValue("$notes", (object?)assessment.Notes ?? DBNull.Value);
            command.Parameters.AddWithValue("$licensed", (object?)assessment.LicensedText ?? DBNull.Value);
            command.Parameters.AddWithValue("$rules", JsonSerializer.Serialize(assessment.MappedRuleIds, JsonOptions));
            command.Parameters.AddWithValue("$refs", JsonSerializer.Serialize(assessment.EvidenceReferences, JsonOptions));
            command.Parameters.AddWithValue("$attachments", JsonSerializer.Serialize(assessment.AttachmentIds, JsonOptions));
            command.Parameters.AddWithValue("$review", (object?)assessment.ReviewDate?.ToString("o") ?? DBNull.Value);
            command.Parameters.AddWithValue("$updated", (object?)assessment.LastUpdatedAt?.ToString("o") ?? DBNull.Value);

            command.ExecuteNonQuery();

            foreach (var attestation in assessment.Attestations)
            {
                using var attestationCommand = connection.CreateCommand();
                attestationCommand.Transaction = transaction;

                attestationCommand.CommandText = """
                    INSERT INTO attestation (attestation_id, assessment_id, control_id, statement,
                                             attested_by, attested_at, attachment_ids, review_date)
                    VALUES ($id, $assessment, $control, $statement, $by, $at, $attachments, $review)
                    ON CONFLICT(attestation_id) DO UPDATE SET
                        statement = excluded.statement, attested_by = excluded.attested_by,
                        attested_at = excluded.attested_at, attachment_ids = excluded.attachment_ids,
                        review_date = excluded.review_date;
                    """;

                attestationCommand.Parameters.AddWithValue("$id", attestation.AttestationId);
                attestationCommand.Parameters.AddWithValue("$assessment", assessmentId.ToString("n"));
                attestationCommand.Parameters.AddWithValue("$control", attestation.ControlId);
                attestationCommand.Parameters.AddWithValue("$statement", attestation.Statement);
                attestationCommand.Parameters.AddWithValue("$by", attestation.AttestedBy);
                attestationCommand.Parameters.AddWithValue("$at", attestation.AttestedAt.ToString("o"));
                attestationCommand.Parameters.AddWithValue(
                    "$attachments",
                    JsonSerializer.Serialize(attestation.AttachmentIds, JsonOptions));
                attestationCommand.Parameters.AddWithValue(
                    "$review",
                    (object?)attestation.ReviewDate?.ToString("o") ?? DBNull.Value);

                attestationCommand.ExecuteNonQuery();
            }
        }

        transaction.Commit();
    }

    /// <summary>Loads the stored compliance control assessments with their attestations.</summary>
    public IReadOnlyList<ControlAssessment> LoadControlAssessments(Guid assessmentId)
    {
        using var connection = _store.OpenConnection();

        var attestations = LoadAttestations(connection, assessmentId);
        var assessments = new List<ControlAssessment>();

        using var command = connection.CreateCommand();

        command.CommandText = """
            SELECT control_id, is_applicable, status, suggested, operator_confirmed, owner, notes,
                   licensed_text, mapped_rules, evidence_refs, attachment_ids, review_date, updated_at
            FROM control_assessment WHERE assessment_id = $id ORDER BY control_id;
            """;

        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var controlId = reader.GetString(0);

            assessments.Add(new ControlAssessment
            {
                ControlId = controlId,
                IsApplicable = reader.GetInt32(1) != 0,
                Status = Enum.Parse<ControlStatus>(reader.GetString(2)),
                Suggested = Enum.Parse<SuggestedStatus>(reader.GetString(3)),
                OperatorConfirmed = reader.GetInt32(4) != 0,
                Owner = reader.IsDBNull(5) ? null : reader.GetString(5),
                Notes = reader.IsDBNull(6) ? null : reader.GetString(6),
                LicensedText = reader.IsDBNull(7) ? null : reader.GetString(7),
                MappedRuleIds = JsonSerializer.Deserialize<List<string>>(reader.GetString(8), JsonOptions) ?? [],
                EvidenceReferences = JsonSerializer.Deserialize<List<string>>(reader.GetString(9), JsonOptions) ?? [],
                AttachmentIds = JsonSerializer.Deserialize<List<string>>(reader.GetString(10), JsonOptions) ?? [],
                Attestations = attestations.GetValueOrDefault(controlId, []),
                ReviewDate = reader.IsDBNull(11)
                    ? null
                    : DateTimeOffset.Parse(reader.GetString(11), System.Globalization.CultureInfo.InvariantCulture),
                LastUpdatedAt = reader.IsDBNull(12)
                    ? null
                    : DateTimeOffset.Parse(reader.GetString(12), System.Globalization.CultureInfo.InvariantCulture),
            });
        }

        return assessments;
    }

    /// <summary>Appends diagnostics to the collection log.</summary>
    public void AppendDiagnostics(Guid assessmentId, IReadOnlyCollection<CollectionDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(diagnostics);

        if (diagnostics.Count == 0)
        {
            return;
        }

        using var connection = _store.OpenConnection();
        using var transaction = connection.BeginTransaction();

        var sequence = NextDiagnosticSequence(connection, transaction, assessmentId);

        foreach (var diagnostic in diagnostics)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;

            command.CommandText = """
                INSERT INTO collection_diagnostic (assessment_id, sequence, timestamp, severity,
                                                   collector_id, message, code, exception_type, attempt)
                VALUES ($assessment, $sequence, $timestamp, $severity, $collector, $message, $code, $exception, $attempt);
                """;

            command.Parameters.AddWithValue("$assessment", assessmentId.ToString("n"));
            command.Parameters.AddWithValue("$sequence", sequence++);
            command.Parameters.AddWithValue("$timestamp", diagnostic.Timestamp.ToString("o"));
            command.Parameters.AddWithValue("$severity", diagnostic.Severity.ToString());
            command.Parameters.AddWithValue("$collector", diagnostic.CollectorId);
            command.Parameters.AddWithValue("$message", diagnostic.Message);
            command.Parameters.AddWithValue("$code", (object?)diagnostic.Code ?? DBNull.Value);
            command.Parameters.AddWithValue("$exception", (object?)diagnostic.ExceptionType ?? DBNull.Value);
            command.Parameters.AddWithValue("$attempt", diagnostic.Attempt);

            command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>Loads the collection diagnostic log in order.</summary>
    public IReadOnlyList<CollectionDiagnostic> LoadDiagnostics(Guid assessmentId)
    {
        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = """
            SELECT timestamp, severity, collector_id, message, code, exception_type, attempt
            FROM collection_diagnostic WHERE assessment_id = $id ORDER BY sequence;
            """;

        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        var diagnostics = new List<CollectionDiagnostic>();

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            diagnostics.Add(new CollectionDiagnostic
            {
                Timestamp = DateTimeOffset.Parse(reader.GetString(0), System.Globalization.CultureInfo.InvariantCulture),
                Severity = Enum.Parse<DiagnosticSeverity>(reader.GetString(1)),
                CollectorId = reader.GetString(2),
                Message = reader.GetString(3),
                Code = reader.IsDBNull(4) ? null : reader.GetString(4),
                ExceptionType = reader.IsDBNull(5) ? null : reader.GetString(5),
                Attempt = reader.GetInt32(6),
            });
        }

        return diagnostics;
    }

    /// <summary>Stores an imported baseline.</summary>
    public void SaveBaseline(Guid assessmentId, ImportedBaseline baseline)
    {
        ArgumentNullException.ThrowIfNull(baseline);

        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = """
            INSERT INTO imported_baseline (baseline_id, assessment_id, file_name, package_sha256,
                                           product_name, baseline_version, imported_at, document)
            VALUES ($id, $assessment, $file, $hash, $product, $version, $imported, $document)
            ON CONFLICT(baseline_id) DO UPDATE SET document = excluded.document;
            """;

        command.Parameters.AddWithValue("$id", baseline.BaselineId);
        command.Parameters.AddWithValue("$assessment", assessmentId.ToString("n"));
        command.Parameters.AddWithValue("$file", baseline.SourceFileName);
        command.Parameters.AddWithValue("$hash", baseline.PackageSha256);
        command.Parameters.AddWithValue("$product", baseline.ProductName);
        command.Parameters.AddWithValue("$version", baseline.BaselineVersion);
        command.Parameters.AddWithValue("$imported", baseline.ImportedAt.ToString("o"));
        command.Parameters.AddWithValue("$document", JsonSerializer.SerializeToUtf8Bytes(baseline, JsonOptions));

        command.ExecuteNonQuery();
    }

    /// <summary>Loads every imported baseline for an assessment.</summary>
    public IReadOnlyList<ImportedBaseline> LoadBaselines(Guid assessmentId)
    {
        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = "SELECT document FROM imported_baseline WHERE assessment_id = $id ORDER BY imported_at;";
        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        var baselines = new List<ImportedBaseline>();

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            using var stream = reader.GetStream(0);
            var baseline = JsonSerializer.Deserialize<ImportedBaseline>(stream, JsonOptions);

            if (baseline is not null)
            {
                baselines.Add(baseline);
            }
        }

        return baselines;
    }

    /// <summary>Stores a report profile.</summary>
    public void SaveReportProfile(Guid assessmentId, ReportProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = """
            INSERT INTO report_profile (profile_id, assessment_id, name, document, updated_at)
            VALUES ($id, $assessment, $name, $document, $updated)
            ON CONFLICT(profile_id) DO UPDATE SET
                name = excluded.name, document = excluded.document, updated_at = excluded.updated_at;
            """;

        command.Parameters.AddWithValue("$id", profile.ProfileId);
        command.Parameters.AddWithValue("$assessment", assessmentId.ToString("n"));
        command.Parameters.AddWithValue("$name", profile.Name);
        command.Parameters.AddWithValue("$document", JsonSerializer.Serialize(profile, JsonOptions));
        command.Parameters.AddWithValue("$updated", DateTimeOffset.UtcNow.ToString("o"));

        command.ExecuteNonQuery();
    }

    /// <summary>Loads the report profiles defined for an assessment.</summary>
    public IReadOnlyList<ReportProfile> LoadReportProfiles(Guid assessmentId)
    {
        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = "SELECT document FROM report_profile WHERE assessment_id = $id ORDER BY name;";
        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        var profiles = new List<ReportProfile>();

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var profile = JsonSerializer.Deserialize<ReportProfile>(reader.GetString(0), JsonOptions);

            if (profile is not null)
            {
                profiles.Add(profile);
            }
        }

        return profiles;
    }

    /// <summary>Stores evidence records for the report's evidence appendix.</summary>
    public void SaveEvidenceRecords(Guid assessmentId, IReadOnlyCollection<EvidenceRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);

        using var connection = _store.OpenConnection();
        using var transaction = connection.BeginTransaction();

        foreach (var record in records)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;

            command.CommandText = """
                INSERT INTO evidence_record (evidence_id, assessment_id, kind, source, collector_id,
                                             collected_at, summary, sensitivity, payload, payload_sha256, attachment_id)
                VALUES ($id, $assessment, $kind, $source, $collector, $collected, $summary, $sensitivity,
                        $payload, $hash, $attachment)
                ON CONFLICT(evidence_id) DO UPDATE SET
                    summary = excluded.summary, payload = excluded.payload, payload_sha256 = excluded.payload_sha256;
                """;

            command.Parameters.AddWithValue("$id", record.EvidenceId);
            command.Parameters.AddWithValue("$assessment", assessmentId.ToString("n"));
            command.Parameters.AddWithValue("$kind", record.Kind.ToString());
            command.Parameters.AddWithValue("$source", record.Source.ToString());
            command.Parameters.AddWithValue("$collector", record.CollectorId);
            command.Parameters.AddWithValue("$collected", record.CollectedAt.ToString("o"));
            command.Parameters.AddWithValue("$summary", record.Summary);
            command.Parameters.AddWithValue("$sensitivity", (int)record.Sensitivity);
            command.Parameters.AddWithValue("$payload", (object?)record.Payload ?? DBNull.Value);
            command.Parameters.AddWithValue("$hash", (object?)record.PayloadSha256 ?? DBNull.Value);
            command.Parameters.AddWithValue("$attachment", (object?)record.AttachmentId ?? DBNull.Value);

            command.ExecuteNonQuery();
        }

        transaction.Commit();
    }

    /// <summary>Loads the evidence records for an assessment.</summary>
    public IReadOnlyList<EvidenceRecord> LoadEvidenceRecords(Guid assessmentId)
    {
        using var connection = _store.OpenConnection();
        using var command = connection.CreateCommand();

        command.CommandText = """
            SELECT evidence_id, kind, source, collector_id, collected_at, summary, sensitivity,
                   payload, payload_sha256, attachment_id
            FROM evidence_record WHERE assessment_id = $id ORDER BY evidence_id;
            """;

        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        var records = new List<EvidenceRecord>();

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            records.Add(new EvidenceRecord
            {
                EvidenceId = reader.GetString(0),
                Kind = Enum.Parse<EvidenceKind>(reader.GetString(1)),
                Source = Enum.Parse<Contracts.AssessmentSource>(reader.GetString(2)),
                CollectorId = reader.GetString(3),
                CollectedAt = DateTimeOffset.Parse(reader.GetString(4), System.Globalization.CultureInfo.InvariantCulture),
                Summary = reader.GetString(5),
                Sensitivity = (Contracts.Sensitivity)reader.GetInt32(6),
                Payload = reader.IsDBNull(7) ? null : reader.GetString(7),
                PayloadSha256 = reader.IsDBNull(8) ? null : reader.GetString(8),
                AttachmentId = reader.IsDBNull(9) ? null : reader.GetString(9),
            });
        }

        return records;
    }

    private static Dictionary<string, List<Attestation>> LoadAttestations(SqliteConnection connection, Guid assessmentId)
    {
        var byControl = new Dictionary<string, List<Attestation>>(StringComparer.OrdinalIgnoreCase);

        using var command = connection.CreateCommand();

        command.CommandText = """
            SELECT attestation_id, control_id, statement, attested_by, attested_at, attachment_ids, review_date
            FROM attestation WHERE assessment_id = $id ORDER BY attested_at;
            """;

        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var controlId = reader.GetString(1);

            if (!byControl.TryGetValue(controlId, out var list))
            {
                list = [];
                byControl[controlId] = list;
            }

            list.Add(new Attestation
            {
                AttestationId = reader.GetString(0),
                ControlId = controlId,
                Statement = reader.GetString(2),
                AttestedBy = reader.GetString(3),
                AttestedAt = DateTimeOffset.Parse(reader.GetString(4), System.Globalization.CultureInfo.InvariantCulture),
                AttachmentIds = JsonSerializer.Deserialize<List<string>>(reader.GetString(5), JsonOptions) ?? [],
                ReviewDate = reader.IsDBNull(6)
                    ? null
                    : DateTimeOffset.Parse(reader.GetString(6), System.Globalization.CultureInfo.InvariantCulture),
            });
        }

        return byControl;
    }

    private static long NextDiagnosticSequence(SqliteConnection connection, SqliteTransaction transaction, Guid assessmentId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COALESCE(MAX(sequence), 0) + 1 FROM collection_diagnostic WHERE assessment_id = $id;";
        command.Parameters.AddWithValue("$id", assessmentId.ToString("n"));

        return Convert.ToInt64(command.ExecuteScalar() ?? 1L, System.Globalization.CultureInfo.InvariantCulture);
    }
}
