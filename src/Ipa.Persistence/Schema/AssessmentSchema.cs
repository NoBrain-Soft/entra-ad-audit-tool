using Microsoft.Data.Sqlite;

namespace Ipa.Persistence.Schema;

/// <summary>
/// The assessment database schema and its migrations.
/// </summary>
/// <remarks>
/// The schema version is recorded both in the database and in a saved project's manifest. Opening a
/// project written by an older release applies the migrations between the two versions in order;
/// opening one written by a newer release is refused rather than attempted, because a forward
/// migration cannot be inferred.
/// </remarks>
public static class AssessmentSchema
{
    /// <summary>Current schema version.</summary>
    public const int CurrentVersion = 1;

    /// <summary>Ordered migrations, keyed by the version each one produces.</summary>
    private static readonly IReadOnlyDictionary<int, string> Migrations = new Dictionary<int, string>
    {
        [1] = """
            CREATE TABLE assessment (
                assessment_id       TEXT PRIMARY KEY NOT NULL,
                created_at          TEXT NOT NULL,
                reference_time      TEXT NOT NULL,
                state               TEXT NOT NULL,
                application_version TEXT NOT NULL,
                rule_pack_version   TEXT,
                metadata_json       TEXT NOT NULL,
                scope_json          TEXT NOT NULL
            );

            CREATE TABLE evidence_record (
                evidence_id   TEXT PRIMARY KEY NOT NULL,
                assessment_id TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE CASCADE,
                kind          TEXT NOT NULL,
                source        TEXT NOT NULL,
                collector_id  TEXT NOT NULL,
                collected_at  TEXT NOT NULL,
                summary       TEXT NOT NULL,
                sensitivity   INTEGER NOT NULL,
                payload       TEXT,
                payload_sha256 TEXT,
                attachment_id TEXT
            );

            CREATE INDEX idx_evidence_assessment ON evidence_record(assessment_id);

            CREATE TABLE normalised_evidence (
                assessment_id TEXT PRIMARY KEY NOT NULL REFERENCES assessment(assessment_id) ON DELETE CASCADE,
                document      BLOB NOT NULL,
                written_at    TEXT NOT NULL
            );

            CREATE TABLE rule_result (
                assessment_id TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE CASCADE,
                rule_id       TEXT NOT NULL,
                rule_version  INTEGER NOT NULL,
                status        TEXT NOT NULL,
                availability  TEXT,
                evaluated_at  TEXT NOT NULL,
                rationale     TEXT NOT NULL,
                detail_json   TEXT NOT NULL,
                PRIMARY KEY (assessment_id, rule_id)
            );

            CREATE TABLE finding_workflow (
                assessment_id TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE CASCADE,
                finding_id    TEXT NOT NULL,
                notes         TEXT,
                disposition   TEXT,
                justification TEXT,
                recorded_by   TEXT,
                recorded_at   TEXT,
                review_date   TEXT,
                PRIMARY KEY (assessment_id, finding_id)
            );

            CREATE TABLE control_assessment (
                assessment_id  TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE CASCADE,
                control_id     TEXT NOT NULL,
                is_applicable  INTEGER NOT NULL,
                status         TEXT NOT NULL,
                suggested      TEXT NOT NULL,
                operator_confirmed INTEGER NOT NULL,
                owner          TEXT,
                notes          TEXT,
                licensed_text  TEXT,
                mapped_rules   TEXT NOT NULL,
                evidence_refs  TEXT NOT NULL,
                attachment_ids TEXT NOT NULL,
                review_date    TEXT,
                updated_at     TEXT,
                PRIMARY KEY (assessment_id, control_id)
            );

            CREATE TABLE attestation (
                attestation_id TEXT PRIMARY KEY NOT NULL,
                assessment_id  TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE CASCADE,
                control_id     TEXT NOT NULL,
                statement      TEXT NOT NULL,
                attested_by    TEXT NOT NULL,
                attested_at    TEXT NOT NULL,
                attachment_ids TEXT NOT NULL,
                review_date    TEXT
            );

            CREATE TABLE collection_diagnostic (
                assessment_id TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE CASCADE,
                sequence      INTEGER NOT NULL,
                timestamp     TEXT NOT NULL,
                severity      TEXT NOT NULL,
                collector_id  TEXT NOT NULL,
                message       TEXT NOT NULL,
                code          TEXT,
                exception_type TEXT,
                attempt       INTEGER NOT NULL,
                PRIMARY KEY (assessment_id, sequence)
            );

            CREATE TABLE imported_baseline (
                baseline_id   TEXT PRIMARY KEY NOT NULL,
                assessment_id TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE CASCADE,
                file_name     TEXT NOT NULL,
                package_sha256 TEXT NOT NULL,
                product_name  TEXT NOT NULL,
                baseline_version TEXT NOT NULL,
                imported_at   TEXT NOT NULL,
                document      BLOB NOT NULL
            );

            CREATE TABLE report_profile (
                profile_id    TEXT PRIMARY KEY NOT NULL,
                assessment_id TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE CASCADE,
                name          TEXT NOT NULL,
                document      TEXT NOT NULL,
                updated_at    TEXT NOT NULL
            );
            """,
    };

    /// <summary>Creates or upgrades the schema in an open connection.</summary>
    public static void Initialise(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var current = ReadVersion(connection);

        if (current > CurrentVersion)
        {
            throw new InvalidOperationException(
                $"The assessment database uses schema version {current}, which this release " +
                $"(schema version {CurrentVersion}) cannot read. Open the project with the release " +
                "that produced it.");
        }

        for (var version = current + 1; version <= CurrentVersion; version++)
        {
            if (!Migrations.TryGetValue(version, out var script))
            {
                throw new InvalidOperationException($"No migration is defined for schema version {version}.");
            }

            using var transaction = connection.BeginTransaction();

            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = script;
                command.ExecuteNonQuery();
            }

            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = $"PRAGMA user_version = {version};";
                command.ExecuteNonQuery();
            }

            transaction.Commit();
        }
    }

    /// <summary>Reads the schema version recorded in a database.</summary>
    public static int ReadVersion(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";

        return Convert.ToInt32(command.ExecuteScalar() ?? 0, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Checks whether a project's recorded schema version can be opened by this release, returning
    /// the reason when it cannot.
    /// </summary>
    public static bool CanOpen(int schemaVersion, out string? reason)
    {
        if (schemaVersion > CurrentVersion)
        {
            reason = $"The project uses schema version {schemaVersion}; this release supports up to " +
                     $"version {CurrentVersion}.";
            return false;
        }

        if (schemaVersion < 1)
        {
            reason = "The project declares an invalid schema version.";
            return false;
        }

        reason = null;
        return true;
    }
}
