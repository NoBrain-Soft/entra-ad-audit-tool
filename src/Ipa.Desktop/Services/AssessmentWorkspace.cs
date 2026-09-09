using Ipa.Compliance;
using Ipa.Compliance.Catalogue;
using Ipa.Contracts;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Compliance;
using Ipa.Contracts.Reporting;
using Ipa.Core.Assessment;
using Ipa.Core.Collection;
using Ipa.Core.Projects;
using Ipa.Persistence;
using Ipa.Persistence.Session;
using Ipa.Reporting.Model;
using Ipa.Reporting.Pdf;

namespace Ipa.Desktop.Services;

/// <summary>
/// Holds everything the desktop application works on for one assessment: the ephemeral encrypted
/// session, the current assessment state and the services that act on it.
/// </summary>
/// <remarks>
/// The workspace owns the ephemeral store, so disposing it deletes the working database. Nothing
/// here survives the process unless the operator explicitly saves a project.
/// </remarks>
public sealed class AssessmentWorkspace : IDisposable
{
    private readonly AssessmentService _service = new();
    private readonly ProjectService _projects = new();
    private EphemeralSessionStore? _store;
    private AssessmentRepository? _repository;

    /// <summary>The assessment currently open, or null when none has been created.</summary>
    public AssessmentSession? Session { get; private set; }

    /// <summary>The compliance workspace for the open assessment.</summary>
    public ComplianceWorkspace Compliance { get; private set; } = new();

    /// <summary>The report profile the operator has configured.</summary>
    public ReportProfile ReportProfile { get; set; } = new()
    {
        ProfileId = Guid.NewGuid().ToString("n"),
        Name = "Default report",
    };

    /// <summary>Path of the project file this assessment was opened from or last saved to.</summary>
    public string? ProjectPath { get; private set; }

    /// <summary>The rule pack version every score in this workspace is tied to.</summary>
    public string RulePackVersion => _service.RulePackVersion;

    /// <summary>True when an assessment is open.</summary>
    public bool HasSession => Session is not null;

    /// <summary>Creates a new assessment and its ephemeral encrypted session.</summary>
    public AssessmentSession CreateAssessment(AssessmentMetadata metadata, AssessmentScope scope)
    {
        DisposeSessionStore();

        var session = AssessmentService.CreateSession(metadata, scope, DateTimeOffset.UtcNow);

        _store = EphemeralSessionStore.Create(session.AssessmentId);
        _repository = new AssessmentRepository(_store);
        _repository.SaveAssessment(session);

        Session = session;
        Compliance = new ComplianceWorkspace();
        ProjectPath = null;

        return session;
    }

    /// <summary>Runs collection for the open assessment.</summary>
    public async Task CollectAsync(
        IReadOnlyList<CollectionStage> stages,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var session = RequireSession();

        Session = await _service.CollectAsync(session, stages, progress, cancellationToken).ConfigureAwait(false);

        Persist();
    }

    /// <summary>Reruns the collectors the operator selected, keeping results that succeeded.</summary>
    public async Task RerunAsync(
        IReadOnlyList<ICollector> collectors,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        var session = RequireSession();

        Session = await _service.RerunAsync(session, collectors, progress, cancellationToken).ConfigureAwait(false);

        Persist();
    }

    /// <summary>Evaluates the rule pack and refreshes findings, scores and the compliance mapping.</summary>
    public EvaluationOutcome Evaluate()
    {
        var session = RequireSession();
        var (notes, exceptions) = _repository?.LoadFindingWorkflow(session.AssessmentId) ?? ([], []);

        var outcome = _service.Evaluate(
            session,
            notes,
            exceptions,
            Compliance.Assessments);

        Session = AssessmentService.Apply(session, outcome, _service.RulePackVersion);
        Compliance = outcome.Compliance;

        Persist();

        return outcome;
    }

    /// <summary>Records the operator's disposition for a finding. The raw score is unchanged.</summary>
    public void RecordFindingDisposition(
        string findingId,
        string? notes,
        Contracts.Findings.FindingException? exception)
    {
        var session = RequireSession();
        _repository?.SaveFindingWorkflow(session.AssessmentId, findingId, notes, exception);
    }

    /// <summary>Records the operator's judgement for a compliance control.</summary>
    public void RecordControlStatus(string controlId, ControlStatus status, string recordedBy, string? notes)
    {
        Compliance.RecordStatus(controlId, status, recordedBy, DateTimeOffset.UtcNow, notes);

        if (Session is { } session)
        {
            Session = session with { ControlAssessments = Compliance.Assessments };
            _repository?.SaveControlAssessments(session.AssessmentId, Compliance.Assessments);
        }
    }

    /// <summary>Builds the report model for the current state.</summary>
    public ReportModel BuildReportModel(IReadOnlyList<string>? acceptedExceptions = null)
    {
        var session = RequireSession();

        return ReportModelBuilder.Build(
            session,
            ReportProfile,
            Compliance.ComputeMetrics(),
            IsoControlCatalogue.All,
            DateTimeOffset.UtcNow,
            Rules.Engine.FirstPartyRulePack.Current.Definitions,
            acceptedExceptions);
    }

    /// <summary>Generates the report to a file.</summary>
    public async Task GenerateReportAsync(string outputPath, CancellationToken cancellationToken)
    {
        var model = BuildReportModel();
        await new ReportGenerator().GenerateAsync(model, outputPath, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Saves the assessment to an encrypted project container.</summary>
    public void SaveProject(string filePath, ReadOnlySpan<char> passphrase, string? label = null)
    {
        var session = RequireSession();

        if (_store is null)
        {
            throw new InvalidOperationException("There is no open session to save.");
        }

        Persist();
        _projects.Save(session, _store, filePath, passphrase, attachments: null, label);
        ProjectPath = filePath;
    }

    /// <summary>Opens an encrypted project into a fresh ephemeral session.</summary>
    public void OpenProject(string filePath, ReadOnlySpan<char> passphrase)
    {
        var opened = _projects.Open(filePath, passphrase);

        DisposeSessionStore();

        _store = opened.Store;
        _repository = new AssessmentRepository(_store);

        Session = ProjectService.Rehydrate(_repository, opened.Manifest);
        Compliance = new ComplianceWorkspace(Session.ControlAssessments);
        ReportProfile = Session.ReportProfile ?? ReportProfile;
        ProjectPath = filePath;
    }

    /// <summary>Closes the assessment and deletes its ephemeral session.</summary>
    public void CloseAssessment()
    {
        DisposeSessionStore();
        Session = null;
        Compliance = new ComplianceWorkspace();
        ProjectPath = null;
    }

    /// <summary>Sessions left behind by a previous run that the operator may clean up.</summary>
    public static IReadOnlyList<CrashRecovery.StaleSession> FindStaleSessions() =>
        CrashRecovery.FindStaleSessions();

    /// <summary>Deletes a stale session directory.</summary>
    public static bool CleanupStaleSession(string directory) => CrashRecovery.Cleanup(directory);

    private void Persist()
    {
        if (Session is not { } session || _repository is null)
        {
            return;
        }

        _repository.SaveAssessment(session);

        if (session.Evidence is { } evidence)
        {
            _repository.SaveEvidence(session.AssessmentId, evidence);
            _repository.SaveEvidenceRecords(session.AssessmentId, evidence.Records);
        }

        if (session.RuleResults.Count > 0)
        {
            _repository.SaveRuleResults(session.AssessmentId, session.RuleResults);
        }

        if (session.ControlAssessments.Count > 0)
        {
            _repository.SaveControlAssessments(session.AssessmentId, session.ControlAssessments);
        }

        if (session.Diagnostics.Count > 0)
        {
            _repository.AppendDiagnostics(session.AssessmentId, session.Diagnostics);
        }

        if (session.Baseline is { } baseline)
        {
            _repository.SaveBaseline(session.AssessmentId, baseline);
        }

        _repository.SaveReportProfile(session.AssessmentId, ReportProfile);
    }

    private AssessmentSession RequireSession() =>
        Session ?? throw new InvalidOperationException("No assessment is open.");

    private void DisposeSessionStore()
    {
        _store?.Dispose();
        _store = null;
        _repository = null;
    }

    /// <inheritdoc />
    public void Dispose() => DisposeSessionStore();
}
