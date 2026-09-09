using Ipa.Collectors.Entra.Graph;
using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Security;

namespace Ipa.Collectors.Entra.Collectors;

/// <summary>
/// Retrieves the Microsoft Secure Score snapshot.
/// </summary>
/// <remarks>
/// Retrieval needs a sensitive Graph permission and an appropriate directory role, so a refusal is
/// expected in many tenants and is recorded as a permission problem rather than an error. The score
/// is displayed as Microsoft's own metric and never blended into this product's posture score.
/// </remarks>
public sealed class SecureScoreCollector : ICollector
{
    private readonly GraphReadClient _graph;

    public SecureScoreCollector(GraphReadClient graph)
    {
        ArgumentNullException.ThrowIfNull(graph);
        _graph = graph;
    }

    /// <inheritdoc />
    public string CollectorId => "entra.secureScore";

    /// <inheritdoc />
    public string DisplayName => "Microsoft Secure Score";

    /// <inheritdoc />
    public AssessmentSource Source => AssessmentSource.Entra;

    /// <inheritdoc />
    public IReadOnlyList<CollectorPrerequisite> Prerequisites { get; } =
    [
        new("Security permission", "Consent for SecurityEvents.Read.All."),
        new("Directory role", "A role such as Security Reader on the signed-in account."),
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> RequiredPermissions { get; } = ["SecurityEvents.Read.All"];

    /// <inheritdoc />
    public IReadOnlyList<string> ProducedEvidenceKeys { get; } = [EvidenceKeys.EntraSecureScore];

    /// <inheritdoc />
    public IReadOnlyList<CheckGroup> SupportedGroups { get; } = [CheckGroup.EntraSecureScore];

    /// <inheritdoc />
    public bool AppliesTo(CollectionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.SelectedGroups.Contains(CheckGroup.EntraSecureScore);
    }

    /// <inheritdoc />
    public async Task<CollectionResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var builder = new CollectorResultBuilder(CollectorId, Source, context);

        try
        {
            builder.Progress("Secure Score", "Reading the most recent Secure Score snapshot");

            var (items, failure) = await _graph
                .TryEnumerateAsync("security/secureScores?$top=1", cancellationToken, maxItems: 1)
                .ConfigureAwait(false);

            if (failure is not null || items.Count == 0)
            {
                builder.MarkUnavailable(
                    EvidenceKeys.EntraSecureScore,
                    failure is null ? EvidenceAvailability.Unsupported : EntraDirectoryCollector.Classify(failure),
                    failure?.Message ??
                    "The tenant returned no Secure Score snapshot. Retrieval requires a sensitive " +
                    "permission and an appropriate directory role.");

                return builder.Build(CollectionOutcome.Failed, new EvidenceFragment());
            }

            var item = items[0];

            var snapshot = new SecureScoreSnapshot
            {
                CreatedDateTime = GraphJson.Timestamp(item, "createdDateTime") ?? context.ReferenceTime,
                CurrentScore = GraphJson.Number(item, "currentScore") ?? 0,
                MaxScore = GraphJson.Number(item, "maxScore") ?? 0,
                AzureTenantId = GraphJson.String(item, "azureTenantId"),
                Controls = GraphJson.Objects(item, "controlScores")
                    .Select(control => new SecureScoreControl
                    {
                        ControlName = GraphJson.String(control, "controlName") ?? "unknown",
                        Score = GraphJson.Number(control, "score") ?? 0,
                        State = GraphJson.String(control, "implementationStatus"),
                        Description = GraphJson.String(control, "description"),
                    })
                    .ToList(),
            };

            builder.MarkCollected(EvidenceKeys.EntraSecureScore);
            builder.AddRecord(
                "entra.secureScore",
                EvidenceKind.DirectoryQuery,
                $"Microsoft Secure Score {snapshot.CurrentScore:F0} of {snapshot.MaxScore:F0} " +
                $"as of {snapshot.CreatedDateTime:yyyy-MM-dd}. Reported separately from the posture score.");

            var existing = context.PreviousEvidence?.Entra;

            var fragment = existing is null
                ? new EvidenceFragment()
                : new EvidenceFragment { Entra = existing with { SecureScore = snapshot } };

            return builder.Build(CollectionOutcome.Succeeded, fragment);
        }
        catch (OperationCanceledException)
        {
            builder.Log(DiagnosticSeverity.Information, "Collection was cancelled by the operator.", "Cancelled");
            return builder.Build(CollectionOutcome.Cancelled, new EvidenceFragment());
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Error,
                $"Secure Score retrieval failed: {Redaction.Scrub(ex.Message)}",
                "CollectionFailed",
                ex);

            builder.MarkUnavailable(
                EvidenceKeys.EntraSecureScore,
                EvidenceAvailability.Error,
                "Secure Score retrieval failed.");

            return builder.Build(CollectionOutcome.Failed, new EvidenceFragment());
        }
    }
}
