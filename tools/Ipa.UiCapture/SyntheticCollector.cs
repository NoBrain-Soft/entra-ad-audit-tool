using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;
using Ipa.Core.Tests.Fixtures;

namespace Ipa.UiCapture;

/// <summary>
/// Supplies the synthetic environment through the ordinary collection pipeline, so the screens
/// that show evaluated content are filled the way a real run fills them.
/// </summary>
internal sealed class SyntheticCollector : ICollector
{
    /// <inheritdoc />
    public string CollectorId => "capture.synthetic";

    /// <inheritdoc />
    public string DisplayName => "Synthetic environment";

    /// <inheritdoc />
    public AssessmentSource Source => AssessmentSource.ActiveDirectory;

    /// <inheritdoc />
    public IReadOnlyList<CollectorPrerequisite> Prerequisites => [];

    /// <inheritdoc />
    public IReadOnlyList<string> RequiredPermissions => [];

    /// <inheritdoc />
    public IReadOnlyList<string> ProducedEvidenceKeys => EvidenceKeys.All;

    /// <inheritdoc />
    public IReadOnlyList<CheckGroup> SupportedGroups => Enum.GetValues<CheckGroup>();

    /// <inheritdoc />
    public bool AppliesTo(CollectionContext context) => true;

    /// <inheritdoc />
    public Task<CollectionResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken)
    {
        var builder = new CollectorResultBuilder(CollectorId, Source, context);

        foreach (var key in EvidenceKeys.All)
        {
            builder.MarkCollected(key);
        }

        return Task.FromResult(builder.Build(
            CollectionOutcome.Succeeded,
            new EvidenceFragment
            {
                ActiveDirectory = SyntheticEnvironment.WeakForest(),
                Entra = SyntheticEnvironment.WeakTenant(),
            }));
    }
}
