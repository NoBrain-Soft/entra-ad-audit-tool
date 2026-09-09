using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;
using Ipa.Core.Collection;
using Ipa.Core.Tests.Fixtures;
using Xunit;

namespace Ipa.Core.Tests;

/// <summary>
/// Tests for the collection pipeline: ordering, cancellation, partial failure and rerunning a
/// failed collector without discarding the results that succeeded.
/// </summary>
public sealed class CollectionPipelineTests
{
    private static CollectionContext Context() => new()
    {
        AssessmentId = Guid.NewGuid(),
        ReferenceTime = SyntheticEnvironment.Reference,
        SelectedGroups = Enum.GetValues<CheckGroup>(),
    };

    /// <summary>A collector whose behaviour the test controls.</summary>
    private sealed class FakeCollector : ICollector
    {
        private readonly Func<CollectionContext, CancellationToken, Task<CollectionResult>> _behaviour;

        public FakeCollector(
            string id,
            AssessmentSource source,
            string[] evidenceKeys,
            Func<CollectionContext, CancellationToken, Task<CollectionResult>> behaviour)
        {
            CollectorId = id;
            Source = source;
            ProducedEvidenceKeys = evidenceKeys;
            _behaviour = behaviour;
        }

        public string CollectorId { get; }
        public string DisplayName => CollectorId;
        public AssessmentSource Source { get; }
        public IReadOnlyList<CollectorPrerequisite> Prerequisites => [];
        public IReadOnlyList<string> RequiredPermissions => [];
        public IReadOnlyList<string> ProducedEvidenceKeys { get; }
        public IReadOnlyList<CheckGroup> SupportedGroups => Enum.GetValues<CheckGroup>();
        public bool Applies { get; init; } = true;

        public bool AppliesTo(CollectionContext context) => Applies;

        public Task<CollectionResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken) =>
            _behaviour(context, cancellationToken);
    }

    private static CollectionResult Success(string id, string evidenceKey, EvidenceFragment? fragment = null) => new()
    {
        CollectorId = id,
        Outcome = CollectionOutcome.Succeeded,
        StartedAt = SyntheticEnvironment.Reference,
        CompletedAt = SyntheticEnvironment.Reference,
        Availability =
        [
            new EvidenceAvailabilityEntry { EvidenceKey = evidenceKey, Availability = EvidenceAvailability.Collected },
        ],
        Fragment = fragment ?? new EvidenceFragment(),
    };

    [Fact]
    public async Task StagesRunInOrderAndLaterStagesSeeEarlierEvidence()
    {
        var order = new List<string>();
        NormalizedEvidence? seenBySecond = null;

        var first = new FakeCollector("first", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdUsers],
            (_, _) =>
            {
                order.Add("first");
                return Task.FromResult(Success("first", EvidenceKeys.AdUsers, new EvidenceFragment
                {
                    ActiveDirectory = SyntheticEnvironment.HealthyForest(),
                }));
            });

        var second = new FakeCollector("second", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdGroupPolicy],
            (context, _) =>
            {
                order.Add("second");
                seenBySecond = context.PreviousEvidence;
                return Task.FromResult(Success("second", EvidenceKeys.AdGroupPolicy));
            });

        var run = await new CollectionPipeline().RunAsync(
            [new CollectionStage("One", [first]), new CollectionStage("Two", [second])],
            Context(),
            CancellationToken.None);

        Assert.Equal(["first", "second"], order);
        Assert.NotNull(seenBySecond?.ActiveDirectory);
        Assert.Equal(2, run.Results.Count);
    }

    [Fact]
    public async Task CollectorsOfTheSameSourceRunSequentially()
    {
        var concurrent = 0;
        var maximumConcurrent = 0;
        var gate = new Lock();

        Func<CollectionContext, CancellationToken, Task<CollectionResult>> behaviour(string id) =>
            async (_, token) =>
            {
                lock (gate)
                {
                    concurrent++;
                    maximumConcurrent = Math.Max(maximumConcurrent, concurrent);
                }

                await Task.Delay(20, token);

                lock (gate)
                {
                    concurrent--;
                }

                return Success(id, EvidenceKeys.AdUsers);
            };

        var collectors = new ICollector[]
        {
            new FakeCollector("a", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdUsers], behaviour("a")),
            new FakeCollector("b", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdGroups], behaviour("b")),
            new FakeCollector("c", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdAcls], behaviour("c")),
        };

        await new CollectionPipeline().RunAsync(
            [new CollectionStage("Stage", collectors)],
            Context(),
            CancellationToken.None);

        Assert.Equal(1, maximumConcurrent);
    }

    [Fact]
    public async Task DifferentSourcesRunInParallel()
    {
        var started = new List<string>();
        var barrier = new SemaphoreSlim(0);

        var activeDirectory = new FakeCollector("ad", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdUsers],
            async (_, token) =>
            {
                lock (started)
                {
                    started.Add("ad");
                }

                await barrier.WaitAsync(token);
                return Success("ad", EvidenceKeys.AdUsers);
            });

        var entra = new FakeCollector("entra", AssessmentSource.Entra, [EvidenceKeys.EntraUsers],
            (_, _) =>
            {
                lock (started)
                {
                    started.Add("entra");
                }

                barrier.Release();
                return Task.FromResult(Success("entra", EvidenceKeys.EntraUsers));
            });

        var run = await new CollectionPipeline().RunAsync(
            [new CollectionStage("Stage", [activeDirectory, entra])],
            Context(),
            CancellationToken.None);

        // The Active Directory collector only completes because the Entra collector ran alongside
        // it and released the barrier.
        Assert.Equal(2, run.Results.Count);
    }

    [Fact]
    public async Task AFailingCollectorDoesNotStopTheRun()
    {
        var failing = new FakeCollector("failing", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdAcls],
            (_, _) => throw new InvalidOperationException("the directory refused the request"));

        var succeeding = new FakeCollector("succeeding", AssessmentSource.Entra, [EvidenceKeys.EntraUsers],
            (_, _) => Task.FromResult(Success("succeeding", EvidenceKeys.EntraUsers)));

        var run = await new CollectionPipeline().RunAsync(
            [new CollectionStage("Stage", [failing, succeeding])],
            Context(),
            CancellationToken.None);

        Assert.Equal(2, run.Results.Count);
        Assert.Equal("failing", Assert.Single(run.FailedCollectorIds));

        // The failed collector's evidence is marked errored, so rules that need it report as not
        // collected rather than passing on absent data.
        Assert.Equal(EvidenceAvailability.Error, run.Evidence.GetAvailability(EvidenceKeys.AdAcls).Availability);
        Assert.True(run.Evidence.GetAvailability(EvidenceKeys.EntraUsers).IsAvailable);
    }

    [Fact]
    public async Task AThrownExceptionIsNeverReportedAsSuccess()
    {
        var failing = new FakeCollector("boom", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdUsers],
            (_, _) => throw new TimeoutException("the server did not respond"));

        var run = await new CollectionPipeline().RunAsync(
            [new CollectionStage("Stage", [failing])],
            Context(),
            CancellationToken.None);

        var result = Assert.Single(run.Results);
        Assert.Equal(CollectionOutcome.Failed, result.Outcome);
        Assert.Contains(run.Diagnostics, diagnostic => diagnostic.ExceptionType == nameof(TimeoutException));
    }

    [Fact]
    public async Task CancellationStopsTheRunAndIsReported()
    {
        using var cancellation = new CancellationTokenSource();

        var first = new FakeCollector("first", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdUsers],
            (_, _) =>
            {
                cancellation.Cancel();
                return Task.FromResult(Success("first", EvidenceKeys.AdUsers));
            });

        var second = new FakeCollector("second", AssessmentSource.Entra, [EvidenceKeys.EntraUsers],
            (_, _) => Task.FromResult(Success("second", EvidenceKeys.EntraUsers)));

        var run = await new CollectionPipeline().RunAsync(
            [new CollectionStage("One", [first]), new CollectionStage("Two", [second])],
            Context(),
            cancellation.Token);

        Assert.True(run.WasCancelled);
        Assert.DoesNotContain(run.Results, result => result.CollectorId == "second");
    }

    [Fact]
    public async Task InapplicableCollectorsAreSkippedWithAReason()
    {
        var skipped = new FakeCollector("skipped", AssessmentSource.Hybrid, [EvidenceKeys.HybridMatches],
            (_, _) => Task.FromResult(Success("skipped", EvidenceKeys.HybridMatches)))
        {
            Applies = false,
        };

        var run = await new CollectionPipeline().RunAsync(
            [new CollectionStage("Stage", [skipped])],
            Context(),
            CancellationToken.None);

        var result = Assert.Single(run.Results);
        Assert.Equal(CollectionOutcome.Skipped, result.Outcome);
        Assert.Equal(
            EvidenceAvailability.NotSelected,
            run.Evidence.GetAvailability(EvidenceKeys.HybridMatches).Availability);
    }

    [Fact]
    public async Task RerunningAFailedCollectorRestoresCoverageWithoutLosingOtherResults()
    {
        var attempt = 0;

        var flaky = new FakeCollector("flaky", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdAcls],
            (_, _) =>
            {
                attempt++;

                return attempt == 1
                    ? throw new InvalidOperationException("transient failure")
                    : Task.FromResult(Success("flaky", EvidenceKeys.AdAcls));
            });

        var stable = new FakeCollector("stable", AssessmentSource.Entra, [EvidenceKeys.EntraUsers],
            (_, _) => Task.FromResult(Success("stable", EvidenceKeys.EntraUsers)));

        var pipeline = new CollectionPipeline();
        var context = Context();

        var first = await pipeline.RunAsync(
            [new CollectionStage("Stage", [flaky, stable])],
            context,
            CancellationToken.None);

        Assert.Single(first.FailedCollectorIds);

        var second = await pipeline.RerunAsync(
            [flaky],
            first.Evidence,
            first.Results,
            context,
            CancellationToken.None);

        Assert.Empty(second.FailedCollectorIds);
        Assert.Equal(2, second.Results.Count);
        Assert.True(second.Evidence.GetAvailability(EvidenceKeys.AdAcls).IsAvailable);

        // The result that already succeeded is preserved rather than re-collected.
        Assert.Contains(second.Results, result => result.CollectorId == "stable");
        Assert.True(second.Evidence.GetAvailability(EvidenceKeys.EntraUsers).IsAvailable);
    }

    [Fact]
    public async Task EvidenceRecordsAreDeduplicatedByIdentifier()
    {
        var record = new EvidenceRecord
        {
            EvidenceId = "ad.users",
            Kind = EvidenceKind.DirectoryQuery,
            Source = AssessmentSource.ActiveDirectory,
            CollectorId = "ad",
            CollectedAt = SyntheticEnvironment.Reference,
            Summary = "first",
        };

        var collector = new FakeCollector("ad", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdUsers],
            (_, _) => Task.FromResult(Success("ad", EvidenceKeys.AdUsers) with
            {
                Records = [record, record with { Summary = "second" }],
            }));

        var run = await new CollectionPipeline().RunAsync(
            [new CollectionStage("Stage", [collector])],
            Context(),
            CancellationToken.None);

        var stored = Assert.Single(run.Evidence.Records);
        Assert.Equal("second", stored.Summary);
    }

    [Fact]
    public async Task ProgressIsReportedToTheSuppliedSink()
    {
        var reported = new List<CollectionProgress>();

        var collector = new FakeCollector("ad", AssessmentSource.ActiveDirectory, [EvidenceKeys.AdUsers],
            (context, _) =>
            {
                context.Report(new CollectionProgress
                {
                    CollectorId = "ad",
                    StageName = "Users",
                    Activity = "Reading accounts",
                    Completed = 50,
                    Total = 100,
                });

                return Task.FromResult(Success("ad", EvidenceKeys.AdUsers));
            });

        var context = Context() with
        {
            Progress = new Progress<CollectionProgress>(progress =>
            {
                lock (reported)
                {
                    reported.Add(progress);
                }
            }),
        };

        await new CollectionPipeline().RunAsync(
            [new CollectionStage("Stage", [collector])],
            context,
            CancellationToken.None);

        // Progress is marshalled asynchronously, so allow the callback to run.
        await Task.Delay(100);

        var progress = Assert.Single(reported);
        Assert.Equal(0.5, progress.Fraction);
    }
}
