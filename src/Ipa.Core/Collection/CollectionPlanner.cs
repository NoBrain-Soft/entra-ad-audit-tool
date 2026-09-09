using Ipa.Collectors.ActiveDirectory.Collectors;
using Ipa.Collectors.Entra.Collectors;
using Ipa.Collectors.Entra.Graph;
using Ipa.Collectors.Hybrid;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Collection;

namespace Ipa.Core.Collection;

/// <summary>
/// Builds the ordered stages a collection run executes.
/// </summary>
/// <remarks>
/// Ordering encodes the real dependencies: the directory and the tenant are read first because
/// everything else builds on them, source-specific enrichment follows, and hybrid correlation runs
/// last because it needs both. Collectors reading one source share an evidence fragment, so the
/// pipeline runs them in sequence; the two sources proceed in parallel.
/// </remarks>
public static class CollectionPlanner
{
    /// <summary>Builds the stages for a scope, given whichever sources are connected.</summary>
    /// <param name="scope">The assessment scope.</param>
    /// <param name="directorySession">An open directory session, or null when no forest is connected.</param>
    /// <param name="graph">An authenticated Graph client, or null when no tenant is connected.</param>
    public static IReadOnlyList<CollectionStage> Build(
        AssessmentScope scope,
        DirectorySession? directorySession,
        GraphReadClient? graph)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var discovery = new List<ICollector>();
        var enrichment = new List<ICollector>();
        var correlation = new List<ICollector>();

        if (scope.IncludeActiveDirectory && directorySession is not null)
        {
            discovery.Add(new DirectoryCollector(directorySession));
            enrichment.Add(new GroupPolicyCollector(directorySession));
            enrichment.Add(new CertificateServicesCollector(directorySession));
        }

        if (scope.IncludeEntra && graph is not null)
        {
            discovery.Add(new EntraDirectoryCollector(graph));
            enrichment.Add(new EntraPolicyCollector(graph));
            enrichment.Add(new EntraApplicationCollector(graph));
            enrichment.Add(new SecureScoreCollector(graph));
        }

        if (scope.IncludeHybrid && directorySession is not null && graph is not null)
        {
            correlation.Add(new HybridCollector());
        }

        var stages = new List<CollectionStage>();

        if (discovery.Count > 0)
        {
            stages.Add(new CollectionStage("Discovery", discovery));
        }

        if (enrichment.Count > 0)
        {
            stages.Add(new CollectionStage("Detail", enrichment));
        }

        if (correlation.Count > 0)
        {
            stages.Add(new CollectionStage("Correlation", correlation));
        }

        return stages;
    }

    /// <summary>
    /// Describes the collectors a scope would run, so the interface can show the plan before any
    /// connection is made.
    /// </summary>
    public static IReadOnlyList<(string Stage, string CollectorId, string DisplayName)> Describe(AssessmentScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var plan = new List<(string, string, string)>();

        if (scope.IncludeActiveDirectory)
        {
            plan.Add(("Discovery", "ad.directory", "Active Directory forest, domains and principals"));
            plan.Add(("Detail", "ad.groupPolicy", "Group Policy objects and SYSVOL content"));
            plan.Add(("Detail", "ad.certificateServices", "Certificate templates and enrolment services"));
        }

        if (scope.IncludeEntra)
        {
            plan.Add(("Discovery", "entra.directory", "Entra tenant, users, groups, devices and roles"));
            plan.Add(("Detail", "entra.policy", "Conditional Access and authentication policy"));
            plan.Add(("Detail", "entra.applications", "Application registrations, service principals and consent"));
            plan.Add(("Detail", "entra.secureScore", "Microsoft Secure Score"));
        }

        if (scope.IncludeHybrid)
        {
            plan.Add(("Correlation", "hybrid.correlation", "Hybrid identity correlation"));
        }

        return plan;
    }
}
