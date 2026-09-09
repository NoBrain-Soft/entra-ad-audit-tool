using System.DirectoryServices.Protocols;
using Ipa.Collectors.ActiveDirectory.Discovery;
using Ipa.Collectors.ActiveDirectory.Normalisation;
using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects the directory itself: forest and domain configuration, controllers, sites, trusts,
/// principals and the access-control entries on tier-zero objects.
/// </summary>
/// <remarks>
/// Every operation is a search. The collector issues no write of any kind, and requests only the
/// discretionary part of a security descriptor so that it needs no auditing privilege.
/// </remarks>
public sealed class DirectoryCollector : ICollector
{
    private readonly DirectorySession _session;

    public DirectoryCollector(DirectorySession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        _session = session;
    }

    /// <inheritdoc />
    public string CollectorId => "ad.directory";

    /// <inheritdoc />
    public string DisplayName => "Active Directory forest, domains and principals";

    /// <inheritdoc />
    public AssessmentSource Source => AssessmentSource.ActiveDirectory;

    /// <inheritdoc />
    public IReadOnlyList<CollectorPrerequisite> Prerequisites { get; } =
    [
        new("Directory connectivity", "A reachable domain controller on LDAP port 389 or 636."),
        new("Read access", "An account able to read the directory; no write access is used."),
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> RequiredPermissions { get; } =
    [
        "Read access to the domain, configuration and schema partitions",
        "Read access to the discretionary security descriptor of tier-zero objects",
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> ProducedEvidenceKeys { get; } =
    [
        EvidenceKeys.AdForest, EvidenceKeys.AdDomains, EvidenceKeys.AdUsers, EvidenceKeys.AdComputers,
        EvidenceKeys.AdGroups, EvidenceKeys.AdAcls, EvidenceKeys.AdTrusts, EvidenceKeys.AdSites,
        EvidenceKeys.AdPasswordPolicy,
    ];

    /// <inheritdoc />
    public IReadOnlyList<CheckGroup> SupportedGroups { get; } =
    [
        CheckGroup.AdPrivilegedAccess, CheckGroup.AdAccountHygiene, CheckGroup.AdDelegationAndAcl,
        CheckGroup.AdDomainPolicy, CheckGroup.AdTrustsAndTopology,
    ];

    /// <inheritdoc />
    public bool AppliesTo(CollectionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.SelectedGroups.Any(SupportedGroups.Contains);
    }

    /// <inheritdoc />
    public Task<CollectionResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var builder = new CollectorResultBuilder(CollectorId, Source, context);

        foreach (var observation in _session.CertificateObservations)
        {
            builder.Log(DiagnosticSeverity.Warning, observation, "CertificateValidation");
        }

        try
        {
            var evidence = Collect(builder, context, cancellationToken);

            return Task.FromResult(builder.Build(
                builder.DetermineOutcome(),
                new EvidenceFragment { ActiveDirectory = evidence }));
        }
        catch (OperationCanceledException)
        {
            builder.Log(DiagnosticSeverity.Information, "Collection was cancelled by the operator.", "Cancelled");
            return Task.FromResult(builder.Build(CollectionOutcome.Cancelled, new EvidenceFragment()));
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Error,
                $"Directory collection failed: {Connection.LdapDirectoryReader.DescribeFailure(ex)}",
                "CollectionFailed",
                ex);

            foreach (var key in ProducedEvidenceKeys)
            {
                builder.MarkUnavailable(key, EvidenceAvailability.Error, "Directory collection failed.");
            }

            return Task.FromResult(builder.Build(CollectionOutcome.Failed, new EvidenceFragment()));
        }
    }

    private ActiveDirectoryEvidence Collect(
        CollectorResultBuilder builder,
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        var reader = _session.Reader;

        builder.Progress("Forest", "Reading forest configuration");

        var schemaVersion = ReadSchemaVersion(builder, cancellationToken);
        var upnSuffixes = ReadUpnSuffixes(builder, cancellationToken);
        var forest = _session.BuildForestSummary(schemaVersion, upnSuffixes);
        builder.MarkCollected(EvidenceKeys.AdForest);
        builder.AddRecord(
            "ad.forest",
            EvidenceKind.DirectoryQuery,
            $"Forest {forest.ForestRootDomain}, functional level {forest.ForestFunctionalLevel}, " +
            $"schema version {forest.SchemaVersion}");

        builder.Progress("Domains", "Enumerating domains");
        var domains = CollectDomains(builder, cancellationToken);
        builder.MarkCollected(EvidenceKeys.AdDomains);
        builder.MarkCollected(EvidenceKeys.AdPasswordPolicy);

        builder.Progress("Topology", "Enumerating sites and domain controllers");
        var controllers = CollectDomainControllers(builder, cancellationToken);
        var sites = CollectSites(builder, controllers, cancellationToken);
        builder.MarkCollected(EvidenceKeys.AdSites);

        builder.Progress("Trusts", "Enumerating trusts");
        var trusts = CollectTrusts(builder, domains, cancellationToken);
        builder.MarkCollected(EvidenceKeys.AdTrusts);

        var users = new List<AdPrincipal>();
        var computers = new List<AdComputer>();
        var groups = new List<AdGroup>();
        var controllerDns = controllers.Select(controller => controller.DnsHostName).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var domain in domains)
        {
            cancellationToken.ThrowIfCancellationRequested();

            builder.Progress("Principals", $"Reading accounts in {domain.DnsName}");

            users.AddRange(reader
                .Search(domain.DistinguishedName, "(&(objectCategory=person)(objectClass=user))",
                    DirectoryObjectNormaliser.UserAttributes, cancellationToken)
                .Select(entry => DirectoryObjectNormaliser.ToPrincipal(entry, domain.DomainSid, domain.DnsName))
                .Where(principal => principal is not null)
                .Select(principal => principal!));

            computers.AddRange(reader
                .Search(domain.DistinguishedName, "(objectClass=computer)",
                    DirectoryObjectNormaliser.ComputerAttributes, cancellationToken)
                .Select(entry => DirectoryObjectNormaliser.ToComputer(entry, controllerDns))
                .Where(computer => computer is not null)
                .Select(computer => computer!));

            groups.AddRange(reader
                .Search(domain.DistinguishedName, "(objectClass=group)",
                    DirectoryObjectNormaliser.GroupAttributes, cancellationToken)
                .Select(entry => DirectoryObjectNormaliser.ToGroup(entry, domain.DomainSid))
                .Where(group => group is not null)
                .Select(group => group!));
        }

        builder.MarkCollected(EvidenceKeys.AdUsers);
        builder.MarkCollected(EvidenceKeys.AdComputers);
        builder.MarkCollected(EvidenceKeys.AdGroups);
        builder.AddRecord(
            "ad.principals",
            EvidenceKind.DirectoryQuery,
            $"{users.Count} user account(s), {computers.Count} computer account(s) and {groups.Count} group(s)");

        builder.Progress("Access control", "Reading security descriptors on tier-zero objects");
        var acls = CollectAccessControlEntries(builder, domains, users, groups, cancellationToken);

        return new ActiveDirectoryEvidence
        {
            Forest = forest,
            Domains = domains,
            DomainControllers = controllers,
            Sites = sites,
            Trusts = trusts,
            Users = users,
            Computers = computers,
            Groups = groups,
            AccessControlEntries = acls,
            ReferenceTime = context.ReferenceTime,
        };
    }

    private int ReadSchemaVersion(CollectorResultBuilder builder, CancellationToken cancellationToken)
    {
        try
        {
            var entry = _session.Reader.ReadEntry(
                _session.SchemaNamingContext,
                ["objectVersion"],
                cancellationToken);

            return entry is null ? 0 : AttributeReader.GetInt32(entry, "objectVersion") ?? 0;
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Warning,
                $"The schema version could not be read: {Connection.LdapDirectoryReader.DescribeFailure(ex)}",
                "SchemaVersion",
                ex);

            return 0;
        }
    }

    private IReadOnlyList<string> ReadUpnSuffixes(CollectorResultBuilder builder, CancellationToken cancellationToken)
    {
        try
        {
            var entry = _session.Reader.ReadEntry(
                $"CN=Partitions,{_session.ConfigurationNamingContext}",
                ["uPNSuffixes"],
                cancellationToken);

            return entry is null ? [] : AttributeReader.GetStrings(entry, "uPNSuffixes");
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Warning,
                $"Alternative user principal name suffixes could not be read: " +
                Connection.LdapDirectoryReader.DescribeFailure(ex),
                "UpnSuffixes",
                ex);

            return [];
        }
    }

    private List<AdDomain> CollectDomains(CollectorResultBuilder builder, CancellationToken cancellationToken)
    {
        var domains = new List<AdDomain>();
        var recycleBinEnabled = IsRecycleBinEnabled(builder, cancellationToken);

        var crossReferences = _session.Reader.Search(
            $"CN=Partitions,{_session.ConfigurationNamingContext}",
            "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))",
            ["nCName", "dnsRoot", "nETBIOSName"],
            cancellationToken,
            SearchScope.OneLevel);

        var netBiosByContext = crossReferences
            .Where(entry => AttributeReader.GetString(entry, "nCName") is not null)
            .ToDictionary(
                entry => AttributeReader.GetString(entry, "nCName")!,
                entry => AttributeReader.GetString(entry, "nETBIOSName") ?? string.Empty,
                StringComparer.OrdinalIgnoreCase);

        foreach (var namingContext in _session.DomainNamingContexts)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var entry = _session.Reader.ReadEntry(
                namingContext,
                [
                    "objectSid", "distinguishedName", "msDS-Behavior-Version", "ms-DS-MachineAccountQuota",
                    "minPwdLength", "pwdHistoryLength", "minPwdAge", "maxPwdAge", "pwdProperties",
                    "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "name",
                ],
                cancellationToken);

            if (entry is null)
            {
                builder.Log(
                    DiagnosticSeverity.Warning,
                    $"The domain naming context could not be read and was skipped.",
                    "DomainUnreadable");

                continue;
            }

            var domainSid = AttributeReader.GetSid(entry, "objectSid");
            if (domainSid is null)
            {
                continue;
            }

            var dnsName = DirectorySession.DistinguishedNameToDns(namingContext);
            var passwordPolicy = BuildPasswordPolicy(entry, dnsName, builder, namingContext, cancellationToken);

            domains.Add(new AdDomain
            {
                DnsName = dnsName,
                NetBiosName = netBiosByContext.GetValueOrDefault(namingContext, string.Empty),
                DomainSid = domainSid,
                DistinguishedName = namingContext,
                FunctionalLevel = AttributeReader.GetInt32(entry, "msDS-Behavior-Version") ?? 0,
                MachineAccountQuota = AttributeReader.GetInt32(entry, "ms-DS-MachineAccountQuota") ?? 10,
                KrbtgtPasswordLastSet = ReadKrbtgtPasswordAge(namingContext, builder, cancellationToken),
                PasswordPolicy = passwordPolicy,
                IsRootDomain = string.Equals(namingContext, _session.RootDse.RootDomainNamingContext, StringComparison.OrdinalIgnoreCase),
                RecycleBinEnabled = recycleBinEnabled,
            });
        }

        return domains;
    }

    private AdPasswordPolicy BuildPasswordPolicy(
        SearchResultEntry entry,
        string dnsName,
        CollectorResultBuilder builder,
        string namingContext,
        CancellationToken cancellationToken)
    {
        // pwdProperties bit 1 requires complexity; bit 16 stores passwords reversibly.
        const int complexityRequired = 0x1;
        const int storeReversible = 0x10;

        var properties = AttributeReader.GetInt32(entry, "pwdProperties") ?? 0;

        return new AdPasswordPolicy
        {
            DomainDnsName = dnsName,
            MinimumPasswordLength = AttributeReader.GetInt32(entry, "minPwdLength") ?? 0,
            PasswordHistoryLength = AttributeReader.GetInt32(entry, "pwdHistoryLength") ?? 0,
            MinimumPasswordAge = AttributeReader.GetNegativeInterval(entry, "minPwdAge"),
            MaximumPasswordAge = AttributeReader.GetNegativeInterval(entry, "maxPwdAge"),
            ComplexityEnabled = (properties & complexityRequired) != 0,
            ReversibleEncryptionEnabled = (properties & storeReversible) != 0,
            LockoutThreshold = AttributeReader.GetInt32(entry, "lockoutThreshold") ?? 0,
            LockoutDuration = AttributeReader.GetNegativeInterval(entry, "lockoutDuration"),
            LockoutObservationWindow = AttributeReader.GetNegativeInterval(entry, "lockOutObservationWindow"),
            HasFineGrainedPolicies = HasFineGrainedPolicies(namingContext, builder, cancellationToken),
        };
    }

    private bool HasFineGrainedPolicies(string namingContext, CollectorResultBuilder builder, CancellationToken cancellationToken)
    {
        try
        {
            var results = _session.Reader.Search(
                $"CN=Password Settings Container,CN=System,{namingContext}",
                "(objectClass=msDS-PasswordSettings)",
                ["cn"],
                cancellationToken,
                SearchScope.OneLevel);

            return results.Count > 0;
        }
        catch (DirectoryOperationException)
        {
            // The container is absent in domains that have never used fine-grained policies.
            return false;
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Information,
                $"Fine-grained password policies could not be enumerated: " +
                Connection.LdapDirectoryReader.DescribeFailure(ex),
                "FineGrainedPolicies",
                ex);

            return false;
        }
    }

    private DateTimeOffset? ReadKrbtgtPasswordAge(
        string namingContext,
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        try
        {
            var entry = _session.Reader.ReadEntry(
                $"CN=krbtgt,CN=Users,{namingContext}",
                ["pwdLastSet"],
                cancellationToken);

            return entry is null ? null : AttributeReader.GetFileTime(entry, "pwdLastSet");
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Information,
                "The key distribution account password age could not be read: " +
                Connection.LdapDirectoryReader.DescribeFailure(ex),
                "KrbtgtAge",
                ex);

            return null;
        }
    }

    private bool IsRecycleBinEnabled(CollectorResultBuilder builder, CancellationToken cancellationToken)
    {
        try
        {
            var entry = _session.Reader.ReadEntry(
                $"CN=Partitions,{_session.ConfigurationNamingContext}",
                ["msDS-EnabledFeature"],
                cancellationToken);

            if (entry is null)
            {
                return false;
            }

            return AttributeReader.GetStrings(entry, "msDS-EnabledFeature")
                .Any(feature => feature.Contains("Recycle Bin Feature", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Information,
                $"The forest feature list could not be read: {Connection.LdapDirectoryReader.DescribeFailure(ex)}",
                "ForestFeatures",
                ex);

            return false;
        }
    }

    private List<AdDomainController> CollectDomainControllers(
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        var controllers = new List<AdDomainController>();

        var entries = _session.Reader.Search(
            $"CN=Sites,{_session.ConfigurationNamingContext}",
            "(objectClass=nTDSDSA)",
            ["distinguishedName", "options", "msDS-Behavior-Version", "hasMasterNCs"],
            cancellationToken);

        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var settingsDn = AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName;

            // The server object is the parent of the directory service settings object, and the
            // site is two levels above that.
            var serverDn = ParentOf(settingsDn);
            var siteDn = ParentOf(ParentOf(serverDn));

            var server = _session.Reader.ReadEntry(
                serverDn,
                ["dNSHostName", "cn", "serverReference"],
                cancellationToken);

            if (server is null)
            {
                continue;
            }

            var options = AttributeReader.GetInt32(entry, "options") ?? 0;
            var hostName = AttributeReader.GetString(server, "dNSHostName")
                           ?? AttributeReader.GetString(server, "cn")
                           ?? serverDn;

            controllers.Add(new AdDomainController
            {
                DnsHostName = hostName,
                DomainDnsName = DirectorySession.DistinguishedNameToDns(
                    AttributeReader.GetString(server, "serverReference") ?? string.Empty),
                SiteName = NameOf(siteDn),
                IsGlobalCatalog = (options & 0x1) != 0,
                IsReadOnly = settingsDn.Contains("CN=RODC", StringComparison.OrdinalIgnoreCase),
                LdapsAvailable = _session.Settings.TransportSecurity != Connection.DirectoryTransportSecurity.SignAndSeal,
            });
        }

        if (controllers.Count == 0)
        {
            builder.Log(
                DiagnosticSeverity.Warning,
                "No domain controllers were enumerated from the configuration partition.",
                "NoDomainControllers");
        }

        return controllers;
    }

    private List<AdSite> CollectSites(
        CollectorResultBuilder builder,
        IReadOnlyCollection<AdDomainController> controllers,
        CancellationToken cancellationToken)
    {
        var sites = new List<AdSite>();

        var siteEntries = _session.Reader.Search(
            $"CN=Sites,{_session.ConfigurationNamingContext}",
            "(objectClass=site)",
            ["cn", "distinguishedName", "siteObjectBL"],
            cancellationToken,
            SearchScope.OneLevel);

        var subnetEntries = _session.Reader.Search(
            $"CN=Subnets,CN=Sites,{_session.ConfigurationNamingContext}",
            "(objectClass=subnet)",
            ["cn", "siteObject"],
            cancellationToken,
            SearchScope.OneLevel);

        var linkEntries = _session.Reader.Search(
            $"CN=Inter-Site Transports,CN=Sites,{_session.ConfigurationNamingContext}",
            "(objectClass=siteLink)",
            ["cn", "siteList"],
            cancellationToken);

        foreach (var entry in siteEntries)
        {
            var name = AttributeReader.GetString(entry, "cn") ?? "unknown";
            var distinguishedName = AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName;

            sites.Add(new AdSite
            {
                Name = name,
                Subnets = subnetEntries
                    .Where(subnet => string.Equals(
                        AttributeReader.GetString(subnet, "siteObject"),
                        distinguishedName,
                        StringComparison.OrdinalIgnoreCase))
                    .Select(subnet => AttributeReader.GetString(subnet, "cn") ?? string.Empty)
                    .Where(subnet => subnet.Length > 0)
                    .ToList(),
                DomainControllers = controllers
                    .Where(controller => string.Equals(controller.SiteName, name, StringComparison.OrdinalIgnoreCase))
                    .Select(controller => controller.DnsHostName)
                    .ToList(),
                SiteLinks = linkEntries
                    .Where(link => AttributeReader.GetStrings(link, "siteList")
                        .Any(member => string.Equals(member, distinguishedName, StringComparison.OrdinalIgnoreCase)))
                    .Select(link => AttributeReader.GetString(link, "cn") ?? string.Empty)
                    .Where(link => link.Length > 0)
                    .ToList(),
            });
        }

        builder.Log(DiagnosticSeverity.Information, $"Enumerated {sites.Count} replication site(s).", "Sites");
        return sites;
    }

    private List<AdTrust> CollectTrusts(
        CollectorResultBuilder builder,
        IReadOnlyCollection<AdDomain> domains,
        CancellationToken cancellationToken)
    {
        var trusts = new List<AdTrust>();

        foreach (var domain in domains)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var entries = _session.Reader.Search(
                    $"CN=System,{domain.DistinguishedName}",
                    "(objectClass=trustedDomain)",
                    ["trustPartner", "name", "trustDirection", "trustAttributes", "trustType", "whenCreated"],
                    cancellationToken,
                    SearchScope.OneLevel);

                trusts.AddRange(entries
                    .Select(entry => DirectoryObjectNormaliser.ToTrust(entry, domain.DnsName))
                    .Where(trust => trust is not null)
                    .Select(trust => trust!));
            }
            catch (Exception ex)
            {
                builder.Log(
                    DiagnosticSeverity.Warning,
                    $"Trusts could not be enumerated for {domain.DnsName}: " +
                    Connection.LdapDirectoryReader.DescribeFailure(ex),
                    "TrustEnumeration",
                    ex);
            }
        }

        return trusts;
    }

    private List<AdAccessControlEntry> CollectAccessControlEntries(
        CollectorResultBuilder builder,
        IReadOnlyCollection<AdDomain> domains,
        IReadOnlyCollection<AdPrincipal> users,
        IReadOnlyCollection<AdGroup> groups,
        CancellationToken cancellationToken)
    {
        var entries = new List<AdAccessControlEntry>();
        var trusteeNames = BuildTrusteeNameMap(users, groups);
        var failures = 0;

        // Security descriptors are read for the objects whose control confers privilege: the
        // domain heads, the protected-account template, and every tier-zero group and account.
        var targets = new List<(string DistinguishedName, string ObjectClass)>();

        foreach (var domain in domains)
        {
            targets.Add((domain.DistinguishedName, "domainDNS"));
            targets.Add(($"CN=AdminSDHolder,CN=System,{domain.DistinguishedName}", "container"));

            foreach (var rid in WellKnownSids.TierZeroGroupRids)
            {
                var sid = WellKnownSids.DomainRelative(domain.DomainSid, rid);
                var group = groups.FirstOrDefault(candidate =>
                    string.Equals(candidate.Sid, sid, StringComparison.OrdinalIgnoreCase));

                if (group is not null)
                {
                    targets.Add((group.DistinguishedName, "group"));
                }
            }
        }

        foreach (var builtinSid in WellKnownSids.TierZeroBuiltinSids)
        {
            var group = groups.FirstOrDefault(candidate =>
                string.Equals(candidate.Sid, builtinSid, StringComparison.OrdinalIgnoreCase));

            if (group is not null)
            {
                targets.Add((group.DistinguishedName, "group"));
            }
        }

        // Members of tier-zero groups are themselves tier-zero objects.
        var resolver = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in groups.Where(group => group.AdminCount))
        {
            foreach (var memberDn in group.MemberDistinguishedNames)
            {
                resolver.Add(memberDn);
            }
        }

        foreach (var memberDn in resolver.Take(2_000))
        {
            targets.Add((memberDn, "user"));
        }

        var total = targets.Count;
        var index = 0;

        foreach (var (distinguishedName, objectClass) in targets.DistinctBy(target => target.DistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            builder.Progress("Access control", "Reading security descriptors", ++index, total);

            try
            {
                var entry = _session.Reader.ReadEntry(
                    distinguishedName,
                    ["nTSecurityDescriptor", "distinguishedName"],
                    cancellationToken,
                    includeSecurityDescriptor: true);

                if (entry is null)
                {
                    continue;
                }

                entries.AddRange(DirectoryObjectNormaliser.ToAccessControlEntries(entry, objectClass, trusteeNames));
            }
            catch (Exception ex)
            {
                failures++;

                if (failures <= 5)
                {
                    builder.Log(
                        DiagnosticSeverity.Warning,
                        $"A security descriptor could not be read: {Connection.LdapDirectoryReader.DescribeFailure(ex)}",
                        "SecurityDescriptor",
                        ex);
                }
            }
        }

        if (entries.Count == 0)
        {
            builder.MarkUnavailable(
                EvidenceKeys.AdAcls,
                EvidenceAvailability.PermissionDenied,
                "No security descriptor could be read. The account may lack permission to read the " +
                "discretionary access-control list of tier-zero objects.");
        }
        else
        {
            builder.MarkCollected(EvidenceKeys.AdAcls);
            builder.AddRecord(
                "ad.acls",
                EvidenceKind.DirectoryQuery,
                $"{entries.Count} access-control entr(ies) read across {index} tier-zero object(s)",
                Sensitivity.ObjectIdentifying);
        }

        if (failures > 0)
        {
            builder.Log(
                DiagnosticSeverity.Warning,
                $"{failures} of {total} security descriptors could not be read.",
                "SecurityDescriptorFailures");
        }

        return entries;
    }

    private static Dictionary<string, string> BuildTrusteeNameMap(
        IReadOnlyCollection<AdPrincipal> users,
        IReadOnlyCollection<AdGroup> groups)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var group in groups)
        {
            map[group.Sid] = group.SamAccountName;
        }

        foreach (var user in users)
        {
            map[user.Sid] = user.SamAccountName;
        }

        return map;
    }

    private static string ParentOf(string distinguishedName)
    {
        var index = distinguishedName.IndexOf(',', StringComparison.Ordinal);
        return index < 0 ? distinguishedName : distinguishedName[(index + 1)..];
    }

    private static string NameOf(string distinguishedName)
    {
        var first = distinguishedName.Split(',', 2)[0];
        var equals = first.IndexOf('=', StringComparison.Ordinal);
        return equals < 0 ? first : first[(equals + 1)..];
    }
}
