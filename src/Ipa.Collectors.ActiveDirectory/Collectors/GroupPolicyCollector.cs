using System.DirectoryServices.Protocols;
using Ipa.Collectors.ActiveDirectory.Connection;
using Ipa.Collectors.ActiveDirectory.Discovery;
using Ipa.Collectors.ActiveDirectory.GroupPolicy;
using Ipa.Collectors.ActiveDirectory.Normalisation;
using Ipa.Collectors.ActiveDirectory.Sysvol;
using Ipa.Contracts;
using Ipa.Contracts.Collection;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// Collects Group Policy metadata from the directory and the corresponding policy content from
/// SYSVOL. SYSVOL is read over managed SMB2 without mounting a share on the operator's machine.
/// </summary>
public sealed class GroupPolicyCollector : ICollector
{
    private readonly DirectorySession _session;
    private readonly Func<SysvolClient>? _sysvolFactory;

    public GroupPolicyCollector(DirectorySession session, Func<SysvolClient>? sysvolFactory = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        _session = session;
        _sysvolFactory = sysvolFactory;
    }

    /// <inheritdoc />
    public string CollectorId => "ad.groupPolicy";

    /// <inheritdoc />
    public string DisplayName => "Group Policy objects and SYSVOL content";

    /// <inheritdoc />
    public AssessmentSource Source => AssessmentSource.ActiveDirectory;

    /// <inheritdoc />
    public IReadOnlyList<CollectorPrerequisite> Prerequisites { get; } =
    [
        new("Directory connectivity", "A reachable domain controller for the policy container."),
        new("SYSVOL access", "SMB2 read access to the SYSVOL share for policy content."),
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> RequiredPermissions { get; } =
    [
        "Read access to the Group Policy container in each domain",
        "Read access to the SYSVOL share",
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> ProducedEvidenceKeys { get; } =
    [
        EvidenceKeys.AdGroupPolicy, EvidenceKeys.AdSysvol,
    ];

    /// <inheritdoc />
    public IReadOnlyList<CheckGroup> SupportedGroups { get; } =
    [
        CheckGroup.AdGroupPolicy, CheckGroup.BaselineConformity,
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

        try
        {
            var policies = CollectPolicies(builder, context, cancellationToken);

            var existing = context.PreviousEvidence?.ActiveDirectory;

            var fragment = existing is null
                ? new EvidenceFragment()
                : new EvidenceFragment { ActiveDirectory = existing with { GroupPolicies = policies } };

            return Task.FromResult(builder.Build(builder.DetermineOutcome(), fragment));
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
                $"Group Policy collection failed: {LdapDirectoryReader.DescribeFailure(ex)}",
                "CollectionFailed",
                ex);

            builder.MarkUnavailable(EvidenceKeys.AdGroupPolicy, EvidenceAvailability.Error, "Group Policy collection failed.");
            builder.MarkUnavailable(EvidenceKeys.AdSysvol, EvidenceAvailability.Error, "SYSVOL content was not read.");

            return Task.FromResult(builder.Build(CollectionOutcome.Failed, new EvidenceFragment()));
        }
    }

    private List<GroupPolicyObject> CollectPolicies(
        CollectorResultBuilder builder,
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        var policies = new List<GroupPolicyObject>();
        var links = CollectLinks(builder, cancellationToken);

        foreach (var namingContext in _session.DomainNamingContexts)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var domainDns = DirectorySession.DistinguishedNameToDns(namingContext);
            builder.Progress("Group Policy", $"Reading policy objects in {domainDns}");

            var entries = _session.Reader.Search(
                $"CN=Policies,CN=System,{namingContext}",
                "(objectClass=groupPolicyContainer)",
                [
                    "cn", "displayName", "gPCFileSysPath", "versionNumber", "flags", "gPCWQLFilter",
                    "whenCreated", "whenChanged", "nTSecurityDescriptor", "distinguishedName",
                ],
                cancellationToken,
                SearchScope.OneLevel,
                includeSecurityDescriptor: true);

            foreach (var entry in entries)
            {
                var guid = AttributeReader.GetString(entry, "cn") ?? string.Empty;
                var version = AttributeReader.GetInt32(entry, "versionNumber") ?? 0;
                var flags = AttributeReader.GetInt32(entry, "flags") ?? 0;

                policies.Add(new GroupPolicyObject
                {
                    Guid = guid.Trim('{', '}').ToUpperInvariant(),
                    DisplayName = AttributeReader.GetString(entry, "displayName") ?? guid,
                    DomainDnsName = domainDns,
                    FileSystemPath = AttributeReader.GetString(entry, "gPCFileSysPath"),
                    DirectoryVersion = version,
                    SysvolVersion = version,
                    ComputerSettingsDisabled = (flags & 0x2) != 0,
                    UserSettingsDisabled = (flags & 0x1) != 0,
                    WmiFilter = AttributeReader.GetString(entry, "gPCWQLFilter"),
                    WhenCreated = AttributeReader.GetGeneralizedTime(entry, "whenCreated"),
                    WhenChanged = AttributeReader.GetGeneralizedTime(entry, "whenChanged"),
                    OwnerSid = DirectoryObjectNormaliser.ReadOwnerSid(entry),
                    Links = links.GetValueOrDefault(guid.Trim('{', '}').ToUpperInvariant(), []),
                    Permissions = ReadContainerPermissions(entry),
                    SysvolUnavailable = true,
                });
            }
        }

        builder.MarkCollected(EvidenceKeys.AdGroupPolicy);
        builder.AddRecord(
            "ad.groupPolicy",
            EvidenceKind.PolicyDocument,
            $"{policies.Count} Group Policy object(s) read from the directory");

        var enriched = EnrichFromSysvol(policies, builder, context, cancellationToken);

        return enriched;
    }

    private List<GroupPolicyObject> EnrichFromSysvol(
        List<GroupPolicyObject> policies,
        CollectorResultBuilder builder,
        CollectionContext context,
        CancellationToken cancellationToken)
    {
        if (policies.Count == 0)
        {
            builder.MarkUnavailable(
                EvidenceKeys.AdSysvol,
                EvidenceAvailability.NotSelected,
                "No Group Policy objects were found, so no SYSVOL content was read.");

            return policies;
        }

        var server = _session.Settings.Server;
        SysvolClient? client = null;

        try
        {
            client = _sysvolFactory?.Invoke() ?? new SysvolClient();
            client.Connect(server, _session.Settings.Credential);
        }
        catch (Exception ex)
        {
            client?.Dispose();

            builder.Log(
                DiagnosticSeverity.Warning,
                $"SYSVOL could not be reached on '{server}': {ex.Message}",
                "SysvolUnavailable",
                ex);

            builder.MarkUnavailable(
                EvidenceKeys.AdSysvol,
                EvidenceAvailability.Unsupported,
                $"SYSVOL on '{server}' could not be reached, so registry policy and security " +
                "template content was not collected. Rules that need it report as not collected.");

            return policies;
        }

        try
        {
            var enriched = new List<GroupPolicyObject>(policies.Count);
            var index = 0;

            foreach (var policy in policies)
            {
                cancellationToken.ThrowIfCancellationRequested();
                builder.Progress("SYSVOL", $"Reading policy content for {policy.DisplayName}", ++index, policies.Count);

                enriched.Add(ReadPolicyContent(client, policy, builder, cancellationToken));
            }

            builder.MarkCollected(EvidenceKeys.AdSysvol);

            var settingCount = enriched.Sum(policy => policy.RegistrySettings.Count + policy.SecuritySettings.Count);
            builder.AddRecord(
                "ad.sysvol",
                EvidenceKind.PolicyDocument,
                $"{settingCount} policy setting(s) parsed from SYSVOL across {enriched.Count} policy object(s)");

            return enriched;
        }
        finally
        {
            client.Dispose();
        }
    }

    private static GroupPolicyObject ReadPolicyContent(
        SysvolClient client,
        GroupPolicyObject policy,
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        if (policy.FileSystemPath is null)
        {
            return policy;
        }

        var basePath = SysvolClient.Normalise(policy.FileSystemPath);
        var registrySettings = new List<RegistryPolicySetting>();
        var securitySettings = new List<SecurityTemplateSetting>();
        var preferencePasswords = new List<GpoPreferencePasswordArtifact>();
        var sysvolVersion = policy.DirectoryVersion;
        var unavailable = false;

        List<SysvolFile> files;

        try
        {
            files = client.ListFiles(basePath, cancellationToken).ToList();
        }
        catch (Exception ex)
        {
            builder.Log(
                DiagnosticSeverity.Warning,
                $"The SYSVOL folder for policy '{policy.DisplayName}' could not be listed: {ex.Message}",
                "SysvolListing",
                ex);

            return policy with { SysvolUnavailable = true };
        }

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var fileName = file.RelativePath.Split('\\').LastOrDefault() ?? string.Empty;

            try
            {
                if (fileName.Equals("GPT.INI", StringComparison.OrdinalIgnoreCase))
                {
                    var content = client.ReadFile(file.RelativePath, cancellationToken);
                    sysvolVersion = ParseGptIniVersion(content) ?? sysvolVersion;
                }
                else if (fileName.Equals("registry.pol", StringComparison.OrdinalIgnoreCase))
                {
                    var content = client.ReadFile(file.RelativePath, cancellationToken);
                    var isMachine = file.RelativePath.Contains(@"\Machine\", StringComparison.OrdinalIgnoreCase);
                    var parsed = RegistryPolicyParser.Parse(content, isMachine);

                    registrySettings.AddRange(parsed.Settings);

                    foreach (var note in parsed.Notes)
                    {
                        builder.Log(DiagnosticSeverity.Information, $"{policy.DisplayName}: {note}", "RegistryPolicy");
                    }
                }
                else if (fileName.Equals("GptTmpl.inf", StringComparison.OrdinalIgnoreCase))
                {
                    var content = client.ReadFile(file.RelativePath, cancellationToken);
                    var parsed = SecurityTemplateParser.Parse(content);

                    securitySettings.AddRange(parsed.Settings);

                    foreach (var note in parsed.Notes)
                    {
                        builder.Log(DiagnosticSeverity.Information, $"{policy.DisplayName}: {note}", "SecurityTemplate");
                    }
                }
                else if (PreferenceCredentialScanner.CandidateFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                {
                    var content = client.ReadFile(file.RelativePath, cancellationToken);
                    preferencePasswords.AddRange(PreferenceCredentialScanner.Scan(file.RelativePath, content));
                }
            }
            catch (Exception ex)
            {
                unavailable = true;

                builder.Log(
                    DiagnosticSeverity.Warning,
                    $"A SYSVOL file for policy '{policy.DisplayName}' could not be read: {ex.Message}",
                    "SysvolRead",
                    ex);
            }
        }

        return policy with
        {
            RegistrySettings = registrySettings,
            SecuritySettings = securitySettings,
            PreferencePasswords = preferencePasswords,
            SysvolVersion = sysvolVersion,
            SysvolUnavailable = unavailable,
        };
    }

    /// <summary>Reads the version recorded in <c>GPT.INI</c>, which the directory should mirror.</summary>
    public static int? ParseGptIniVersion(ReadOnlySpan<byte> content)
    {
        var text = System.Text.Encoding.UTF8.GetString(content);

        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim();

            if (!trimmed.StartsWith("Version", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var separator = trimmed.IndexOf('=', StringComparison.Ordinal);
            if (separator > 0 && int.TryParse(trimmed[(separator + 1)..].Trim(), out var version))
            {
                return version;
            }
        }

        return null;
    }

    private Dictionary<string, List<GpoLink>> CollectLinks(
        CollectorResultBuilder builder,
        CancellationToken cancellationToken)
    {
        var links = new Dictionary<string, List<GpoLink>>(StringComparer.OrdinalIgnoreCase);

        var targets = new List<(string Dn, string Type)>();

        foreach (var namingContext in _session.DomainNamingContexts)
        {
            targets.Add((namingContext, "domain"));

            try
            {
                targets.AddRange(_session.Reader
                    .Search(namingContext, "(objectClass=organizationalUnit)", ["distinguishedName", "gPLink"], cancellationToken)
                    .Select(entry => (AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName, "organizationalUnit")));
            }
            catch (Exception ex)
            {
                builder.Log(
                    DiagnosticSeverity.Warning,
                    $"Organisational units could not be enumerated: {LdapDirectoryReader.DescribeFailure(ex)}",
                    "OuEnumeration",
                    ex);
            }
        }

        targets.AddRange(_session.Reader
            .Search($"CN=Sites,{_session.ConfigurationNamingContext}", "(objectClass=site)",
                ["distinguishedName", "gPLink"], cancellationToken, SearchScope.OneLevel)
            .Select(entry => (AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName, "site")));

        foreach (var (dn, type) in targets.DistinctBy(target => target.Dn, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var entry = _session.Reader.ReadEntry(dn, ["gPLink"], cancellationToken);
                var raw = entry is null ? null : AttributeReader.GetString(entry, "gPLink");

                if (string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }

                var order = 0;

                foreach (var link in ParseGpLink(raw, dn, type))
                {
                    var withOrder = link.Link with { Order = order++ };

                    if (!links.TryGetValue(link.Guid, out var list))
                    {
                        list = [];
                        links[link.Guid] = list;
                    }

                    list.Add(withOrder);
                }
            }
            catch (Exception ex)
            {
                builder.Log(
                    DiagnosticSeverity.Information,
                    $"A policy link could not be read: {LdapDirectoryReader.DescribeFailure(ex)}",
                    "GpLink",
                    ex);
            }
        }

        return links;
    }

    /// <summary>
    /// Parses the <c>gPLink</c> attribute, whose value is a sequence of
    /// <c>[LDAP://cn={GUID},...;options]</c> entries. Option bit one disables the link and bit two
    /// enforces it.
    /// </summary>
    public static IReadOnlyList<(string Guid, GpoLink Link)> ParseGpLink(string value, string targetDn, string targetType)
    {
        ArgumentNullException.ThrowIfNull(value);

        var results = new List<(string, GpoLink)>();

        foreach (var segment in value.Split('[', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = segment.TrimEnd(']');
            var parts = trimmed.Split(';');

            if (parts.Length < 2)
            {
                continue;
            }

            var path = parts[0];
            var start = path.IndexOf('{', StringComparison.Ordinal);
            var end = path.IndexOf('}', StringComparison.Ordinal);

            if (start < 0 || end <= start)
            {
                continue;
            }

            var guid = path[(start + 1)..end].ToUpperInvariant();

            if (!int.TryParse(parts[1], out var options))
            {
                options = 0;
            }

            results.Add((guid, new GpoLink
            {
                TargetDistinguishedName = targetDn,
                TargetType = targetType,
                LinkEnabled = (options & 0x1) == 0,
                Enforced = (options & 0x2) != 0,
            }));
        }

        return results;
    }

    private static IReadOnlyList<GpoPermissionEntry> ReadContainerPermissions(SearchResultEntry entry)
    {
        var aces = DirectoryObjectNormaliser.ToAccessControlEntries(entry, "groupPolicyContainer");

        return aces
            .Where(ace => !ace.IsDeny)
            .Select(ace => new GpoPermissionEntry
            {
                TrusteeSid = ace.TrusteeSid,
                TrusteeName = ace.TrusteeName,
                Rights = ace.Rights.ToString(),
                AppliesToSysvol = false,
                IsInherited = ace.IsInherited,
            })
            .ToList();
    }
}
