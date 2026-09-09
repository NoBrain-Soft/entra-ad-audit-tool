using System.DirectoryServices.Protocols;

namespace Ipa.Collectors.ActiveDirectory.Discovery;

/// <summary>The forest facts published on the RootDSE of a domain controller.</summary>
public sealed record RootDseInformation
{
    public required string DefaultNamingContext { get; init; }
    public required string ConfigurationNamingContext { get; init; }
    public required string SchemaNamingContext { get; init; }
    public required string RootDomainNamingContext { get; init; }
    public string? DnsHostName { get; init; }
    public string? ServerName { get; init; }
    public int DomainFunctionality { get; init; }
    public int ForestFunctionality { get; init; }
    public int DomainControllerFunctionality { get; init; }
    public DateTimeOffset? CurrentServerTime { get; init; }
    public IReadOnlyList<string> NamingContexts { get; init; } = [];
    public IReadOnlyList<string> SupportedControls { get; init; } = [];
}

/// <summary>Reads the RootDSE, the anonymous entry point that describes the directory.</summary>
public sealed class RootDseReader
{
    private static readonly string[] Attributes =
    [
        "defaultNamingContext", "configurationNamingContext", "schemaNamingContext",
        "rootDomainNamingContext", "namingContexts", "dnsHostName", "serverName",
        "domainFunctionality", "forestFunctionality", "domainControllerFunctionality",
        "currentTime", "supportedControl",
    ];

    /// <summary>Reads the RootDSE from an open connection.</summary>
    public RootDseInformation Read(LdapConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var request = new SearchRequest(
            distinguishedName: null,
            ldapFilter: "(objectClass=*)",
            searchScope: SearchScope.Base,
            attributeList: Attributes);

        var response = (SearchResponse)connection.SendRequest(request);

        if (response.Entries.Count == 0)
        {
            throw new InvalidOperationException("The directory server returned no RootDSE entry.");
        }

        var entry = response.Entries[0];

        return new RootDseInformation
        {
            DefaultNamingContext = AttributeReader.GetString(entry, "defaultNamingContext") ?? string.Empty,
            ConfigurationNamingContext = AttributeReader.GetString(entry, "configurationNamingContext") ?? string.Empty,
            SchemaNamingContext = AttributeReader.GetString(entry, "schemaNamingContext") ?? string.Empty,
            RootDomainNamingContext = AttributeReader.GetString(entry, "rootDomainNamingContext") ?? string.Empty,
            DnsHostName = AttributeReader.GetString(entry, "dnsHostName"),
            ServerName = AttributeReader.GetString(entry, "serverName"),
            DomainFunctionality = AttributeReader.GetInt32(entry, "domainFunctionality") ?? 0,
            ForestFunctionality = AttributeReader.GetInt32(entry, "forestFunctionality") ?? 0,
            DomainControllerFunctionality = AttributeReader.GetInt32(entry, "domainControllerFunctionality") ?? 0,
            CurrentServerTime = AttributeReader.GetGeneralizedTime(entry, "currentTime"),
            NamingContexts = AttributeReader.GetStrings(entry, "namingContexts"),
            SupportedControls = AttributeReader.GetStrings(entry, "supportedControl"),
        };
    }
}
