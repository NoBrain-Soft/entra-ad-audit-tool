using System.DirectoryServices.Protocols;
using Ipa.Collectors.ActiveDirectory.Connection;
using Ipa.Collectors.ActiveDirectory.Discovery;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.Collectors;

/// <summary>
/// An open, read-only session against one forest. The session owns the connection, the RootDSE
/// facts and the partition names that every Active Directory collector needs, so the forest is
/// discovered once per assessment rather than once per collector.
/// </summary>
public sealed class DirectorySession : IDisposable
{
    private readonly LdapConnection _connection;

    private DirectorySession(
        LdapConnection connection,
        LdapDirectoryReader reader,
        RootDseInformation rootDse,
        DirectoryConnectionSettings settings,
        IReadOnlyList<string> certificateObservations)
    {
        _connection = connection;
        Reader = reader;
        RootDse = rootDse;
        Settings = settings;
        CertificateObservations = certificateObservations;
    }

    /// <summary>Paged, read-only search interface.</summary>
    public LdapDirectoryReader Reader { get; }

    /// <summary>Forest facts read from the RootDSE.</summary>
    public RootDseInformation RootDse { get; }

    /// <summary>The settings the session was opened with.</summary>
    public DirectoryConnectionSettings Settings { get; }

    /// <summary>Notes recorded while validating the server certificate.</summary>
    public IReadOnlyList<string> CertificateObservations { get; }

    /// <summary>Configuration partition distinguished name.</summary>
    public string ConfigurationNamingContext => RootDse.ConfigurationNamingContext;

    /// <summary>Schema partition distinguished name.</summary>
    public string SchemaNamingContext => RootDse.SchemaNamingContext;

    /// <summary>
    /// Domain naming contexts in the forest, excluding the configuration, schema and application
    /// partitions.
    /// </summary>
    public IReadOnlyList<string> DomainNamingContexts =>
        RootDse.NamingContexts
            .Where(context => !string.Equals(context, RootDse.ConfigurationNamingContext, StringComparison.OrdinalIgnoreCase))
            .Where(context => !string.Equals(context, RootDse.SchemaNamingContext, StringComparison.OrdinalIgnoreCase))
            .Where(context => !context.StartsWith("DC=DomainDnsZones,", StringComparison.OrdinalIgnoreCase))
            .Where(context => !context.StartsWith("DC=ForestDnsZones,", StringComparison.OrdinalIgnoreCase))
            .ToList();

    /// <summary>Opens a session against a server, discovering the forest through the RootDSE.</summary>
    public static DirectorySession Open(DirectoryConnectionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var factory = new LdapConnectionFactory();
        var connection = factory.Create(settings, out var validator);

        try
        {
            var reader = new LdapDirectoryReader(connection, settings.PageSize);
            var rootDse = new RootDseReader().Read(connection);

            return new DirectorySession(connection, reader, rootDse, settings, validator.Observations);
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>Converts a distinguished name into its DNS form, for example <c>corp.example</c>.</summary>
    public static string DistinguishedNameToDns(string distinguishedName)
    {
        ArgumentNullException.ThrowIfNull(distinguishedName);

        return string.Join('.', distinguishedName
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(part => part[3..]));
    }

    /// <summary>Builds the forest summary recorded in the evidence model.</summary>
    public AdForest BuildForestSummary(int schemaVersion, IReadOnlyList<string> upnSuffixes) => new()
    {
        ForestRootDomain = DistinguishedNameToDns(RootDse.RootDomainNamingContext),
        ForestFunctionalLevel = RootDse.ForestFunctionality,
        SchemaVersion = schemaVersion,
        SchemaNamingContext = RootDse.SchemaNamingContext,
        ConfigurationNamingContext = RootDse.ConfigurationNamingContext,
        DomainNamingContexts = DomainNamingContexts,
        UpnSuffixes = upnSuffixes,
        CollectedFromServerTime = RootDse.CurrentServerTime,
    };

    /// <inheritdoc />
    public void Dispose() => _connection.Dispose();
}
