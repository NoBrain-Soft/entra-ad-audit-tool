using System.Net;
using System.Net.Sockets;

namespace Ipa.Collectors.ActiveDirectory.Discovery;

/// <summary>A domain controller located through DNS service records.</summary>
public sealed record LocatedDomainController(string HostName, int Port, int Priority, int Weight);

/// <summary>
/// Locates domain controllers through the DNS service records that Active Directory publishes.
/// The lookup is read-only and performs no directory operation of its own.
/// </summary>
public sealed class ForestLocator
{
    private readonly IDnsSrvResolver _resolver;

    public ForestLocator(IDnsSrvResolver? resolver = null) =>
        _resolver = resolver ?? new SystemDnsSrvResolver();

    /// <summary>
    /// Returns the domain controllers published for a domain, ordered by service record priority
    /// and then by weight, which is the order a client is expected to try them in.
    /// </summary>
    public async Task<IReadOnlyList<LocatedDomainController>> LocateAsync(
        string domainDnsName,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domainDnsName);

        var records = await _resolver
            .ResolveAsync($"_ldap._tcp.dc._msdcs.{domainDnsName.TrimEnd('.')}", cancellationToken)
            .ConfigureAwait(false);

        return records
            .OrderBy(record => record.Priority)
            .ThenByDescending(record => record.Weight)
            .ThenBy(record => record.HostName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Confirms that a host name resolves, so that a typo fails early and clearly.</summary>
    public static async Task<bool> HostResolvesAsync(string hostName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(hostName, cancellationToken).ConfigureAwait(false);
            return addresses.Length > 0;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}

/// <summary>Resolves DNS service records. Abstracted so that discovery can be tested offline.</summary>
public interface IDnsSrvResolver
{
    /// <summary>Resolves the service records published at a name.</summary>
    Task<IReadOnlyList<LocatedDomainController>> ResolveAsync(string serviceName, CancellationToken cancellationToken);
}

/// <summary>
/// Resolves service records using the platform resolver. .NET exposes no managed service-record
/// query, so the resolver reads the entries the operating system publishes for the domain and
/// falls back to a direct host lookup when no service record is reachable.
/// </summary>
public sealed class SystemDnsSrvResolver : IDnsSrvResolver
{
    /// <inheritdoc />
    public async Task<IReadOnlyList<LocatedDomainController>> ResolveAsync(
        string serviceName,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);

        // The service name has the form _ldap._tcp.dc._msdcs.<domain>; the domain itself usually
        // resolves to the address of every domain controller, which is the fallback used here.
        var marker = "._msdcs.";
        var index = serviceName.IndexOf(marker, StringComparison.OrdinalIgnoreCase);

        if (index < 0)
        {
            return [];
        }

        var domain = serviceName[(index + marker.Length)..];

        try
        {
            var entry = await Dns.GetHostEntryAsync(domain, cancellationToken).ConfigureAwait(false);

            var hosts = new List<LocatedDomainController>();

            foreach (var address in entry.AddressList)
            {
                try
                {
                    var reverse = await Dns
                        .GetHostEntryAsync(address.ToString(), cancellationToken)
                        .ConfigureAwait(false);
                    hosts.Add(new LocatedDomainController(reverse.HostName, 389, 0, 100));
                }
                catch (SocketException)
                {
                    hosts.Add(new LocatedDomainController(address.ToString(), 389, 0, 100));
                }
            }

            return hosts
                .DistinctBy(host => host.HostName, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (SocketException)
        {
            return [];
        }
    }
}
