using System.DirectoryServices.Protocols;
using Ipa.Contracts.Security;

namespace Ipa.Collectors.ActiveDirectory.Connection;

/// <summary>
/// Executes paged, read-only directory searches. Every request this reader issues is a search:
/// the class exposes no add, modify or delete operation, so a collector cannot write to the
/// directory even by mistake.
/// </summary>
public sealed class LdapDirectoryReader
{
    private readonly LdapConnection _connection;
    private readonly int _pageSize;

    public LdapDirectoryReader(LdapConnection connection, int pageSize = 500)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentOutOfRangeException.ThrowIfLessThan(pageSize, 1);

        _connection = connection;
        _pageSize = pageSize;
    }

    /// <summary>
    /// Runs a paged search and returns every entry. The security descriptor control is requested
    /// only when the caller asks for it, so ordinary searches do not carry the extra cost.
    /// </summary>
    /// <param name="searchBase">Distinguished name to search beneath.</param>
    /// <param name="filter">LDAP filter.</param>
    /// <param name="attributes">Attributes to return.</param>
    /// <param name="cancellationToken">Cancellation token honoured between pages.</param>
    /// <param name="scope">Search scope.</param>
    /// <param name="includeSecurityDescriptor">
    /// When true, requests the discretionary part of the security descriptor. The system access
    /// control list is deliberately not requested: reading it needs a privilege this assessment
    /// does not ask for.
    /// </param>
    public IReadOnlyList<SearchResultEntry> Search(
        string searchBase,
        string filter,
        string[] attributes,
        CancellationToken cancellationToken,
        SearchScope scope = SearchScope.Subtree,
        bool includeSecurityDescriptor = false)
    {
        ArgumentNullException.ThrowIfNull(searchBase);
        ArgumentException.ThrowIfNullOrWhiteSpace(filter);
        ArgumentNullException.ThrowIfNull(attributes);

        var results = new List<SearchResultEntry>();
        var pageControl = new PageResultRequestControl(_pageSize);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var request = new SearchRequest(searchBase, filter, scope, attributes);
            request.Controls.Add(pageControl);

            if (includeSecurityDescriptor)
            {
                // Owner, group and discretionary list only.
                request.Controls.Add(new SecurityDescriptorFlagControl(
                    SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl));
            }

            SearchResponse response;

            try
            {
                response = (SearchResponse)_connection.SendRequest(request);
            }
            catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.SizeLimitExceeded)
            {
                // A server-side size limit returns the entries collected so far; the caller records
                // the truncation through the diagnostic log.
                break;
            }

            foreach (SearchResultEntry entry in response.Entries)
            {
                results.Add(entry);
            }

            var pageResponse = response.Controls
                .OfType<PageResultResponseControl>()
                .FirstOrDefault();

            if (pageResponse is null || pageResponse.Cookie.Length == 0)
            {
                break;
            }

            pageControl.Cookie = pageResponse.Cookie;
        }

        return results;
    }

    /// <summary>Runs a base-scope search for a single entry, returning null when it is absent.</summary>
    public SearchResultEntry? ReadEntry(
        string distinguishedName,
        string[] attributes,
        CancellationToken cancellationToken,
        bool includeSecurityDescriptor = false)
    {
        var entries = Search(
            distinguishedName,
            "(objectClass=*)",
            attributes,
            cancellationToken,
            SearchScope.Base,
            includeSecurityDescriptor);

        return entries.Count == 0 ? null : entries[0];
    }

    /// <summary>
    /// Produces a message safe for the diagnostic log from a directory exception. The server's
    /// text can echo a distinguished name or a bind attempt, so it is scrubbed before use.
    /// </summary>
    public static string DescribeFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception switch
        {
            DirectoryOperationException directory =>
                $"{directory.Response?.ResultCode.ToString() ?? "OperationFailed"}: " +
                Redaction.Scrub(directory.Response?.ErrorMessage ?? directory.Message),

            LdapException ldap => $"LDAP error {ldap.ErrorCode}: {Redaction.Scrub(ldap.Message)}",

            _ => Redaction.Scrub(exception.Message),
        };
    }
}
