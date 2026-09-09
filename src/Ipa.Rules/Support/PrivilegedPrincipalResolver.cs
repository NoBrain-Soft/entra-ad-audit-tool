using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;

namespace Ipa.Rules.Support;

/// <summary>
/// Resolves effective tier-zero membership from collected groups and principals. Nesting is
/// followed transitively with cycle protection, because privilege reached through three nested
/// groups is exactly as effective as direct membership.
/// </summary>
public sealed class PrivilegedPrincipalResolver
{
    private readonly ActiveDirectoryEvidence _evidence;
    private readonly Dictionary<string, AdGroup> _groupsByDn;
    private readonly Dictionary<string, AdPrincipal> _usersByDn;
    private readonly Dictionary<string, AdComputer> _computersByDn;
    private readonly Lazy<IReadOnlySet<string>> _tierZeroGroupSids;
    private readonly Lazy<IReadOnlyList<AdPrincipal>> _tierZeroUsers;

    public PrivilegedPrincipalResolver(ActiveDirectoryEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        _evidence = evidence;

        _groupsByDn = evidence.Groups
            .GroupBy(group => group.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);

        _usersByDn = evidence.Users
            .GroupBy(user => user.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(user => user.Key, user => user.First(), StringComparer.OrdinalIgnoreCase);

        _computersByDn = evidence.Computers
            .GroupBy(computer => computer.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(computer => computer.Key, computer => computer.First(), StringComparer.OrdinalIgnoreCase);

        _tierZeroGroupSids = new Lazy<IReadOnlySet<string>>(ComputeTierZeroGroupSids);
        _tierZeroUsers = new Lazy<IReadOnlyList<AdPrincipal>>(ComputeTierZeroUsers);
    }

    /// <summary>SIDs of the groups that grant tier-zero control, including nested groups.</summary>
    public IReadOnlySet<string> TierZeroGroupSids => _tierZeroGroupSids.Value;

    /// <summary>Every user account that holds tier-zero privilege through any nesting depth.</summary>
    public IReadOnlyList<AdPrincipal> TierZeroUsers => _tierZeroUsers.Value;

    /// <summary>True when the SID is a tier-zero group or a member of one.</summary>
    public bool IsTierZero(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return false;
        }

        return TierZeroGroupSids.Contains(sid)
               || TierZeroUsers.Any(user => string.Equals(user.Sid, sid, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Returns the transitive member principals of one group, resolved from its SID.</summary>
    public IReadOnlyList<AdPrincipal> GetTransitiveUsers(string groupSid)
    {
        var group = _evidence.Groups.FirstOrDefault(
            candidate => string.Equals(candidate.Sid, groupSid, StringComparison.OrdinalIgnoreCase));

        if (group is null)
        {
            return [];
        }

        var users = new List<AdPrincipal>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Walk(group, users, null, visited);
        return users;
    }

    /// <summary>Returns groups nested inside the supplied group, at any depth.</summary>
    public IReadOnlyList<AdGroup> GetNestedGroups(string groupSid)
    {
        var group = _evidence.Groups.FirstOrDefault(
            candidate => string.Equals(candidate.Sid, groupSid, StringComparison.OrdinalIgnoreCase));

        if (group is null)
        {
            return [];
        }

        var nested = new List<AdGroup>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Walk(group, [], nested, visited);
        return nested;
    }

    /// <summary>Returns the well-known tier-zero groups that exist in the collected forest.</summary>
    public IReadOnlyList<AdGroup> GetTierZeroGroups()
    {
        var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var domain in _evidence.Domains)
        {
            foreach (var rid in WellKnownSids.TierZeroGroupRids)
            {
                wanted.Add(WellKnownSids.DomainRelative(domain.DomainSid, rid));
            }
        }

        foreach (var builtin in WellKnownSids.TierZeroBuiltinSids)
        {
            wanted.Add(builtin);
        }

        return _evidence.Groups.Where(group => wanted.Contains(group.Sid)).ToList();
    }

    private IReadOnlySet<string> ComputeTierZeroGroupSids()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var seed in GetTierZeroGroups())
        {
            result.Add(seed.Sid);
            foreach (var nested in GetNestedGroups(seed.Sid))
            {
                result.Add(nested.Sid);
            }
        }

        return result;
    }

    private IReadOnlyList<AdPrincipal> ComputeTierZeroUsers()
    {
        var users = new Dictionary<string, AdPrincipal>(StringComparer.OrdinalIgnoreCase);

        foreach (var seed in GetTierZeroGroups())
        {
            foreach (var user in GetTransitiveUsers(seed.Sid))
            {
                users[user.Sid] = user;
            }
        }

        // Accounts whose primary group is a tier-zero group are members without a member link.
        foreach (var user in _evidence.Users)
        {
            if (user.PrimaryGroupId is not { } rid)
            {
                continue;
            }

            var domainSid = WellKnownSids.GetDomainSid(user.Sid);
            if (domainSid is null)
            {
                continue;
            }

            if (WellKnownSids.TierZeroGroupRids.Contains(rid))
            {
                users[user.Sid] = user;
            }
        }

        return users.Values.OrderBy(user => user.SamAccountName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private void Walk(
        AdGroup group,
        List<AdPrincipal> users,
        List<AdGroup>? nestedGroups,
        HashSet<string> visited)
    {
        if (!visited.Add(group.DistinguishedName))
        {
            return;
        }

        foreach (var memberDn in group.MemberDistinguishedNames)
        {
            if (_usersByDn.TryGetValue(memberDn, out var user))
            {
                if (users.All(existing => !string.Equals(existing.Sid, user.Sid, StringComparison.OrdinalIgnoreCase)))
                {
                    users.Add(user);
                }

                continue;
            }

            if (_groupsByDn.TryGetValue(memberDn, out var nested))
            {
                nestedGroups?.Add(nested);
                Walk(nested, users, nestedGroups, visited);
                continue;
            }

            // Computer accounts nested in privileged groups are recorded as principals too.
            if (_computersByDn.TryGetValue(memberDn, out var computer))
            {
                var asPrincipal = new AdPrincipal
                {
                    Sid = computer.Sid,
                    DistinguishedName = computer.DistinguishedName,
                    SamAccountName = computer.SamAccountName,
                    DomainSid = WellKnownSids.GetDomainSid(computer.Sid) ?? string.Empty,
                    Flags = computer.Flags,
                    LastLogonTimestamp = computer.LastLogonTimestamp,
                    ObjectClass = "computer",
                };

                if (users.All(existing => !string.Equals(existing.Sid, asPrincipal.Sid, StringComparison.OrdinalIgnoreCase)))
                {
                    users.Add(asPrincipal);
                }
            }
        }
    }
}
