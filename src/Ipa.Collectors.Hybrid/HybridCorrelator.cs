using System.Buffers.Text;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.Hybrid;

/// <summary>The result of correlating an Active Directory forest with an Entra tenant.</summary>
public sealed record CorrelationResult
{
    public IReadOnlyList<HybridIdentityMatch> Matches { get; init; } = [];
    public IReadOnlyList<HybridReviewItem> ReviewItems { get; init; } = [];
    public IReadOnlyList<string> OrphanedCloudObjectIds { get; init; } = [];
    public IReadOnlyList<string> DuplicateAnchors { get; init; } = [];
}

/// <summary>
/// Correlates on-premises and cloud identities.
/// </summary>
/// <remarks>
/// Matching uses authoritative synchronisation anchors first: the on-premises security identifier
/// the tenant records, then the immutable identifier derived from the object's globally unique
/// identifier, then the distinguished name. A user principal name is accepted only when its suffix
/// is a verified domain of the tenant and it resolves to exactly one object on each side. Display
/// name and mail address are never sufficient on their own: a pair that agrees only on those
/// becomes a review item rather than a match.
/// </remarks>
public sealed class HybridCorrelator
{
    /// <summary>Correlates the two directories.</summary>
    public CorrelationResult Correlate(ActiveDirectoryEvidence activeDirectory, EntraEvidence entra)
    {
        ArgumentNullException.ThrowIfNull(activeDirectory);
        ArgumentNullException.ThrowIfNull(entra);

        var matches = new List<HybridIdentityMatch>();
        var reviewItems = new List<HybridReviewItem>();
        var matchedCloudIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var matchedOnPremisesSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var adBySid = activeDirectory.Users
            .GroupBy(user => user.Sid, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);

        var adByDistinguishedName = activeDirectory.Users
            .GroupBy(user => user.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);

        // The immutable identifier is the base64 form of the on-premises object's globally unique
        // identifier. It is matched by comparing the decoded bytes against the object's identifier
        // where the collector recorded one.
        var adByImmutableId = BuildImmutableIdIndex(activeDirectory);

        var verifiedDomains = entra.Tenant.Domains
            .Where(domain => domain.IsVerified)
            .Select(domain => domain.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var adByUpn = activeDirectory.Users
            .Where(user => user.UserPrincipalName is not null)
            .GroupBy(user => user.UserPrincipalName!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToList(), StringComparer.OrdinalIgnoreCase);

        foreach (var cloudUser in entra.Users)
        {
            var match = TryMatch(
                cloudUser,
                adBySid,
                adByImmutableId,
                adByDistinguishedName,
                adByUpn,
                verifiedDomains,
                reviewItems);

            if (match is null)
            {
                continue;
            }

            matches.Add(match);
            matchedCloudIds.Add(cloudUser.ObjectId);
            matchedOnPremisesSids.Add(match.AdSid);
        }

        var orphaned = entra.Users
            .Where(user => user.OnPremisesSyncEnabled)
            .Where(user => !matchedCloudIds.Contains(user.ObjectId))
            .Select(user => user.ObjectId)
            .ToList();

        var duplicateAnchors = entra.Users
            .Where(user => user.OnPremisesImmutableId is not null)
            .GroupBy(user => user.OnPremisesImmutableId!, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToList();

        duplicateAnchors.AddRange(entra.Users
            .Where(user => user.OnPremisesSecurityIdentifier is not null)
            .GroupBy(user => user.OnPremisesSecurityIdentifier!, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key));

        return new CorrelationResult
        {
            Matches = matches,
            ReviewItems = reviewItems,
            OrphanedCloudObjectIds = orphaned,
            DuplicateAnchors = duplicateAnchors.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        };
    }

    private static HybridIdentityMatch? TryMatch(
        EntraUser cloudUser,
        IReadOnlyDictionary<string, AdPrincipal> adBySid,
        IReadOnlyDictionary<string, AdPrincipal> adByImmutableId,
        IReadOnlyDictionary<string, AdPrincipal> adByDistinguishedName,
        IReadOnlyDictionary<string, List<AdPrincipal>> adByUpn,
        IReadOnlySet<string> verifiedDomains,
        List<HybridReviewItem> reviewItems)
    {
        // 1. The on-premises security identifier the tenant itself recorded is authoritative.
        if (cloudUser.OnPremisesSecurityIdentifier is { } sid && adBySid.TryGetValue(sid, out var bySid))
        {
            return Build(bySid, cloudUser, HybridMatchMethod.SecurityIdentifier, HybridMatchConfidence.Authoritative,
                [$"onPremisesSecurityIdentifier={sid}"]);
        }

        // 2. The immutable identifier is the synchronisation anchor.
        if (cloudUser.OnPremisesImmutableId is { } immutableId
            && adByImmutableId.TryGetValue(immutableId, out var byImmutableId))
        {
            return Build(byImmutableId, cloudUser, HybridMatchMethod.ImmutableId, HybridMatchConfidence.Authoritative,
                [$"onPremisesImmutableId={immutableId}"]);
        }

        // 3. The distinguished name the tenant recorded, when the object still exists.
        if (cloudUser.OnPremisesDistinguishedName is { } distinguishedName
            && adByDistinguishedName.TryGetValue(distinguishedName, out var byDn))
        {
            return Build(byDn, cloudUser, HybridMatchMethod.DistinguishedName, HybridMatchConfidence.Strong,
                [$"onPremisesDistinguishedName={distinguishedName}"]);
        }

        // 4. A user principal name, but only inside a verified domain and only when unambiguous.
        var suffix = SuffixOf(cloudUser.UserPrincipalName);

        if (suffix is not null
            && verifiedDomains.Contains(suffix)
            && adByUpn.TryGetValue(cloudUser.UserPrincipalName, out var candidates))
        {
            if (candidates.Count == 1)
            {
                return Build(candidates[0], cloudUser, HybridMatchMethod.VerifiedUserPrincipalName,
                    HybridMatchConfidence.Strong, [$"userPrincipalName={cloudUser.UserPrincipalName}"]);
            }

            reviewItems.Add(new HybridReviewItem
            {
                Reason = "More than one on-premises account shares the cloud account's user principal name.",
                AdCandidates = candidates.Select(candidate => candidate.DistinguishedName).ToList(),
                EntraCandidates = [cloudUser.ObjectId],
                Detail = $"User principal name {cloudUser.UserPrincipalName} resolves to " +
                         $"{candidates.Count} on-premises objects.",
            });

            return null;
        }

        // A cloud object that claims on-premises origin but matches nothing is reported for review
        // rather than paired with the nearest looking account.
        if (cloudUser.OnPremisesSyncEnabled)
        {
            reviewItems.Add(new HybridReviewItem
            {
                Reason = "A synchronised cloud account has no matching on-premises object.",
                EntraCandidates = [cloudUser.ObjectId],
                Detail = $"{cloudUser.UserPrincipalName} is marked as synchronised but no " +
                         "authoritative anchor matched an on-premises account.",
            });
        }

        return null;
    }

    private static HybridIdentityMatch Build(
        AdPrincipal onPremises,
        EntraUser cloud,
        HybridMatchMethod method,
        HybridMatchConfidence confidence,
        IReadOnlyList<string> signals) => new()
    {
        AdSid = onPremises.Sid,
        AdDistinguishedName = onPremises.DistinguishedName,
        EntraObjectId = cloud.ObjectId,
        EntraUserPrincipalName = cloud.UserPrincipalName,
        Method = method,
        Confidence = confidence,
        MatchSignals = signals,
    };

    /// <summary>
    /// Indexes on-premises principals by the immutable identifier a synchronised cloud object would
    /// carry. The identifier is the base64 encoding of the object's globally unique identifier;
    /// where the collector recorded no identifier the principal simply does not appear in the index,
    /// which is correct: no anchor means no authoritative match.
    /// </summary>
    private static Dictionary<string, AdPrincipal> BuildImmutableIdIndex(ActiveDirectoryEvidence evidence)
    {
        var index = new Dictionary<string, AdPrincipal>(StringComparer.Ordinal);

        foreach (var user in evidence.Users)
        {
            foreach (var candidate in ImmutableIdCandidates(user))
            {
                index.TryAdd(candidate, user);
            }
        }

        return index;
    }

    private static IEnumerable<string> ImmutableIdCandidates(AdPrincipal user)
    {
        if (user.ObjectGuid is not { } objectGuid)
        {
            yield break;
        }

        // Directory synchronisation encodes the raw sixteen bytes of the object identifier.
        yield return Convert.ToBase64String(objectGuid.ToByteArray());

        // Some deployments seed the anchor from the identifier's canonical text instead, so that
        // form is indexed as well. Both decode back to the same object, so neither is ambiguous.
        yield return Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes(objectGuid.ToString("d")));
    }

    /// <summary>Returns the domain suffix of a user principal name, or null when it has none.</summary>
    public static string? SuffixOf(string? userPrincipalName)
    {
        if (string.IsNullOrWhiteSpace(userPrincipalName))
        {
            return null;
        }

        var index = userPrincipalName.LastIndexOf('@');
        return index < 0 || index == userPrincipalName.Length - 1 ? null : userPrincipalName[(index + 1)..];
    }

    /// <summary>
    /// Decodes an immutable identifier into the globally unique identifier it encodes, returning
    /// null when the value is not a valid encoding.
    /// </summary>
    public static Guid? DecodeImmutableId(string? immutableId)
    {
        if (string.IsNullOrWhiteSpace(immutableId))
        {
            return null;
        }

        Span<byte> buffer = stackalloc byte[24];

        if (!Base64.IsValid(immutableId)
            || !Convert.TryFromBase64String(immutableId, buffer, out var written)
            || written != 16)
        {
            return null;
        }

        return new Guid(buffer[..16]);
    }
}
