namespace Ipa.Contracts.Directory;

/// <summary>
/// Well-known security identifiers used to classify principals as tier-zero, to resolve
/// built-in groups and to recognise default trustees on access-control entries.
/// </summary>
public static class WellKnownSids
{
    // Universal well-known SIDs.
    public const string Everyone = "S-1-1-0";
    public const string AuthenticatedUsers = "S-1-5-11";
    public const string AnonymousLogon = "S-1-5-7";
    public const string Self = "S-1-5-10";
    public const string SystemAccount = "S-1-5-18";
    public const string LocalService = "S-1-5-19";
    public const string NetworkService = "S-1-5-20";
    public const string CreatorOwner = "S-1-3-0";
    public const string InteractiveUsers = "S-1-5-4";
    public const string PreWindows2000CompatibleAccess = "S-1-5-32-554";

    // Built-in domain-local groups (S-1-5-32-*).
    public const string BuiltinAdministrators = "S-1-5-32-544";
    public const string BuiltinUsers = "S-1-5-32-545";
    public const string BuiltinGuests = "S-1-5-32-546";
    public const string BuiltinPrintOperators = "S-1-5-32-550";
    public const string BuiltinBackupOperators = "S-1-5-32-551";
    public const string BuiltinServerOperators = "S-1-5-32-549";
    public const string BuiltinAccountOperators = "S-1-5-32-548";
    public const string BuiltinIncomingForestTrustBuilders = "S-1-5-32-557";

    // Relative identifiers appended to a domain SID.
    public const int AdministratorRid = 500;
    public const int GuestRid = 501;
    public const int KrbtgtRid = 502;
    public const int DomainAdminsRid = 512;
    public const int DomainUsersRid = 513;
    public const int DomainGuestsRid = 514;
    public const int DomainComputersRid = 515;
    public const int DomainControllersRid = 516;
    public const int CertPublishersRid = 517;
    public const int SchemaAdminsRid = 518;
    public const int EnterpriseAdminsRid = 519;
    public const int GroupPolicyCreatorOwnersRid = 520;
    public const int ReadOnlyDomainControllersRid = 521;
    public const int ProtectedUsersRid = 525;
    public const int KeyAdminsRid = 526;
    public const int EnterpriseKeyAdminsRid = 527;

    /// <summary>Builds a domain-relative SID, for example the Domain Admins group of a domain.</summary>
    public static string DomainRelative(string domainSid, int rid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domainSid);
        return $"{domainSid}-{rid}";
    }

    /// <summary>
    /// Relative identifiers of the groups treated as tier zero: membership grants effective
    /// control of the domain or forest.
    /// </summary>
    public static IReadOnlyList<int> TierZeroGroupRids { get; } =
    [
        DomainAdminsRid,
        EnterpriseAdminsRid,
        SchemaAdminsRid,
        GroupPolicyCreatorOwnersRid,
        KeyAdminsRid,
        EnterpriseKeyAdminsRid,
    ];

    /// <summary>Built-in groups treated as tier zero regardless of domain.</summary>
    public static IReadOnlyList<string> TierZeroBuiltinSids { get; } =
    [
        BuiltinAdministrators,
        BuiltinAccountOperators,
        BuiltinBackupOperators,
        BuiltinServerOperators,
        BuiltinPrintOperators,
    ];

    /// <summary>
    /// Trustees whose control of directory objects is expected by design. Access-control rules
    /// use this set to avoid reporting the default security descriptor as a finding.
    /// </summary>
    public static bool IsExpectedPrivilegedTrustee(string sid, IEnumerable<string> domainSids)
    {
        ArgumentNullException.ThrowIfNull(sid);
        ArgumentNullException.ThrowIfNull(domainSids);

        if (sid is SystemAccount or BuiltinAdministrators or CreatorOwner or Self
            or LocalService or NetworkService)
        {
            return true;
        }

        // Enterprise Domain Controllers.
        if (sid == "S-1-5-9")
        {
            return true;
        }

        foreach (var domainSid in domainSids)
        {
            foreach (var rid in (int[])[DomainAdminsRid, EnterpriseAdminsRid, DomainControllersRid, ReadOnlyDomainControllersRid])
            {
                if (string.Equals(sid, DomainRelative(domainSid, rid), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>Returns the relative identifier of a SID, or null when it has none.</summary>
    public static int? GetRid(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return null;
        }

        var index = sid.LastIndexOf('-');
        if (index < 0 || index == sid.Length - 1)
        {
            return null;
        }

        return int.TryParse(sid.AsSpan(index + 1), out var rid) ? rid : null;
    }

    /// <summary>Returns the domain portion of a SID, or null when the SID has no domain part.</summary>
    public static string? GetDomainSid(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid))
        {
            return null;
        }

        var index = sid.LastIndexOf('-');
        return index <= 0 ? null : sid[..index];
    }
}

/// <summary>Schema GUIDs of the extended rights the tool reasons about.</summary>
public static class ExtendedRights
{
    public const string ReplicatingDirectoryChanges = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    public const string ReplicatingDirectoryChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
    public const string ReplicatingDirectoryChangesInFilteredSet = "89e95b76-444d-4c62-991a-0facbeda640c";
    public const string AllExtendedRights = "00000000-0000-0000-0000-000000000000";
    public const string ResetPassword = "00299570-246d-11d0-a768-00aa006e0529";
    public const string CertificateEnrollment = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
    public const string CertificateAutoEnrollment = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";

    /// <summary>Rights whose combination permits directory replication (a DCSync-capable grant).</summary>
    public static bool IsReplicationRight(string? objectTypeGuid) =>
        string.Equals(objectTypeGuid, ReplicatingDirectoryChanges, StringComparison.OrdinalIgnoreCase)
        || string.Equals(objectTypeGuid, ReplicatingDirectoryChangesAll, StringComparison.OrdinalIgnoreCase);
}
