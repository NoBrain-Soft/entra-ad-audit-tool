using System.DirectoryServices.Protocols;
using Ipa.Collectors.ActiveDirectory.Discovery;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;

namespace Ipa.Collectors.ActiveDirectory.Normalisation;

/// <summary>
/// Converts directory search results into the normalised evidence model. All interpretation of
/// directory-specific encodings happens here, so rule evaluators see platform-neutral data and
/// the same forest produces identical evidence from Windows and from Linux.
/// </summary>
public static class DirectoryObjectNormaliser
{
    // userAccountControl flags.
    private const int AccountDisabled = 0x0002;
    private const int PasswordNotRequired = 0x0020;
    private const int TrustedForDelegation = 0x80000;
    private const int NotDelegated = 0x100000;
    private const int UseDesKeyOnly = 0x200000;
    private const int DontRequirePreAuth = 0x400000;
    private const int PasswordNeverExpires = 0x10000;
    private const int SmartCardRequired = 0x40000;
    private const int TrustedToAuthForDelegation = 0x1000000;

    // groupType flags.
    private const int GroupBuiltinLocal = 0x00000001;
    private const int GroupGlobal = 0x00000002;
    private const int GroupDomainLocal = 0x00000004;
    private const int GroupUniversal = 0x00000008;
    private const uint GroupSecurityEnabled = 0x80000000;

    // trustAttributes flags.
    private const int TrustAttributeNonTransitive = 0x00000001;
    private const int TrustAttributeQuarantinedDomain = 0x00000004;
    private const int TrustAttributeForestTransitive = 0x00000008;
    private const int TrustAttributeCrossOrganisation = 0x00000010;
    private const int TrustAttributeTreatAsExternal = 0x00000040;

    /// <summary>Attributes requested for user objects.</summary>
    public static string[] UserAttributes { get; } =
    [
        "objectSid", "distinguishedName", "sAMAccountName", "userPrincipalName", "displayName",
        "userAccountControl", "whenCreated", "lastLogonTimestamp", "pwdLastSet", "adminCount",
        "servicePrincipalName", "msDS-AllowedToDelegateTo", "sIDHistory", "primaryGroupID",
        "objectClass", "lockoutTime", "msDS-User-Account-Control-Computed",
    ];

    /// <summary>Attributes requested for computer objects.</summary>
    public static string[] ComputerAttributes { get; } =
    [
        "objectSid", "distinguishedName", "sAMAccountName", "dNSHostName", "operatingSystem",
        "operatingSystemVersion", "userAccountControl", "whenCreated", "lastLogonTimestamp",
        "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "primaryGroupID",
        "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime",
    ];

    /// <summary>Attributes requested for group objects.</summary>
    public static string[] GroupAttributes { get; } =
    [
        "objectSid", "distinguishedName", "sAMAccountName", "groupType", "member", "adminCount",
    ];

    /// <summary>Converts a user search result into a normalised principal.</summary>
    public static AdPrincipal? ToPrincipal(SearchResultEntry entry, string domainSid, string? domainDnsName)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var sid = AttributeReader.GetSid(entry, "objectSid");
        var distinguishedName = AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName;
        var samAccountName = AttributeReader.GetString(entry, "sAMAccountName");

        if (sid is null || samAccountName is null)
        {
            return null;
        }

        var uac = AttributeReader.GetInt32(entry, "userAccountControl") ?? 0;
        var computed = AttributeReader.GetInt32(entry, "msDS-User-Account-Control-Computed") ?? 0;
        var lockoutTime = AttributeReader.GetFileTime(entry, "lockoutTime");
        var allowedToDelegateTo = AttributeReader.GetStrings(entry, "msDS-AllowedToDelegateTo");

        return new AdPrincipal
        {
            Sid = sid,
            DistinguishedName = distinguishedName,
            SamAccountName = samAccountName,
            UserPrincipalName = AttributeReader.GetString(entry, "userPrincipalName"),
            DisplayName = AttributeReader.GetString(entry, "displayName"),
            DomainSid = WellKnownSids.GetDomainSid(sid) ?? domainSid,
            DomainDnsName = domainDnsName,
            WhenCreated = AttributeReader.GetGeneralizedTime(entry, "whenCreated"),
            LastLogonTimestamp = AttributeReader.GetFileTime(entry, "lastLogonTimestamp"),
            PasswordLastSet = AttributeReader.GetFileTime(entry, "pwdLastSet"),
            Flags = MapAccountFlags(uac, computed, lockoutTime),
            Delegation = MapDelegation(uac, allowedToDelegateTo, resourceBased: false),
            ServicePrincipalNames = AttributeReader.GetStrings(entry, "servicePrincipalName"),
            AllowedToDelegateTo = allowedToDelegateTo,
            SidHistory = AttributeReader.GetSids(entry, "sIDHistory"),
            AdminCount = (AttributeReader.GetInt32(entry, "adminCount") ?? 0) != 0,
            PrimaryGroupId = AttributeReader.GetInt32(entry, "primaryGroupID"),
            ObjectClass = AttributeReader.GetStrings(entry, "objectClass").LastOrDefault() ?? "user",
        };
    }

    /// <summary>Converts a computer search result into a normalised computer account.</summary>
    public static AdComputer? ToComputer(SearchResultEntry entry, IReadOnlyCollection<string> domainControllerDns)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var sid = AttributeReader.GetSid(entry, "objectSid");
        var samAccountName = AttributeReader.GetString(entry, "sAMAccountName");

        if (sid is null || samAccountName is null)
        {
            return null;
        }

        var uac = AttributeReader.GetInt32(entry, "userAccountControl") ?? 0;
        var allowedToDelegateTo = AttributeReader.GetStrings(entry, "msDS-AllowedToDelegateTo");
        var resourceBased = AttributeReader.GetBytes(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity") is not null;
        var dnsHostName = AttributeReader.GetString(entry, "dNSHostName");

        var lapsExpiry = AttributeReader.GetFileTime(entry, "msLAPS-PasswordExpirationTime")
                         ?? AttributeReader.GetFileTime(entry, "ms-Mcs-AdmPwdExpirationTime");

        return new AdComputer
        {
            Sid = sid,
            DistinguishedName = AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName,
            SamAccountName = samAccountName,
            DnsHostName = dnsHostName,
            OperatingSystem = AttributeReader.GetString(entry, "operatingSystem"),
            OperatingSystemVersion = AttributeReader.GetString(entry, "operatingSystemVersion"),
            LastLogonTimestamp = AttributeReader.GetFileTime(entry, "lastLogonTimestamp"),
            WhenCreated = AttributeReader.GetGeneralizedTime(entry, "whenCreated"),
            Flags = MapAccountFlags(uac, 0, null),
            Delegation = MapDelegation(uac, allowedToDelegateTo, resourceBased),
            AllowedToDelegateTo = allowedToDelegateTo,
            IsDomainController = dnsHostName is not null
                                 && domainControllerDns.Contains(dnsHostName, StringComparer.OrdinalIgnoreCase),
            HasLapsPassword = lapsExpiry is not null,
            LapsPasswordExpiry = lapsExpiry,
        };
    }

    /// <summary>Converts a group search result into a normalised group.</summary>
    public static AdGroup? ToGroup(SearchResultEntry entry, string domainSid)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var sid = AttributeReader.GetSid(entry, "objectSid");
        var samAccountName = AttributeReader.GetString(entry, "sAMAccountName");

        if (sid is null || samAccountName is null)
        {
            return null;
        }

        var groupType = unchecked((uint)(AttributeReader.GetInt32(entry, "groupType") ?? 0));

        return new AdGroup
        {
            Sid = sid,
            DistinguishedName = AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName,
            SamAccountName = samAccountName,
            DomainSid = WellKnownSids.GetDomainSid(sid) ?? domainSid,
            Scope = MapGroupScope((int)groupType),
            IsSecurityGroup = (groupType & GroupSecurityEnabled) != 0,
            AdminCount = (AttributeReader.GetInt32(entry, "adminCount") ?? 0) != 0,
            MemberDistinguishedNames = AttributeReader.GetStrings(entry, "member"),
        };
    }

    /// <summary>Converts a trusted-domain object into a normalised trust.</summary>
    public static AdTrust? ToTrust(SearchResultEntry entry, string sourceDomain)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var target = AttributeReader.GetString(entry, "trustPartner")
                     ?? AttributeReader.GetString(entry, "name");

        if (target is null)
        {
            return null;
        }

        var attributes = AttributeReader.GetInt32(entry, "trustAttributes") ?? 0;
        var direction = AttributeReader.GetInt32(entry, "trustDirection") ?? 0;

        var isForest = (attributes & TrustAttributeForestTransitive) != 0;
        var isExternal = !isForest
                         && ((attributes & TrustAttributeTreatAsExternal) != 0
                             || (attributes & TrustAttributeCrossOrganisation) != 0
                             || (attributes & TrustAttributeNonTransitive) != 0);

        // Quarantine is the flag that enables SID filtering on an external trust. Forest trusts
        // filter by default unless the treat-as-external flag has been set on them.
        var quarantined = (attributes & TrustAttributeQuarantinedDomain) != 0;
        var treatedAsExternal = (attributes & TrustAttributeTreatAsExternal) != 0;

        return new AdTrust
        {
            SourceDomain = sourceDomain,
            TargetDomain = target,
            Direction = (AdTrustDirection)Math.Clamp(direction, 0, 3),
            TrustAttributes = attributes,
            IsTransitive = (attributes & TrustAttributeNonTransitive) == 0,
            IsForestTrust = isForest,
            IsExternal = isExternal,
            SidFilteringEnabled = quarantined || (isForest && !treatedAsExternal),
            SidHistoryEnabled = treatedAsExternal && !quarantined,
            SelectiveAuthentication = (attributes & TrustAttributeCrossOrganisation) != 0,
            WhenCreated = AttributeReader.GetGeneralizedTime(entry, "whenCreated"),
        };
    }

    /// <summary>Converts a security descriptor attribute into normalised access-control entries.</summary>
    public static IReadOnlyList<AdAccessControlEntry> ToAccessControlEntries(
        SearchResultEntry entry,
        string objectClass,
        IReadOnlyDictionary<string, string>? trusteeNames = null)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var descriptorBytes = AttributeReader.GetBytes(entry, "nTSecurityDescriptor");
        if (descriptorBytes is null)
        {
            return [];
        }

        var descriptor = SecurityDescriptorParser.Parse(descriptorBytes);
        if (descriptor is null)
        {
            return [];
        }

        var distinguishedName = AttributeReader.GetString(entry, "distinguishedName") ?? entry.DistinguishedName;

        return descriptor.DiscretionaryAces
            .Select(ace => new AdAccessControlEntry
            {
                ObjectDistinguishedName = distinguishedName,
                ObjectClass = objectClass,
                TrusteeSid = ace.TrusteeSid,
                TrusteeName = trusteeNames?.GetValueOrDefault(ace.TrusteeSid),
                Rights = SecurityDescriptorParser.MapRights(
                    ace.AccessMask,
                    ace.ObjectTypeGuid is not null,
                    ace.ObjectTypeGuid),
                ObjectTypeGuid = ace.ObjectTypeGuid,
                ExtendedRightName = SecurityDescriptorParser.DescribeExtendedRight(ace.ObjectTypeGuid),
                IsInherited = ace.IsInherited,
                IsDeny = ace.IsDeny,
            })
            .ToList();
    }

    /// <summary>Reads the owner of an object from its security descriptor.</summary>
    public static string? ReadOwnerSid(SearchResultEntry entry)
    {
        var descriptorBytes = AttributeReader.GetBytes(entry, "nTSecurityDescriptor");
        return descriptorBytes is null ? null : SecurityDescriptorParser.Parse(descriptorBytes)?.OwnerSid;
    }

    /// <summary>Maps userAccountControl and computed flags onto the normalised flag set.</summary>
    public static AdAccountFlags MapAccountFlags(int uac, int computed, DateTimeOffset? lockoutTime)
    {
        var flags = AdAccountFlags.None;

        if ((uac & AccountDisabled) != 0)
        {
            flags |= AdAccountFlags.Disabled;
        }

        if ((uac & PasswordNeverExpires) != 0)
        {
            flags |= AdAccountFlags.PasswordNeverExpires;
        }

        if ((uac & PasswordNotRequired) != 0)
        {
            flags |= AdAccountFlags.PasswordNotRequired;
        }

        if ((uac & DontRequirePreAuth) != 0)
        {
            flags |= AdAccountFlags.DoesNotRequirePreAuth;
        }

        if ((uac & TrustedForDelegation) != 0)
        {
            flags |= AdAccountFlags.TrustedForDelegation;
        }

        if ((uac & TrustedToAuthForDelegation) != 0)
        {
            flags |= AdAccountFlags.TrustedToAuthForDelegation;
        }

        if ((uac & NotDelegated) != 0)
        {
            flags |= AdAccountFlags.NotDelegated;
        }

        if ((uac & UseDesKeyOnly) != 0)
        {
            flags |= AdAccountFlags.UseDesKeyOnly;
        }

        if ((uac & SmartCardRequired) != 0)
        {
            flags |= AdAccountFlags.SmartCardRequired;
        }

        // The computed attribute reports the transient lockout and expiry state.
        const int computedLockout = 0x0010;
        const int computedPasswordExpired = 0x800000;

        if ((computed & computedLockout) != 0 || lockoutTime is not null)
        {
            flags |= AdAccountFlags.LockedOut;
        }

        if ((computed & computedPasswordExpired) != 0)
        {
            flags |= AdAccountFlags.PasswordExpired;
        }

        return flags;
    }

    /// <summary>Determines the delegation configured on an account.</summary>
    public static AdDelegationKind MapDelegation(
        int uac,
        IReadOnlyCollection<string> allowedToDelegateTo,
        bool resourceBased)
    {
        if ((uac & TrustedForDelegation) != 0)
        {
            return AdDelegationKind.Unconstrained;
        }

        if (allowedToDelegateTo.Count > 0)
        {
            return (uac & TrustedToAuthForDelegation) != 0
                ? AdDelegationKind.ConstrainedWithProtocolTransition
                : AdDelegationKind.ConstrainedKerberosOnly;
        }

        return resourceBased ? AdDelegationKind.ResourceBasedConstrained : AdDelegationKind.None;
    }

    /// <summary>Maps the groupType bit field onto the normalised scope.</summary>
    public static AdGroupScope MapGroupScope(int groupType)
    {
        if ((groupType & GroupBuiltinLocal) != 0)
        {
            return AdGroupScope.BuiltinLocal;
        }

        if ((groupType & GroupUniversal) != 0)
        {
            return AdGroupScope.Universal;
        }

        if ((groupType & GroupDomainLocal) != 0)
        {
            return AdGroupScope.DomainLocal;
        }

        return (groupType & GroupGlobal) != 0 ? AdGroupScope.Global : AdGroupScope.Global;
    }
}
