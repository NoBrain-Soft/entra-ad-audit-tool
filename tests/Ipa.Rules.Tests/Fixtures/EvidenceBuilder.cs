using Ipa.Contracts;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;

namespace Ipa.Rules.Tests.Fixtures;

/// <summary>
/// Builds sanitised evidence fixtures for rule tests. Every identifier is fabricated: nothing here
/// comes from a real directory or tenant.
/// </summary>
public static class EvidenceBuilder
{
    /// <summary>Fixed reference instant, so every age-based rule is deterministic.</summary>
    public static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Fabricated domain identifier used throughout the fixtures.</summary>
    public const string DomainSid = "S-1-5-21-1111111111-2222222222-3333333333";

    /// <summary>Fabricated domain distinguished name.</summary>
    public const string DomainDn = "DC=corp,DC=example";

    /// <summary>Evidence with nothing collected, for the missing-evidence contract.</summary>
    public static NormalizedEvidence Empty() => new()
    {
        Availability = EvidenceKeys.All.ToDictionary(
            key => key,
            key => new EvidenceAvailabilityEntry
            {
                EvidenceKey = key,
                Availability = EvidenceAvailability.NotSelected,
                Reason = "The evidence set was not part of this assessment.",
            },
            StringComparer.OrdinalIgnoreCase),
        ReferenceTime = Reference,
    };

    /// <summary>Evidence where every set is marked collected but the collections are empty.</summary>
    public static NormalizedEvidence Sparse() => new()
    {
        ActiveDirectory = MinimalForest(),
        Entra = MinimalTenant(),
        Hybrid = MinimalHybrid(),
        Availability = AllCollected(),
        ReferenceTime = Reference,
    };

    /// <summary>Marks every evidence set as collected.</summary>
    public static Dictionary<string, EvidenceAvailabilityEntry> AllCollected() =>
        EvidenceKeys.All.ToDictionary(
            key => key,
            key => new EvidenceAvailabilityEntry
            {
                EvidenceKey = key,
                Availability = EvidenceAvailability.Collected,
            },
            StringComparer.OrdinalIgnoreCase);

    /// <summary>Marks one evidence set as unavailable, leaving the rest collected.</summary>
    public static Dictionary<string, EvidenceAvailabilityEntry> AllCollectedExcept(
        string missingKey,
        EvidenceAvailability availability = EvidenceAvailability.PermissionDenied)
    {
        var map = AllCollected();

        map[missingKey] = new EvidenceAvailabilityEntry
        {
            EvidenceKey = missingKey,
            Availability = availability,
            Reason = "The permission required for this data was not granted.",
        };

        return map;
    }

    /// <summary>A forest with the required shape but no principals, groups or policies.</summary>
    public static ActiveDirectoryEvidence MinimalForest() => new()
    {
        Forest = new AdForest
        {
            ForestRootDomain = "corp.example",
            ForestFunctionalLevel = 7,
            SchemaVersion = 88,
            DomainNamingContexts = [DomainDn],
        },
        Domains =
        [
            new AdDomain
            {
                DnsName = "corp.example",
                NetBiosName = "CORP",
                DomainSid = DomainSid,
                DistinguishedName = DomainDn,
                FunctionalLevel = 7,
                MachineAccountQuota = 0,
                RecycleBinEnabled = true,
                KrbtgtPasswordLastSet = Reference.AddDays(-30),
                PasswordPolicy = StrongPasswordPolicy(),
            },
        ],
        DomainControllers =
        [
            Controller("dc01.corp.example"),
            Controller("dc02.corp.example"),
        ],
        Sites =
        [
            new AdSite
            {
                Name = "HQ",
                Subnets = ["10.0.0.0/24"],
                DomainControllers = ["dc01.corp.example", "dc02.corp.example"],
            },
        ],
        AccessControlEntries =
        [
            new AdAccessControlEntry
            {
                ObjectDistinguishedName = $"CN=AdminSDHolder,CN=System,{DomainDn}",
                ObjectClass = "container",
                TrusteeSid = WellKnownSids.BuiltinAdministrators,
                Rights = AdAceRight.GenericAll,
            },
        ],
        GroupPolicies = [HardenedPolicy()],
        CertificateServices = new AdCertificateServicesEvidence(),
        ReferenceTime = Reference,
    };

    /// <summary>A tenant with the required shape but no users, applications or policies.</summary>
    public static EntraEvidence MinimalTenant() => new()
    {
        Tenant = new EntraTenant
        {
            TenantId = "00000000-0000-0000-0000-0000000000ff",
            DisplayName = "Contoso",
            Domains =
            [
                new EntraDomain
                {
                    Name = "contoso.com",
                    IsVerified = true,
                    IsDefault = true,
                    AuthenticationType = "Managed",
                },
            ],
            ServicePlans = [],
            OnPremisesSyncEnabled = false,
        },
        AuthenticationMethods = new AuthenticationMethodsConfiguration
        {
            MethodStates = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase) { ["fido2"] = true },
            SecurityDefaultsEnabled = true,
        },
        ReferenceTime = Reference,
    };

    /// <summary>Hybrid evidence with nothing correlated.</summary>
    public static HybridEvidence MinimalHybrid() => new()
    {
        LastDirectorySyncTime = Reference.AddHours(-1),
        ReferenceTime = Reference,
    };

    /// <summary>A password policy that satisfies every domain-policy rule.</summary>
    public static AdPasswordPolicy StrongPasswordPolicy() => new()
    {
        DomainDnsName = "corp.example",
        MinimumPasswordLength = 14,
        PasswordHistoryLength = 24,
        ComplexityEnabled = true,
        ReversibleEncryptionEnabled = false,
        LockoutThreshold = 5,
        LockoutDuration = TimeSpan.FromMinutes(30),
        LockoutObservationWindow = TimeSpan.FromMinutes(30),
        MaximumPasswordAge = TimeSpan.FromDays(365),
    };

    /// <summary>A Group Policy object configuring every hardening value the rules check.</summary>
    public static GroupPolicyObject HardenedPolicy() => new()
    {
        Guid = "31B2F340-016D-11D2-945F-00C04FB984F9",
        DisplayName = "Default Domain Policy",
        DomainDnsName = "corp.example",
        DirectoryVersion = 5,
        SysvolVersion = 5,
        Links = [new GpoLink { TargetDistinguishedName = DomainDn, TargetType = "domain" }],
        RegistrySettings =
        [
            Registry(@"System\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity", "2"),
            Registry(@"System\CurrentControlSet\Services\NTDS\Parameters", "LdapEnforceChannelBinding", "2"),
            Registry(@"System\CurrentControlSet\Services\LanManServer\Parameters", "RequireSecuritySignature", "1"),
            Registry(@"System\CurrentControlSet\Services\LanManServer\Parameters", "SMB1", "0"),
            Registry(@"System\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", "5"),
        ],
        SecuritySettings =
        [
            new SecurityTemplateSetting
            {
                Section = "Privilege Rights",
                Name = "SeDebugPrivilege",
                Value = "*" + WellKnownSids.BuiltinAdministrators,
                Trustees = [WellKnownSids.BuiltinAdministrators],
            },
        ],
        Permissions =
        [
            new GpoPermissionEntry
            {
                TrusteeSid = WellKnownSids.DomainRelative(DomainSid, WellKnownSids.DomainAdminsRid),
                Rights = "GenericAll",
                AppliesToSysvol = false,
            },
        ],
    };

    /// <summary>Builds a registry policy setting.</summary>
    public static RegistryPolicySetting Registry(string key, string name, string value) => new()
    {
        KeyPath = key,
        ValueName = name,
        ValueType = 4,
        Value = value,
    };

    /// <summary>Builds a domain controller entry.</summary>
    public static AdDomainController Controller(string hostName) => new()
    {
        DnsHostName = hostName,
        DomainDnsName = "corp.example",
        SiteName = "HQ",
        IsGlobalCatalog = true,
        LdapsAvailable = true,
    };

    /// <summary>Builds a user principal with sensible defaults.</summary>
    public static AdPrincipal User(
        int rid,
        string name,
        AdAccountFlags flags = AdAccountFlags.None,
        DateTimeOffset? lastLogon = null,
        DateTimeOffset? passwordSet = null) => new()
    {
        Sid = $"{DomainSid}-{rid}",
        ObjectGuid = Guid.Parse($"aaaaaaaa-0000-0000-0000-{rid:D12}"),
        DistinguishedName = $"CN={name},OU=Staff,{DomainDn}",
        SamAccountName = name,
        UserPrincipalName = $"{name}@corp.example",
        DomainSid = DomainSid,
        DomainDnsName = "corp.example",
        Flags = flags,
        LastLogonTimestamp = lastLogon ?? Reference.AddDays(-1),
        PasswordLastSet = passwordSet ?? Reference.AddDays(-10),
    };

    /// <summary>Builds the Domain Admins group holding the supplied members.</summary>
    public static AdGroup DomainAdmins(params AdPrincipal[] members) => new()
    {
        Sid = WellKnownSids.DomainRelative(DomainSid, WellKnownSids.DomainAdminsRid),
        DistinguishedName = $"CN=Domain Admins,CN=Users,{DomainDn}",
        SamAccountName = "Domain Admins",
        DomainSid = DomainSid,
        AdminCount = true,
        MemberDistinguishedNames = members.Select(member => member.DistinguishedName).ToList(),
    };

    /// <summary>Builds an Entra user with sensible defaults.</summary>
    public static EntraUser EntraUser(
        string id,
        string upn,
        string userType = "Member",
        bool enabled = true,
        bool mfaRegistered = true,
        DateTimeOffset? lastSignIn = null) => new()
    {
        ObjectId = id,
        UserPrincipalName = upn,
        UserType = userType,
        AccountEnabled = enabled,
        CreatedDateTime = Reference.AddYears(-1),
        LastSignInDateTime = lastSignIn ?? Reference.AddDays(-1),
        Registration = new MfaRegistrationState { IsMfaRegistered = mfaRegistered, IsMfaCapable = mfaRegistered },
    };
}
