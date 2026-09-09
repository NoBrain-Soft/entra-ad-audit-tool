using Ipa.Contracts;
using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;

namespace Ipa.Core.Tests.Fixtures;

/// <summary>
/// A sanitised synthetic environment used by the rule and scoring tests. Every identifier is
/// fabricated: no value here comes from a real directory or tenant.
/// </summary>
public static class SyntheticEnvironment
{
    /// <summary>Fixed reference instant, so every age-based rule is deterministic.</summary>
    public static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    public const string DomainSid = "S-1-5-21-1111111111-2222222222-3333333333";
    public const string DomainDn = "DC=corp,DC=example";

    /// <summary>Builds a forest that satisfies the rule pack's expectations.</summary>
    public static ActiveDirectoryEvidence HealthyForest()
    {
        var domainAdmins = WellKnownSids.DomainRelative(DomainSid, WellKnownSids.DomainAdminsRid);
        var protectedUsers = WellKnownSids.DomainRelative(DomainSid, WellKnownSids.ProtectedUsersRid);

        var admin = new AdPrincipal
        {
            Sid = $"{DomainSid}-1105",
            ObjectGuid = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001"),
            DistinguishedName = $"CN=adm.alice,OU=Tier0,{DomainDn}",
            SamAccountName = "adm.alice",
            UserPrincipalName = "adm.alice@corp.example",
            DomainSid = DomainSid,
            DomainDnsName = "corp.example",
            LastLogonTimestamp = Reference.AddDays(-2),
            PasswordLastSet = Reference.AddDays(-30),
            AdminCount = true,
        };

        var user = new AdPrincipal
        {
            Sid = $"{DomainSid}-1201",
            ObjectGuid = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000002"),
            DistinguishedName = $"CN=bob,OU=Staff,{DomainDn}",
            SamAccountName = "bob",
            UserPrincipalName = "bob@corp.example",
            DomainSid = DomainSid,
            DomainDnsName = "corp.example",
            LastLogonTimestamp = Reference.AddDays(-1),
            PasswordLastSet = Reference.AddDays(-10),
        };

        var krbtgt = new AdPrincipal
        {
            Sid = $"{DomainSid}-502",
            DistinguishedName = $"CN=krbtgt,CN=Users,{DomainDn}",
            SamAccountName = "krbtgt",
            DomainSid = DomainSid,
            Flags = AdAccountFlags.Disabled,
            PasswordLastSet = Reference.AddDays(-20),
        };

        return new ActiveDirectoryEvidence
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
                    KrbtgtPasswordLastSet = Reference.AddDays(-20),
                    RecycleBinEnabled = true,
                    IsRootDomain = true,
                    PasswordPolicy = new AdPasswordPolicy
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
                    },
                },
            ],
            DomainControllers =
            [
                new AdDomainController
                {
                    DnsHostName = "dc01.corp.example", DomainDnsName = "corp.example",
                    SiteName = "HQ", IsGlobalCatalog = true, LdapsAvailable = true,
                },
                new AdDomainController
                {
                    DnsHostName = "dc02.corp.example", DomainDnsName = "corp.example",
                    SiteName = "HQ", IsGlobalCatalog = true, LdapsAvailable = true,
                },
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
            Users = [admin, user, krbtgt],
            Computers =
            [
                new AdComputer
                {
                    Sid = $"{DomainSid}-1301",
                    DistinguishedName = $"CN=DC01,OU=Domain Controllers,{DomainDn}",
                    SamAccountName = "DC01$",
                    DnsHostName = "dc01.corp.example",
                    OperatingSystem = "Windows Server 2022 Datacenter",
                    LastLogonTimestamp = Reference.AddHours(-1),
                    IsDomainController = true,
                },
            ],
            Groups =
            [
                new AdGroup
                {
                    Sid = domainAdmins,
                    DistinguishedName = $"CN=Domain Admins,CN=Users,{DomainDn}",
                    SamAccountName = "Domain Admins",
                    DomainSid = DomainSid,
                    AdminCount = true,
                    MemberDistinguishedNames = [admin.DistinguishedName],
                },
                new AdGroup
                {
                    Sid = protectedUsers,
                    DistinguishedName = $"CN=Protected Users,CN=Users,{DomainDn}",
                    SamAccountName = "Protected Users",
                    DomainSid = DomainSid,
                    MemberDistinguishedNames = [admin.DistinguishedName],
                },
            ],
            AccessControlEntries =
            [
                new AdAccessControlEntry
                {
                    ObjectDistinguishedName = DomainDn,
                    ObjectClass = "domainDNS",
                    TrusteeSid = WellKnownSids.DomainRelative(DomainSid, WellKnownSids.DomainAdminsRid),
                    Rights = AdAceRight.GenericAll,
                },
                new AdAccessControlEntry
                {
                    ObjectDistinguishedName = $"CN=AdminSDHolder,CN=System,{DomainDn}",
                    ObjectClass = "container",
                    TrusteeSid = WellKnownSids.BuiltinAdministrators,
                    Rights = AdAceRight.GenericAll,
                },
            ],
            GroupPolicies =
            [
                new GroupPolicyObject
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
                },
            ],
            CertificateServices = new AdCertificateServicesEvidence(),
            ReferenceTime = Reference,
        };
    }

    /// <summary>Builds a forest with a representative set of weaknesses.</summary>
    public static ActiveDirectoryEvidence WeakForest()
    {
        var healthy = HealthyForest();
        var domain = healthy.Domains[0];

        var kerberoastableAdmin = healthy.Users[0] with
        {
            ServicePrincipalNames = ["MSSQLSvc/sql01.corp.example:1433"],
            PasswordLastSet = Reference.AddDays(-900),
            LastLogonTimestamp = Reference.AddDays(-400),
        };

        var weakUser = healthy.Users[1] with
        {
            Flags = AdAccountFlags.PasswordNeverExpires | AdAccountFlags.DoesNotRequirePreAuth
                    | AdAccountFlags.PasswordNotRequired,
            SidHistory = ["S-1-5-21-9-9-9-1105"],
            LastLogonTimestamp = Reference.AddDays(-500),
        };

        return healthy with
        {
            Domains =
            [
                domain with
                {
                    MachineAccountQuota = 10,
                    FunctionalLevel = 4,
                    RecycleBinEnabled = false,
                    KrbtgtPasswordLastSet = Reference.AddDays(-3000),
                    PasswordPolicy = domain.PasswordPolicy! with
                    {
                        MinimumPasswordLength = 7,
                        ComplexityEnabled = false,
                        ReversibleEncryptionEnabled = true,
                        LockoutThreshold = 0,
                        PasswordHistoryLength = 0,
                    },
                },
            ],
            Users = [kerberoastableAdmin, weakUser, healthy.Users[2]],
            Computers =
            [
                healthy.Computers[0],
                new AdComputer
                {
                    Sid = $"{DomainSid}-1401",
                    DistinguishedName = $"CN=LEGACY01,OU=Servers,{DomainDn}",
                    SamAccountName = "LEGACY01$",
                    OperatingSystem = "Windows Server 2008 R2 Standard",
                    LastLogonTimestamp = Reference.AddDays(-800),
                    Delegation = AdDelegationKind.Unconstrained,
                },
            ],
            Groups =
            [
                healthy.Groups[0] with
                {
                    MemberDistinguishedNames =
                    [
                        kerberoastableAdmin.DistinguishedName,
                        $"CN=Nested Admins,OU=Groups,{DomainDn}",
                    ],
                },
                healthy.Groups[1] with { MemberDistinguishedNames = [] },
                new AdGroup
                {
                    Sid = $"{DomainSid}-1500",
                    DistinguishedName = $"CN=Nested Admins,OU=Groups,{DomainDn}",
                    SamAccountName = "Nested Admins",
                    DomainSid = DomainSid,
                    MemberDistinguishedNames = [weakUser.DistinguishedName],
                },
            ],
            AccessControlEntries =
            [
                new AdAccessControlEntry
                {
                    ObjectDistinguishedName = DomainDn,
                    ObjectClass = "domainDNS",
                    TrusteeSid = $"{DomainSid}-1201",
                    TrusteeName = "bob",
                    Rights = AdAceRight.ExtendedRight,
                    ObjectTypeGuid = ExtendedRights.ReplicatingDirectoryChangesAll,
                    ExtendedRightName = "DS-Replication-Get-Changes-All",
                },
                new AdAccessControlEntry
                {
                    ObjectDistinguishedName = $"CN=AdminSDHolder,CN=System,{DomainDn}",
                    ObjectClass = "container",
                    TrusteeSid = $"{DomainSid}-1201",
                    TrusteeName = "bob",
                    Rights = AdAceRight.GenericAll,
                },
            ],
            GroupPolicies =
            [
                healthy.GroupPolicies[0] with
                {
                    RegistrySettings = [],
                    PreferencePasswords =
                    [
                        new GpoPreferencePasswordArtifact
                        {
                            RelativePath = @"corp.example\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml",
                            Element = "Groups/User/Properties",
                            AccountName = "LocalAdmin",
                        },
                    ],
                    Permissions =
                    [
                        new GpoPermissionEntry
                        {
                            TrusteeSid = $"{DomainSid}-1201",
                            TrusteeName = "bob",
                            Rights = "GenericWrite",
                            AppliesToSysvol = true,
                        },
                    ],
                },
            ],
        };
    }

    /// <summary>Builds a tenant that satisfies the rule pack's expectations.</summary>
    public static EntraEvidence HealthyTenant()
    {
        var admin = new EntraUser
        {
            ObjectId = "00000000-0000-0000-0000-0000000000a1",
            UserPrincipalName = "adm.alice@contoso.com",
            UserType = "Member",
            CreatedDateTime = Reference.AddYears(-2),
            LastSignInDateTime = Reference.AddDays(-1),
            Registration = new MfaRegistrationState { IsMfaRegistered = true, IsMfaCapable = true },
        };

        var breakGlassOne = new EntraUser
        {
            ObjectId = "00000000-0000-0000-0000-0000000000b1",
            UserPrincipalName = "break.glass.one@contoso.com",
            UserType = "Member",
            LastSignInDateTime = Reference.AddDays(-10),
            Registration = new MfaRegistrationState { IsMfaRegistered = true },
        };

        var breakGlassTwo = breakGlassOne with
        {
            ObjectId = "00000000-0000-0000-0000-0000000000b2",
            UserPrincipalName = "break.glass.two@contoso.com",
        };

        var member = new EntraUser
        {
            ObjectId = "00000000-0000-0000-0000-0000000000c1",
            UserPrincipalName = "bob@contoso.com",
            UserType = "Member",
            LastSignInDateTime = Reference.AddDays(-2),
            Registration = new MfaRegistrationState { IsMfaRegistered = true },
        };

        return new EntraEvidence
        {
            Tenant = new EntraTenant
            {
                TenantId = "00000000-0000-0000-0000-0000000000ff",
                DisplayName = "Contoso",
                Domains =
                [
                    new EntraDomain
                    {
                        Name = "contoso.com", IsVerified = true, IsDefault = true,
                        AuthenticationType = "Managed",
                    },
                ],
                ServicePlans = ["AAD_PREMIUM", "AAD_PREMIUM_P2"],
                OnPremisesSyncEnabled = true,
                LastDirectorySyncTime = Reference.AddHours(-1),
            },
            Users = [admin, breakGlassOne, breakGlassTwo, member],
            RoleAssignments =
            [
                Assignment("62e90394-69f5-4237-9190-012177145e10", "Global Administrator", admin.ObjectId, RoleAssignmentKind.Eligible),
                Assignment("62e90394-69f5-4237-9190-012177145e10", "Global Administrator", breakGlassOne.ObjectId, RoleAssignmentKind.Permanent),
                Assignment("62e90394-69f5-4237-9190-012177145e10", "Global Administrator", breakGlassTwo.ObjectId, RoleAssignmentKind.Permanent),
            ],
            ConditionalAccessPolicies =
            [
                new ConditionalAccessPolicy
                {
                    PolicyId = "policy-mfa",
                    DisplayName = "Require multi-factor authentication for all users",
                    State = "enabled",
                    IncludeUsers = ["All"],
                    ExcludeUsers = [breakGlassOne.ObjectId, breakGlassTwo.ObjectId],
                    IncludeApplications = ["All"],
                    GrantControls = new ConditionalAccessGrantControls { BuiltInControls = ["mfa"] },
                    ModifiedDateTime = Reference.AddDays(-5),
                },
                new ConditionalAccessPolicy
                {
                    PolicyId = "policy-legacy",
                    DisplayName = "Block legacy authentication",
                    State = "enabled",
                    IncludeUsers = ["All"],
                    IncludeApplications = ["All"],
                    ClientAppTypes = ["exchangeActiveSync", "other"],
                    GrantControls = new ConditionalAccessGrantControls { BuiltInControls = ["block"] },
                    ModifiedDateTime = Reference.AddDays(-5),
                },
                new ConditionalAccessPolicy
                {
                    PolicyId = "policy-device",
                    DisplayName = "Require a compliant device",
                    State = "enabled",
                    IncludeUsers = ["All"],
                    IncludeApplications = ["All"],
                    GrantControls = new ConditionalAccessGrantControls { BuiltInControls = ["compliantDevice"] },
                    ModifiedDateTime = Reference.AddDays(-5),
                },
                new ConditionalAccessPolicy
                {
                    PolicyId = "policy-risk",
                    DisplayName = "Respond to sign-in risk",
                    State = "enabled",
                    IncludeUsers = ["All"],
                    IncludeApplications = ["All"],
                    SignInRiskLevels = ["high"],
                    GrantControls = new ConditionalAccessGrantControls { BuiltInControls = ["mfa"] },
                    ModifiedDateTime = Reference.AddDays(-5),
                },
            ],
            AuthenticationMethods = new AuthenticationMethodsConfiguration
            {
                MethodStates = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
                {
                    ["fido2"] = true,
                    ["microsoftAuthenticator"] = true,
                    ["sms"] = false,
                },
                SecurityDefaultsEnabled = false,
                LegacyPerUserMfaInUse = false,
            },
            LegacyAuthentication = [],
            ReferenceTime = Reference,
        };
    }

    /// <summary>Builds a tenant with a representative set of weaknesses.</summary>
    public static EntraEvidence WeakTenant()
    {
        var healthy = HealthyTenant();

        var guestAdmin = new EntraUser
        {
            ObjectId = "00000000-0000-0000-0000-0000000000d1",
            UserPrincipalName = "external_partner#EXT#@contoso.onmicrosoft.com",
            UserType = "Guest",
            CreatedDateTime = Reference.AddYears(-1),
            ExternalUserState = "PendingAcceptance",
        };

        return healthy with
        {
            Users = [.. healthy.Users.Select(user => user with { Registration = null }), guestAdmin],
            RoleAssignments =
            [
                Assignment("62e90394-69f5-4237-9190-012177145e10", "Global Administrator", healthy.Users[0].ObjectId, RoleAssignmentKind.Permanent),
                Assignment("62e90394-69f5-4237-9190-012177145e10", "Global Administrator", guestAdmin.ObjectId, RoleAssignmentKind.Permanent),
            ],
            ConditionalAccessPolicies = [],
            AuthenticationMethods = new AuthenticationMethodsConfiguration
            {
                MethodStates = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
                {
                    ["sms"] = true,
                    ["voice"] = true,
                },
                SecurityDefaultsEnabled = false,
                LegacyPerUserMfaInUse = true,
            },
            LegacyAuthentication =
            [
                new LegacyAuthenticationObservation
                {
                    ClientApplication = "IMAP4",
                    SignInCount = 42,
                    SuccessfulSignInCount = 12,
                    DistinctUserCount = 3,
                    LastObserved = Reference.AddDays(-1),
                },
            ],
            ServicePrincipals =
            [
                new EntraServicePrincipal
                {
                    ObjectId = "sp-1",
                    AppId = "app-1",
                    DisplayName = "Legacy Integration",
                    AppRoleGrants =
                    [
                        new GrantedAppRole
                        {
                            ResourceAppId = "graph",
                            ResourceDisplayName = "Microsoft Graph",
                            PermissionValue = "Directory.ReadWrite.All",
                        },
                    ],
                },
            ],
            Applications =
            [
                new EntraApplication
                {
                    ObjectId = "app-object-1",
                    AppId = "app-1",
                    DisplayName = "Legacy Integration",
                    SignInAudience = "AzureADMultipleOrgs",
                    Credentials =
                    [
                        new DirectoryCredential
                        {
                            KeyId = "key-1",
                            CredentialType = "password",
                            StartDateTime = Reference.AddYears(-4),
                            EndDateTime = Reference.AddDays(-30),
                        },
                    ],
                },
            ],
        };
    }

    private static EntraRoleAssignment Assignment(
        string roleId,
        string roleName,
        string principalId,
        RoleAssignmentKind kind) => new()
    {
        RoleDefinitionId = roleId,
        RoleName = roleName,
        PrincipalId = principalId,
        PrincipalDisplayName = principalId,
        PrincipalType = "user",
        Kind = kind,
    };

    private static RegistryPolicySetting Registry(string key, string name, string value) => new()
    {
        KeyPath = key,
        ValueName = name,
        ValueType = 4,
        Value = value,
    };
}
