namespace Ipa.Contracts.Evidence;

/// <summary>A verified or unverified domain registered on the tenant.</summary>
public sealed record EntraDomain
{
    public required string Name { get; init; }
    public bool IsVerified { get; init; }
    public bool IsDefault { get; init; }
    public bool IsInitial { get; init; }

    /// <summary>Authentication type: <c>Managed</c> or <c>Federated</c>.</summary>
    public required string AuthenticationType { get; init; }

    public string? FederationIssuerUri { get; init; }
    public string? FederationSigningCertificateExpiry { get; init; }
    public bool FederatedSignOnSupportsMfa { get; init; }
}

/// <summary>Tenant-level facts used for applicability decisions.</summary>
public sealed record EntraTenant
{
    public required string TenantId { get; init; }
    public required string DisplayName { get; init; }
    public IReadOnlyList<EntraDomain> Domains { get; init; } = [];

    /// <summary>Service plans detected on the tenant, used to decide licence-gated applicability.</summary>
    public IReadOnlyList<string> ServicePlans { get; init; } = [];

    /// <summary>True when on-premises directory synchronisation is enabled for the tenant.</summary>
    public bool OnPremisesSyncEnabled { get; init; }

    public DateTimeOffset? LastDirectorySyncTime { get; init; }

    /// <summary>National cloud identifier, for example <c>global</c>. Only the global cloud is supported in v1.</summary>
    public string CloudInstance { get; init; } = "global";
}

/// <summary>Registration state of strong authentication for a user.</summary>
public sealed record MfaRegistrationState
{
    public bool IsMfaRegistered { get; init; }
    public bool IsMfaCapable { get; init; }
    public bool IsPasswordlessCapable { get; init; }
    public bool IsSsprRegistered { get; init; }
    public IReadOnlyList<string> Methods { get; init; } = [];
}

/// <summary>A normalised Entra user.</summary>
public sealed record EntraUser
{
    public required string ObjectId { get; init; }
    public required string UserPrincipalName { get; init; }
    public string? DisplayName { get; init; }
    public bool AccountEnabled { get; init; } = true;

    /// <summary><c>Member</c> or <c>Guest</c>.</summary>
    public required string UserType { get; init; }

    public DateTimeOffset? CreatedDateTime { get; init; }
    public DateTimeOffset? LastSignInDateTime { get; init; }
    public DateTimeOffset? LastNonInteractiveSignInDateTime { get; init; }
    public bool OnPremisesSyncEnabled { get; init; }
    public string? OnPremisesImmutableId { get; init; }
    public string? OnPremisesSecurityIdentifier { get; init; }
    public string? OnPremisesDistinguishedName { get; init; }
    public string? OnPremisesSamAccountName { get; init; }
    public MfaRegistrationState? Registration { get; init; }
    public IReadOnlyList<string> AssignedLicenseSkus { get; init; } = [];
    public string? ExternalUserState { get; init; }
}

/// <summary>A normalised Entra group.</summary>
public sealed record EntraGroup
{
    public required string ObjectId { get; init; }
    public required string DisplayName { get; init; }
    public bool SecurityEnabled { get; init; }
    public bool IsAssignableToRole { get; init; }
    public bool OnPremisesSyncEnabled { get; init; }
    public string? OnPremisesSecurityIdentifier { get; init; }
    public string? MembershipRule { get; init; }
    public IReadOnlyList<string> MemberObjectIds { get; init; } = [];
    public IReadOnlyList<string> OwnerObjectIds { get; init; } = [];
}

/// <summary>A registered device object.</summary>
public sealed record EntraDevice
{
    public required string ObjectId { get; init; }
    public required string DisplayName { get; init; }
    public bool AccountEnabled { get; init; } = true;
    public string? TrustType { get; init; }
    public string? OperatingSystem { get; init; }
    public string? OperatingSystemVersion { get; init; }
    public bool? IsCompliant { get; init; }
    public bool? IsManaged { get; init; }
    public DateTimeOffset? ApproximateLastSignInDateTime { get; init; }
    public DateTimeOffset? RegistrationDateTime { get; init; }
}

/// <summary>How a directory role is held.</summary>
public enum RoleAssignmentKind
{
    /// <summary>Standing assignment that is always active.</summary>
    Permanent,

    /// <summary>Privileged Identity Management eligible assignment requiring activation.</summary>
    Eligible,

    /// <summary>Privileged Identity Management assignment that is currently activated.</summary>
    Activated,
}

/// <summary>A directory role assignment resolved to its principal.</summary>
public sealed record EntraRoleAssignment
{
    public required string RoleDefinitionId { get; init; }
    public required string RoleName { get; init; }
    public required string PrincipalId { get; init; }
    public required string PrincipalDisplayName { get; init; }

    /// <summary><c>user</c>, <c>group</c> or <c>servicePrincipal</c>.</summary>
    public required string PrincipalType { get; init; }

    public RoleAssignmentKind Kind { get; init; } = RoleAssignmentKind.Permanent;

    /// <summary>Directory scope of the assignment. <c>/</c> denotes tenant-wide.</summary>
    public string Scope { get; init; } = "/";

    public DateTimeOffset? AssignedDateTime { get; init; }
    public DateTimeOffset? ExpiresDateTime { get; init; }
}

/// <summary>A credential on an application registration or service principal.</summary>
public sealed record DirectoryCredential
{
    public required string KeyId { get; init; }

    /// <summary><c>password</c> or <c>certificate</c>.</summary>
    public required string CredentialType { get; init; }

    public string? DisplayName { get; init; }
    public DateTimeOffset? StartDateTime { get; init; }
    public DateTimeOffset? EndDateTime { get; init; }
}

/// <summary>A resource permission requested by an application registration.</summary>
public sealed record RequestedPermission
{
    public required string ResourceAppId { get; init; }
    public required string PermissionId { get; init; }
    public string? PermissionValue { get; init; }

    /// <summary><c>Scope</c> for delegated permissions, <c>Role</c> for application permissions.</summary>
    public required string PermissionKind { get; init; }
}

/// <summary>A normalised application registration owned by the tenant.</summary>
public sealed record EntraApplication
{
    public required string ObjectId { get; init; }
    public required string AppId { get; init; }
    public required string DisplayName { get; init; }
    public string? SignInAudience { get; init; }
    public DateTimeOffset? CreatedDateTime { get; init; }
    public IReadOnlyList<DirectoryCredential> Credentials { get; init; } = [];
    public IReadOnlyList<RequestedPermission> RequestedPermissions { get; init; } = [];
    public IReadOnlyList<string> OwnerObjectIds { get; init; } = [];
    public IReadOnlyList<string> RedirectUris { get; init; } = [];
}

/// <summary>A normalised service principal, including its granted permissions.</summary>
public sealed record EntraServicePrincipal
{
    public required string ObjectId { get; init; }
    public required string AppId { get; init; }
    public required string DisplayName { get; init; }
    public string? ServicePrincipalType { get; init; }
    public bool AccountEnabled { get; init; } = true;
    public bool AppRoleAssignmentRequired { get; init; }
    public IReadOnlyList<DirectoryCredential> Credentials { get; init; } = [];

    /// <summary>Application permissions granted to the principal (<c>Role</c> grants).</summary>
    public IReadOnlyList<GrantedAppRole> AppRoleGrants { get; init; } = [];

    /// <summary>Delegated permission grants (<c>oauth2PermissionGrants</c>).</summary>
    public IReadOnlyList<DelegatedGrant> DelegatedGrants { get; init; } = [];

    public IReadOnlyList<string> OwnerObjectIds { get; init; } = [];
    public IReadOnlyList<string> Tags { get; init; } = [];

    /// <summary>True when the principal is published by Microsoft rather than the tenant.</summary>
    public bool IsMicrosoftPublished { get; init; }
}

/// <summary>An application permission granted to a service principal.</summary>
public sealed record GrantedAppRole
{
    public required string ResourceAppId { get; init; }
    public required string ResourceDisplayName { get; init; }
    public required string PermissionValue { get; init; }
    public DateTimeOffset? CreatedDateTime { get; init; }
}

/// <summary>A delegated permission grant.</summary>
public sealed record DelegatedGrant
{
    public required string ResourceAppId { get; init; }
    public required string ResourceDisplayName { get; init; }

    /// <summary>Space-separated scope list as returned by Microsoft Graph.</summary>
    public required string Scopes { get; init; }

    /// <summary><c>AllPrincipals</c> for tenant-wide admin consent, otherwise <c>Principal</c>.</summary>
    public required string ConsentType { get; init; }

    public string? PrincipalId { get; init; }
}

/// <summary>Conditional Access grant controls in a normalised shape.</summary>
public sealed record ConditionalAccessGrantControls
{
    /// <summary><c>AND</c> or <c>OR</c>.</summary>
    public string Operator { get; init; } = "OR";

    public IReadOnlyList<string> BuiltInControls { get; init; } = [];
    public IReadOnlyList<string> AuthenticationStrengthPolicyIds { get; init; } = [];
}

/// <summary>A normalised Conditional Access policy.</summary>
public sealed record ConditionalAccessPolicy
{
    public required string PolicyId { get; init; }
    public required string DisplayName { get; init; }

    /// <summary><c>enabled</c>, <c>disabled</c> or <c>enabledForReportingButNotEnforced</c>.</summary>
    public required string State { get; init; }

    public IReadOnlyList<string> IncludeUsers { get; init; } = [];
    public IReadOnlyList<string> ExcludeUsers { get; init; } = [];
    public IReadOnlyList<string> IncludeGroups { get; init; } = [];
    public IReadOnlyList<string> ExcludeGroups { get; init; } = [];
    public IReadOnlyList<string> IncludeRoles { get; init; } = [];
    public IReadOnlyList<string> ExcludeRoles { get; init; } = [];
    public IReadOnlyList<string> IncludeApplications { get; init; } = [];
    public IReadOnlyList<string> ExcludeApplications { get; init; } = [];
    public IReadOnlyList<string> IncludeUserActions { get; init; } = [];
    public IReadOnlyList<string> ClientAppTypes { get; init; } = [];
    public IReadOnlyList<string> IncludePlatforms { get; init; } = [];
    public IReadOnlyList<string> ExcludePlatforms { get; init; } = [];
    public IReadOnlyList<string> IncludeLocations { get; init; } = [];
    public IReadOnlyList<string> ExcludeLocations { get; init; } = [];
    public IReadOnlyList<string> UserRiskLevels { get; init; } = [];
    public IReadOnlyList<string> SignInRiskLevels { get; init; } = [];
    public ConditionalAccessGrantControls? GrantControls { get; init; }
    public IReadOnlyList<string> SessionControls { get; init; } = [];
    public DateTimeOffset? CreatedDateTime { get; init; }
    public DateTimeOffset? ModifiedDateTime { get; init; }

    public bool IsEnabled => string.Equals(State, "enabled", StringComparison.OrdinalIgnoreCase);

    public bool IsReportOnly =>
        string.Equals(State, "enabledForReportingButNotEnforced", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the policy targets every user in the tenant.</summary>
    public bool TargetsAllUsers =>
        IncludeUsers.Any(user => string.Equals(user, "All", StringComparison.OrdinalIgnoreCase));

    /// <summary>True when the policy targets every cloud application.</summary>
    public bool TargetsAllApplications =>
        IncludeApplications.Any(app => string.Equals(app, "All", StringComparison.OrdinalIgnoreCase));
}

/// <summary>Tenant authentication-method configuration.</summary>
public sealed record AuthenticationMethodsConfiguration
{
    /// <summary>Method identifier to enabled state, for example <c>fido2</c> or <c>sms</c>.</summary>
    public IReadOnlyDictionary<string, bool> MethodStates { get; init; } =
        new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

    public string? PolicyMigrationState { get; init; }
    public bool SecurityDefaultsEnabled { get; init; }

    /// <summary>True when per-user legacy MFA state is still in use for at least one account.</summary>
    public bool LegacyPerUserMfaInUse { get; init; }
}

/// <summary>An aggregated sign-in observation used for legacy-authentication detection.</summary>
public sealed record LegacyAuthenticationObservation
{
    public required string ClientApplication { get; init; }
    public int SignInCount { get; init; }
    public int SuccessfulSignInCount { get; init; }
    public int DistinctUserCount { get; init; }
    public DateTimeOffset? LastObserved { get; init; }
}

/// <summary>
/// A Microsoft Secure Score snapshot. Microsoft's provider score is always displayed as a
/// separate, clearly attributed metric and is never blended into the product's posture score.
/// </summary>
public sealed record SecureScoreSnapshot
{
    public required DateTimeOffset CreatedDateTime { get; init; }
    public required double CurrentScore { get; init; }
    public required double MaxScore { get; init; }
    public string? AzureTenantId { get; init; }
    public IReadOnlyList<SecureScoreControl> Controls { get; init; } = [];

    public double Percentage => MaxScore <= 0 ? 0 : Math.Round(CurrentScore / MaxScore * 100d, 1);
}

/// <summary>A single Secure Score control profile as reported by Microsoft.</summary>
public sealed record SecureScoreControl
{
    public required string ControlName { get; init; }
    public double Score { get; init; }
    public string? State { get; init; }
    public string? Description { get; init; }
}

/// <summary>The complete normalised Entra view handed to rule evaluators.</summary>
public sealed record EntraEvidence
{
    public required EntraTenant Tenant { get; init; }
    public IReadOnlyList<EntraUser> Users { get; init; } = [];
    public IReadOnlyList<EntraGroup> Groups { get; init; } = [];
    public IReadOnlyList<EntraDevice> Devices { get; init; } = [];
    public IReadOnlyList<EntraRoleAssignment> RoleAssignments { get; init; } = [];
    public IReadOnlyList<EntraApplication> Applications { get; init; } = [];
    public IReadOnlyList<EntraServicePrincipal> ServicePrincipals { get; init; } = [];
    public IReadOnlyList<ConditionalAccessPolicy> ConditionalAccessPolicies { get; init; } = [];
    public AuthenticationMethodsConfiguration? AuthenticationMethods { get; init; }
    public IReadOnlyList<LegacyAuthenticationObservation> LegacyAuthentication { get; init; } = [];
    public SecureScoreSnapshot? SecureScore { get; init; }

    /// <summary>Timestamp used as "now" by every age-based rule, so recalculation is reproducible.</summary>
    public required DateTimeOffset ReferenceTime { get; init; }
}
