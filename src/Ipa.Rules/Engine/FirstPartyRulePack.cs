using Ipa.Contracts.Rules;
using Ipa.Rules.Evaluators.ActiveDirectory;
using Ipa.Rules.Evaluators.Baseline;
using Ipa.Rules.Evaluators.Entra;
using Ipa.Rules.Evaluators.Hybrid;

namespace Ipa.Rules.Engine;

/// <summary>
/// The single first-party rule pack shipped with the application. Rules are listed explicitly
/// rather than discovered by reflection: version one deliberately loads no rule code from disk,
/// so every score can be tied to a signed release.
/// </summary>
public sealed class FirstPartyRulePack : IRulePack
{
    /// <summary>
    /// Pack version. Increment when any rule is added, removed, or has its evaluation semantics
    /// changed, so that a report's scores remain reproducible against a named pack.
    /// </summary>
    public const string PackVersion = "2026.09.1";

    private static readonly Lazy<FirstPartyRulePack> Instance = new(() =>
        (FirstPartyRulePack)RulePackValidator.Validate(new FirstPartyRulePack()));

    /// <summary>The validated singleton instance of the pack.</summary>
    public static FirstPartyRulePack Current => Instance.Value;

    private FirstPartyRulePack()
    {
        Rules =
        [
            // Active Directory - privileged access
            new TierZeroMembershipSizeRule(),
            new TierZeroNestingRule(),
            new PrivilegedAccountSpnRule(),
            new ProtectedUsersRule(),
            new StalePrivilegedAccountRule(),
            new PrivilegedPasswordAgeRule(),
            new OrphanedAdminCountRule(),

            // Active Directory - account hygiene
            new StaleUserAccountRule(),
            new PasswordNeverExpiresRule(),
            new PasswordNotRequiredRule(),
            new KerberosPreAuthenticationRule(),
            new SidHistoryRule(),
            new StaleComputerAccountRule(),
            new UnsupportedOperatingSystemRule(),

            // Active Directory - delegation and access control
            new UnconstrainedDelegationRule(),
            new ProtocolTransitionRule(),
            new ReplicationRightsRule(),
            new DangerousAclRule(),
            new AdminSdHolderRule(),

            // Active Directory - domain policy
            new MinimumPasswordLengthRule(),
            new PasswordComplexityRule(),
            new ReversibleEncryptionRule(),
            new AccountLockoutRule(),
            new PasswordHistoryRule(),
            new KrbtgtRotationRule(),
            new MachineAccountQuotaRule(),
            new DomainFunctionalLevelRule(),
            new RecycleBinRule(),

            // Active Directory - trusts and topology
            new SidFilteringRule(),
            new SelectiveAuthenticationRule(),
            new ForestFunctionalLevelRule(),
            new DomainControllerRedundancyRule(),
            new SiteTopologyRule(),

            // Active Directory - Group Policy
            new GpoPermissionRule(),
            new GpoPreferencePasswordRule(),
            new GpoConsistencyRule(),
            new LdapServerSigningRule(),
            new LdapChannelBindingRule(),
            new SmbSigningRule(),
            new LmCompatibilityRule(),
            new SmbV1Rule(),
            new PrivilegedLogonRightsRule(),

            // Active Directory - certificate services
            new RequesterSuppliedSubjectRule(),
            new DangerousEkuTemplateRule(),
            new CertificateObjectControlRule(),
            new CertificateServiceScopeNoticeRule(),

            // Entra - privileged access
            new GlobalAdministratorCountRule(),
            new JustInTimePrivilegeRule(),
            new GuestAdministratorRule(),
            new PrivilegedMfaRegistrationRule(),
            new InactivePrivilegedAccountRule(),
            new EmergencyAccessAccountRule(),
            new PrivilegedServicePrincipalRule(),

            // Entra - authentication
            new MfaRegistrationCoverageRule(),
            new LegacyAuthenticationBlockedRule(),
            new LegacyAuthenticationObservedRule(),
            new AuthenticationMethodPolicyRule(),
            new BaselineProtectionRule(),
            new PerUserMfaRule(),

            // Entra - Conditional Access
            new MfaForAllUsersRule(),
            new MfaForAdministratorsRule(),
            new ConditionalAccessExclusionRule(),
            new ReportOnlyPolicyRule(),
            new RiskBasedPolicyRule(),
            new DeviceComplianceRule(),

            // Entra - applications
            new ApplicationCredentialLifetimeRule(),
            new ExpiringCredentialRule(),
            new HighImpactApplicationPermissionRule(),
            new TenantWideConsentRule(),
            new ApplicationOwnerRule(),
            new MultiTenantApplicationRule(),

            // Entra - directory hygiene and provider metrics
            new StaleMemberAccountRule(),
            new StaleGuestAccountRule(),
            new StaleDeviceRule(),
            new RetainedDisabledAccountRule(),
            new SecureScoreAvailabilityRule(),

            // Hybrid
            new DuplicateAnchorRule(),
            new OrphanedCloudObjectRule(),
            new AmbiguousCorrelationRule(),
            new SynchronisedPrivilegedAccountRule(),
            new SyncServiceAccountRule(),
            new OnPremisesPrivilegeSyncRule(),
            new SynchronisationFreshnessRule(),
            new FederationCertificateRule(),
            new FederationMfaRule(),

            // Separately reported baseline metric
            new BaselineConformityRule(),
        ];

        Definitions = Rules.Select(rule => rule.Definition).ToList();
    }

    /// <inheritdoc />
    public string Version => PackVersion;

    /// <inheritdoc />
    public IReadOnlyList<RuleBase> Rules { get; }

    /// <inheritdoc />
    public IReadOnlyList<RuleDefinition> Definitions { get; }
}
