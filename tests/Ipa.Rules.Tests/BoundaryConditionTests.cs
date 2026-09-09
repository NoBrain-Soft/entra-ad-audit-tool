using Ipa.Contracts.Directory;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Evaluators.ActiveDirectory;
using Ipa.Rules.Evaluators.Entra;
using Ipa.Rules.Evaluators.Hybrid;
using Ipa.Rules.Tests.Fixtures;
using Xunit;

namespace Ipa.Rules.Tests;

/// <summary>
/// Boundary tests for the rules that compare against a threshold. Each one is exercised exactly at
/// the threshold and one step either side, because an off-by-one there changes a customer's score.
/// </summary>
public sealed class BoundaryConditionTests
{
    private static RuleResult Evaluate(RuleBase rule, NormalizedEvidence evidence) =>
        rule.Evaluate(new RuleEvaluationContext
        {
            Rule = rule.Definition,
            Evidence = evidence,
            ReferenceTime = evidence.ReferenceTime,
        });

    private static NormalizedEvidence WithForest(ActiveDirectoryEvidence forest) => new()
    {
        ActiveDirectory = forest,
        Availability = EvidenceBuilder.AllCollected(),
        ReferenceTime = EvidenceBuilder.Reference,
    };

    private static NormalizedEvidence WithTenant(EntraEvidence tenant) => new()
    {
        Entra = tenant,
        Availability = EvidenceBuilder.AllCollected(),
        ReferenceTime = EvidenceBuilder.Reference,
    };

    [Theory]
    [InlineData(4, RuleStatus.Pass)]
    [InlineData(5, RuleStatus.Pass)]   // exactly at the threshold of five
    [InlineData(6, RuleStatus.Fail)]
    public void TierZeroMembershipThresholdIsInclusive(int memberCount, RuleStatus expected)
    {
        var members = Enumerable.Range(1, memberCount)
            .Select(index => EvidenceBuilder.User(1100 + index, $"adm{index:00}"))
            .ToList();

        var forest = EvidenceBuilder.MinimalForest() with
        {
            Users = members,
            Groups = [EvidenceBuilder.DomainAdmins([.. members])],
        };

        Assert.Equal(expected, Evaluate(new TierZeroMembershipSizeRule(), WithForest(forest)).Status);
    }

    [Theory]
    [InlineData(89, RuleStatus.Pass)]
    [InlineData(90, RuleStatus.Pass)]   // exactly at the ninety-day threshold
    [InlineData(91, RuleStatus.Fail)]
    public void DormantPrivilegedAccountThresholdIsInclusive(int idleDays, RuleStatus expected)
    {
        var admin = EvidenceBuilder.User(
            1105,
            "adm.alice",
            lastLogon: EvidenceBuilder.Reference.AddDays(-idleDays));

        var forest = EvidenceBuilder.MinimalForest() with
        {
            Users = [admin],
            Groups = [EvidenceBuilder.DomainAdmins(admin)],
        };

        Assert.Equal(expected, Evaluate(new StalePrivilegedAccountRule(), WithForest(forest)).Status);
    }

    [Theory]
    [InlineData(13, RuleStatus.Fail)]
    [InlineData(14, RuleStatus.Pass)]   // exactly the required minimum length
    [InlineData(15, RuleStatus.Pass)]
    public void MinimumPasswordLengthThresholdIsInclusive(int length, RuleStatus expected)
    {
        var forest = EvidenceBuilder.MinimalForest();

        forest = forest with
        {
            Domains =
            [
                forest.Domains[0] with
                {
                    PasswordPolicy = EvidenceBuilder.StrongPasswordPolicy() with { MinimumPasswordLength = length },
                },
            ],
        };

        Assert.Equal(expected, Evaluate(new MinimumPasswordLengthRule(), WithForest(forest)).Status);
    }

    [Theory]
    [InlineData(0, RuleStatus.Fail)]    // no lockout at all
    [InlineData(1, RuleStatus.Pass)]
    [InlineData(10, RuleStatus.Pass)]   // exactly at the maximum threshold
    [InlineData(11, RuleStatus.Fail)]
    public void LockoutThresholdBoundsAreInclusive(int threshold, RuleStatus expected)
    {
        var forest = EvidenceBuilder.MinimalForest();

        forest = forest with
        {
            Domains =
            [
                forest.Domains[0] with
                {
                    PasswordPolicy = EvidenceBuilder.StrongPasswordPolicy() with { LockoutThreshold = threshold },
                },
            ],
        };

        Assert.Equal(expected, Evaluate(new AccountLockoutRule(), WithForest(forest)).Status);
    }

    [Theory]
    [InlineData(179, RuleStatus.Pass)]
    [InlineData(180, RuleStatus.Pass)]  // exactly at the rotation threshold
    [InlineData(181, RuleStatus.Fail)]
    public void KeyDistributionRotationThresholdIsInclusive(int ageDays, RuleStatus expected)
    {
        var forest = EvidenceBuilder.MinimalForest();

        forest = forest with
        {
            Domains =
            [
                forest.Domains[0] with
                {
                    KrbtgtPasswordLastSet = EvidenceBuilder.Reference.AddDays(-ageDays),
                },
            ],
        };

        Assert.Equal(expected, Evaluate(new KrbtgtRotationRule(), WithForest(forest)).Status);
    }

    [Theory]
    [InlineData(6, 7, RuleStatus.Fail)]   // functional level below the minimum
    [InlineData(7, 7, RuleStatus.Pass)]   // exactly the minimum
    [InlineData(10, 7, RuleStatus.Pass)]
    public void DomainFunctionalLevelThresholdIsInclusive(int level, int minimum, RuleStatus expected)
    {
        var forest = EvidenceBuilder.MinimalForest();
        forest = forest with { Domains = [forest.Domains[0] with { FunctionalLevel = level }] };

        var evidence = WithForest(forest);

        var result = new DomainFunctionalLevelRule().Evaluate(new RuleEvaluationContext
        {
            Rule = new DomainFunctionalLevelRule().Definition,
            Evidence = evidence,
            ReferenceTime = evidence.ReferenceTime,
            Thresholds = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                [DomainFunctionalLevelRule.ThresholdName] = minimum,
            },
        });

        Assert.Equal(expected, result.Status);
    }

    [Theory]
    [InlineData(1, RuleStatus.Fail)]    // one writable controller is not redundant
    [InlineData(2, RuleStatus.Pass)]    // exactly the minimum
    [InlineData(3, RuleStatus.Pass)]
    public void DomainControllerRedundancyThresholdIsInclusive(int controllerCount, RuleStatus expected)
    {
        var forest = EvidenceBuilder.MinimalForest() with
        {
            DomainControllers = Enumerable.Range(1, controllerCount)
                .Select(index => EvidenceBuilder.Controller($"dc{index:00}.corp.example"))
                .ToList(),
        };

        Assert.Equal(expected, Evaluate(new DomainControllerRedundancyRule(), WithForest(forest)).Status);
    }

    [Theory]
    [InlineData(1, RuleStatus.Fail)]    // below the recommended minimum of two
    [InlineData(2, RuleStatus.Pass)]
    [InlineData(5, RuleStatus.Pass)]    // exactly at the recommended maximum
    [InlineData(6, RuleStatus.Fail)]
    public void GlobalAdministratorCountRangeIsInclusive(int adminCount, RuleStatus expected)
    {
        var assignments = Enumerable.Range(1, adminCount)
            .Select(index => new EntraRoleAssignment
            {
                RoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10",
                RoleName = "Global Administrator",
                PrincipalId = $"admin-{index}",
                PrincipalDisplayName = $"admin{index}",
                PrincipalType = "user",
            })
            .ToList();

        var tenant = EvidenceBuilder.MinimalTenant() with { RoleAssignments = assignments };

        Assert.Equal(expected, Evaluate(new GlobalAdministratorCountRule(), WithTenant(tenant)).Status);
    }

    [Theory]
    [InlineData(19, 20, RuleStatus.Pass)]   // exactly ninety-five percent, which meets the target
    [InlineData(20, 20, RuleStatus.Pass)]
    [InlineData(18, 20, RuleStatus.Fail)]
    public void MfaRegistrationCoverageThresholdIsInclusive(int registered, int total, RuleStatus expected)
    {
        var users = Enumerable.Range(1, total)
            .Select(index => EvidenceBuilder.EntraUser(
                $"user-{index}",
                $"user{index}@contoso.com",
                mfaRegistered: index <= registered))
            .ToList();

        var tenant = EvidenceBuilder.MinimalTenant() with { Users = users };

        Assert.Equal(expected, Evaluate(new MfaRegistrationCoverageRule(), WithTenant(tenant)).Status);
    }

    [Theory]
    [InlineData(0, RuleStatus.Pass)]
    [InlineData(5, RuleStatus.Pass)]    // exactly at the exclusion threshold
    [InlineData(6, RuleStatus.Fail)]
    public void ConditionalAccessExclusionThresholdIsInclusive(int exclusionCount, RuleStatus expected)
    {
        var policy = new ConditionalAccessPolicy
        {
            PolicyId = "policy-1",
            DisplayName = "Require multi-factor authentication",
            State = "enabled",
            IncludeUsers = ["All"],
            IncludeApplications = ["All"],
            ExcludeUsers = Enumerable.Range(1, exclusionCount).Select(index => $"excluded-{index}").ToList(),
            GrantControls = new ConditionalAccessGrantControls { BuiltInControls = ["mfa"] },
        };

        var tenant = EvidenceBuilder.MinimalTenant() with { ConditionalAccessPolicies = [policy] };

        Assert.Equal(expected, Evaluate(new ConditionalAccessExclusionRule(), WithTenant(tenant)).Status);
    }

    [Theory]
    [InlineData(5, RuleStatus.Pass)]
    [InlineData(6, RuleStatus.Pass)]    // exactly at the six-hour threshold
    [InlineData(7, RuleStatus.Fail)]
    public void SynchronisationFreshnessThresholdIsInclusive(int ageHours, RuleStatus expected)
    {
        var evidence = new NormalizedEvidence
        {
            Hybrid = EvidenceBuilder.MinimalHybrid() with
            {
                LastDirectorySyncTime = EvidenceBuilder.Reference.AddHours(-ageHours),
            },
            Availability = EvidenceBuilder.AllCollected(),
            ReferenceTime = EvidenceBuilder.Reference,
        };

        Assert.Equal(expected, Evaluate(new SynchronisationFreshnessRule(), evidence).Status);
    }

    [Fact]
    public void OperatorThresholdOverridesAreHonoured()
    {
        var members = Enumerable.Range(1, 8)
            .Select(index => EvidenceBuilder.User(1100 + index, $"adm{index:00}"))
            .ToList();

        var forest = EvidenceBuilder.MinimalForest() with
        {
            Users = members,
            Groups = [EvidenceBuilder.DomainAdmins([.. members])],
        };

        var rule = new TierZeroMembershipSizeRule();
        var evidence = WithForest(forest);

        // Eight members fails at the default threshold of five.
        Assert.Equal(RuleStatus.Fail, Evaluate(rule, evidence).Status);

        // The same evidence passes when the operator raises the threshold.
        var relaxed = rule.Evaluate(new RuleEvaluationContext
        {
            Rule = rule.Definition,
            Evidence = evidence,
            ReferenceTime = evidence.ReferenceTime,
            Thresholds = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                [TierZeroMembershipSizeRule.ThresholdName] = 10,
            },
        });

        Assert.Equal(RuleStatus.Pass, relaxed.Status);
    }

    [Fact]
    public void AnAccountWithNoRecordedSignInCountsAsDormant()
    {
        var admin = EvidenceBuilder.User(1105, "adm.alice") with { LastLogonTimestamp = null };

        var forest = EvidenceBuilder.MinimalForest() with
        {
            Users = [admin],
            Groups = [EvidenceBuilder.DomainAdmins(admin)],
        };

        var result = Evaluate(new StalePrivilegedAccountRule(), WithForest(forest));

        Assert.Equal(RuleStatus.Fail, result.Status);
        Assert.Contains(result.AffectedObjects, affected => affected.Detail == "No recorded sign-in");
    }

    [Fact]
    public void DisabledAccountsAreExcludedFromMembershipCounts()
    {
        var enabled = EvidenceBuilder.User(1105, "adm.alice");

        var disabled = Enumerable.Range(1, 10)
            .Select(index => EvidenceBuilder.User(1200 + index, $"old{index:00}", AdAccountFlags.Disabled))
            .ToList();

        var all = new List<Contracts.Evidence.AdPrincipal> { enabled };
        all.AddRange(disabled);

        var forest = EvidenceBuilder.MinimalForest() with
        {
            Users = all,
            Groups = [EvidenceBuilder.DomainAdmins([.. all])],
        };

        // Eleven members, but only one is enabled, so the rule passes.
        Assert.Equal(RuleStatus.Pass, Evaluate(new TierZeroMembershipSizeRule(), WithForest(forest)).Status);
    }

    [Fact]
    public void NotApplicableIsUsedWhenTheConditionCannotArise()
    {
        // A forest with no trusts cannot have a SID filtering problem, so the rule does not apply
        // rather than passing on absent data.
        var result = Evaluate(new SidFilteringRule(), WithForest(EvidenceBuilder.MinimalForest()));

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
        Assert.Contains("no inbound external or forest trust", result.Rationale, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LicenceGatedRulesReportNotApplicableRatherThanFailing()
    {
        // The tenant has no premium plan, so risk-based policies cannot exist.
        var result = Evaluate(new RiskBasedPolicyRule(), WithTenant(EvidenceBuilder.MinimalTenant()));

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
        Assert.Contains("not licensed", result.Rationale, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OutOfScopeCertificateChecksReportUnavailableRatherThanPassing()
    {
        var result = Evaluate(new CertificateServiceScopeNoticeRule(), WithForest(EvidenceBuilder.MinimalForest()));

        Assert.Equal(RuleStatus.NotCollected, result.Status);
        Assert.Equal(Contracts.EvidenceAvailability.Unsupported, result.Availability);
        Assert.Contains("outside the read-only scope", result.Rationale, StringComparison.OrdinalIgnoreCase);
    }
}
