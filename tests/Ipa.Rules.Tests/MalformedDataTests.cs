using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Ipa.Rules.Tests.Fixtures;
using Xunit;

namespace Ipa.Rules.Tests;

/// <summary>
/// Resilience tests against evidence that is present but malformed. Directory and tenant objects
/// can carry values nobody expects, and a rule must reach a defensible conclusion rather than
/// error, because an errored rule silently costs the customer collection coverage.
/// </summary>
public sealed class MalformedDataTests
{
    private static readonly IRulePack Pack = FirstPartyRulePack.Current;

    private static IReadOnlyList<RuleResult> EvaluateAll(NormalizedEvidence evidence) =>
        new RuleEngine(Pack).Evaluate(evidence, new RuleEvaluationOptions());

    private static NormalizedEvidence Build(
        ActiveDirectoryEvidence? forest = null,
        EntraEvidence? tenant = null,
        HybridEvidence? hybrid = null) => new()
    {
        ActiveDirectory = forest ?? EvidenceBuilder.MinimalForest(),
        Entra = tenant ?? EvidenceBuilder.MinimalTenant(),
        Hybrid = hybrid ?? EvidenceBuilder.MinimalHybrid(),
        Availability = EvidenceBuilder.AllCollected(),
        ReferenceTime = EvidenceBuilder.Reference,
    };

    private static void AssertNoErrors(IReadOnlyList<RuleResult> results)
    {
        var errored = results.Where(result => result.Status == RuleStatus.Error).ToList();

        Assert.True(
            errored.Count == 0,
            $"Rules errored on malformed evidence: {string.Join(", ", errored.Select(result => result.RuleId.Value))}");
    }

    [Fact]
    public void EmptyStringIdentifiersAreToleratedAcrossThePack()
    {
        var forest = EvidenceBuilder.MinimalForest() with
        {
            Users =
            [
                new AdPrincipal
                {
                    Sid = string.Empty,
                    DistinguishedName = string.Empty,
                    SamAccountName = string.Empty,
                    DomainSid = string.Empty,
                },
            ],
            Groups =
            [
                new AdGroup
                {
                    Sid = string.Empty,
                    DistinguishedName = string.Empty,
                    SamAccountName = string.Empty,
                    DomainSid = string.Empty,
                },
            ],
        };

        AssertNoErrors(EvaluateAll(Build(forest)));
    }

    [Fact]
    public void TimestampsAtTheExtremesOfTheRangeAreTolerated()
    {
        var forest = EvidenceBuilder.MinimalForest() with
        {
            Users =
            [
                EvidenceBuilder.User(1105, "min") with
                {
                    LastLogonTimestamp = DateTimeOffset.MinValue,
                    PasswordLastSet = DateTimeOffset.MinValue,
                    WhenCreated = DateTimeOffset.MinValue,
                },
                EvidenceBuilder.User(1106, "max") with
                {
                    LastLogonTimestamp = DateTimeOffset.MaxValue,
                    PasswordLastSet = DateTimeOffset.MaxValue,
                    WhenCreated = DateTimeOffset.MaxValue,
                },
            ],
        };

        AssertNoErrors(EvaluateAll(Build(forest)));
    }

    [Fact]
    public void ACircularGroupNestingDoesNotCauseAnInfiniteWalk()
    {
        var first = new AdGroup
        {
            Sid = Contracts.Directory.WellKnownSids.DomainRelative(
                EvidenceBuilder.DomainSid,
                Contracts.Directory.WellKnownSids.DomainAdminsRid),
            DistinguishedName = $"CN=Domain Admins,CN=Users,{EvidenceBuilder.DomainDn}",
            SamAccountName = "Domain Admins",
            DomainSid = EvidenceBuilder.DomainSid,
            MemberDistinguishedNames = [$"CN=Nested,OU=Groups,{EvidenceBuilder.DomainDn}"],
        };

        var second = new AdGroup
        {
            Sid = $"{EvidenceBuilder.DomainSid}-1500",
            DistinguishedName = $"CN=Nested,OU=Groups,{EvidenceBuilder.DomainDn}",
            SamAccountName = "Nested",
            DomainSid = EvidenceBuilder.DomainSid,

            // The nested group points back at its own parent.
            MemberDistinguishedNames = [first.DistinguishedName],
        };

        var forest = EvidenceBuilder.MinimalForest() with { Groups = [first, second] };

        AssertNoErrors(EvaluateAll(Build(forest)));
    }

    [Fact]
    public void AGroupMemberThatDoesNotExistIsIgnored()
    {
        var group = EvidenceBuilder.DomainAdmins() with
        {
            MemberDistinguishedNames = [$"CN=Ghost,OU=Missing,{EvidenceBuilder.DomainDn}"],
        };

        var forest = EvidenceBuilder.MinimalForest() with { Groups = [group] };

        AssertNoErrors(EvaluateAll(Build(forest)));
    }

    [Fact]
    public void MalformedSecurityIdentifiersAreTolerated()
    {
        var forest = EvidenceBuilder.MinimalForest() with
        {
            AccessControlEntries =
            [
                new AdAccessControlEntry
                {
                    ObjectDistinguishedName = EvidenceBuilder.DomainDn,
                    ObjectClass = "domainDNS",
                    TrusteeSid = "not-a-security-identifier",
                    Rights = AdAceRight.GenericAll,
                },
            ],
        };

        AssertNoErrors(EvaluateAll(Build(forest)));
    }

    [Fact]
    public void UnexpectedEnumeratedValuesAreTolerated()
    {
        var tenant = EvidenceBuilder.MinimalTenant() with
        {
            Users =
            [
                EvidenceBuilder.EntraUser("user-1", "user@contoso.com") with { UserType = "SomethingNew" },
            ],
            ConditionalAccessPolicies =
            [
                new ConditionalAccessPolicy
                {
                    PolicyId = "policy-1",
                    DisplayName = "Unknown state policy",
                    State = "anUnrecognisedState",
                },
            ],
        };

        AssertNoErrors(EvaluateAll(Build(tenant: tenant)));
    }

    [Fact]
    public void VeryLargeCollectionsAreHandledAndCapped()
    {
        var users = Enumerable.Range(1, 5_000)
            .Select(index => EvidenceBuilder.User(
                10_000 + index,
                $"stale{index:0000}",
                lastLogon: EvidenceBuilder.Reference.AddDays(-900)))
            .ToList();

        var forest = EvidenceBuilder.MinimalForest() with { Users = users };

        var results = EvaluateAll(Build(forest));

        AssertNoErrors(results);

        // The affected-object list stays bounded even when thousands of objects match.
        Assert.All(
            results,
            result => Assert.True(result.AffectedObjects.Count <= RuleHelpers.MaxAffectedObjects + 1));
    }

    [Fact]
    public void AMalformedGroupPolicyValueDoesNotErrorTheRule()
    {
        var policy = EvidenceBuilder.HardenedPolicy() with
        {
            RegistrySettings =
            [
                // A value the rule expects to be numeric, carrying text instead.
                EvidenceBuilder.Registry(
                    @"System\CurrentControlSet\Services\NTDS\Parameters",
                    "LDAPServerIntegrity",
                    "not a number"),
            ],
        };

        var forest = EvidenceBuilder.MinimalForest() with { GroupPolicies = [policy] };
        var results = EvaluateAll(Build(forest));

        AssertNoErrors(results);

        // An unparsable value is a failure, not a pass: the setting is not demonstrably correct.
        var signing = results.Single(result => result.RuleId.Value == "AD-GPO-004");
        Assert.Equal(RuleStatus.Fail, signing.Status);
    }

    [Fact]
    public void MarkupInObjectNamesSurvivesEvaluationUnchanged()
    {
        const string hostile = "<script>alert('x')</script>";

        var forest = EvidenceBuilder.MinimalForest() with
        {
            Users = [EvidenceBuilder.User(1105, hostile, Contracts.Evidence.AdAccountFlags.PasswordNotRequired)],
        };

        var results = EvaluateAll(Build(forest));

        AssertNoErrors(results);

        // The rule records the name verbatim; escaping is the report's responsibility, and the
        // reporting tests prove it happens there.
        var passwordRule = results.Single(result => result.RuleId.Value == "AD-ACCT-003");

        Assert.Equal(RuleStatus.Fail, passwordRule.Status);
        Assert.Contains(passwordRule.AffectedObjects, affected => affected.DisplayName == hostile);
    }

    [Fact]
    public void NegativeAndZeroPolicyValuesAreTolerated()
    {
        var forest = EvidenceBuilder.MinimalForest();

        forest = forest with
        {
            Domains =
            [
                forest.Domains[0] with
                {
                    MachineAccountQuota = -1,
                    FunctionalLevel = 0,
                    PasswordPolicy = EvidenceBuilder.StrongPasswordPolicy() with
                    {
                        MinimumPasswordLength = 0,
                        PasswordHistoryLength = -5,
                        MaximumPasswordAge = TimeSpan.Zero,
                    },
                },
            ],
        };

        AssertNoErrors(EvaluateAll(Build(forest)));
    }

    [Fact]
    public void AnEmptyForestAndTenantProduceNoErrors()
    {
        var evidence = new NormalizedEvidence
        {
            ActiveDirectory = new ActiveDirectoryEvidence
            {
                Forest = new AdForest { ForestRootDomain = string.Empty },
                ReferenceTime = EvidenceBuilder.Reference,
            },
            Entra = new EntraEvidence
            {
                Tenant = new EntraTenant { TenantId = string.Empty, DisplayName = string.Empty },
                ReferenceTime = EvidenceBuilder.Reference,
            },
            Hybrid = new HybridEvidence { ReferenceTime = EvidenceBuilder.Reference },
            Availability = EvidenceBuilder.AllCollected(),
            ReferenceTime = EvidenceBuilder.Reference,
        };

        AssertNoErrors(EvaluateAll(evidence));
    }
}
