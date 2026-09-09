using Ipa.Collectors.Hybrid;
using Ipa.Contracts.Evidence;
using Xunit;

namespace Ipa.Collectors.Tests;

/// <summary>
/// Tests for hybrid correlation. The central requirement is that a match is only ever made from an
/// authoritative anchor, and that anything weaker becomes a review item rather than a match.
/// </summary>
public sealed class HybridCorrelationTests
{
    private static readonly DateTimeOffset Reference = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid AliceGuid = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static ActiveDirectoryEvidence Forest(params AdPrincipal[] users) => new()
    {
        Forest = new AdForest { ForestRootDomain = "corp.example", ForestFunctionalLevel = 7, SchemaVersion = 88 },
        Domains =
        [
            new AdDomain
            {
                DnsName = "corp.example", NetBiosName = "CORP", DomainSid = "S-1-5-21-1-2-3",
                DistinguishedName = "DC=corp,DC=example", FunctionalLevel = 7,
            },
        ],
        Users = users,
        ReferenceTime = Reference,
    };

    private static EntraEvidence Tenant(IReadOnlyList<EntraUser> users, params string[] verifiedDomains) => new()
    {
        Tenant = new EntraTenant
        {
            TenantId = "tenant",
            DisplayName = "Contoso",
            Domains = verifiedDomains
                .Select(domain => new EntraDomain
                {
                    Name = domain, IsVerified = true, AuthenticationType = "Managed",
                })
                .ToList(),
            OnPremisesSyncEnabled = true,
        },
        Users = users,
        ReferenceTime = Reference,
    };

    private static AdPrincipal Alice => new()
    {
        Sid = "S-1-5-21-1-2-3-1105",
        ObjectGuid = AliceGuid,
        DistinguishedName = "CN=Alice,OU=Staff,DC=corp,DC=example",
        SamAccountName = "alice",
        UserPrincipalName = "alice@corp.example",
        DomainSid = "S-1-5-21-1-2-3",
    };

    [Fact]
    public void MatchesOnTheRecordedOnPremisesSecurityIdentifier()
    {
        var result = new HybridCorrelator().Correlate(
            Forest(Alice),
            Tenant([
                new EntraUser
                {
                    ObjectId = "cloud-1", UserPrincipalName = "alice@contoso.com", UserType = "Member",
                    OnPremisesSyncEnabled = true, OnPremisesSecurityIdentifier = "S-1-5-21-1-2-3-1105",
                },
            ], "contoso.com"));

        var match = Assert.Single(result.Matches);
        Assert.Equal(HybridMatchMethod.SecurityIdentifier, match.Method);
        Assert.Equal(HybridMatchConfidence.Authoritative, match.Confidence);
        Assert.Empty(result.ReviewItems);
    }

    [Fact]
    public void MatchesOnTheImmutableIdentifierDerivedFromTheObjectGuid()
    {
        var immutableId = Convert.ToBase64String(AliceGuid.ToByteArray());

        var result = new HybridCorrelator().Correlate(
            Forest(Alice),
            Tenant([
                new EntraUser
                {
                    ObjectId = "cloud-2", UserPrincipalName = "alice@contoso.com", UserType = "Member",
                    OnPremisesSyncEnabled = true, OnPremisesImmutableId = immutableId,
                },
            ], "contoso.com"));

        var match = Assert.Single(result.Matches);
        Assert.Equal(HybridMatchMethod.ImmutableId, match.Method);
        Assert.Equal(HybridMatchConfidence.Authoritative, match.Confidence);
    }

    [Fact]
    public void MatchesOnTheRecordedDistinguishedName()
    {
        var result = new HybridCorrelator().Correlate(
            Forest(Alice),
            Tenant([
                new EntraUser
                {
                    ObjectId = "cloud-3", UserPrincipalName = "alice@contoso.com", UserType = "Member",
                    OnPremisesSyncEnabled = true,
                    OnPremisesDistinguishedName = "CN=Alice,OU=Staff,DC=corp,DC=example",
                },
            ], "contoso.com"));

        var match = Assert.Single(result.Matches);
        Assert.Equal(HybridMatchMethod.DistinguishedName, match.Method);
        Assert.Equal(HybridMatchConfidence.Strong, match.Confidence);
    }

    [Fact]
    public void MatchesOnAUserPrincipalNameOnlyInsideAVerifiedDomain()
    {
        var evidence = Forest(Alice);

        var matched = new HybridCorrelator().Correlate(
            evidence,
            Tenant([
                new EntraUser { ObjectId = "cloud-4", UserPrincipalName = "alice@corp.example", UserType = "Member" },
            ], "corp.example"));

        Assert.Single(matched.Matches);
        Assert.Equal(HybridMatchMethod.VerifiedUserPrincipalName, matched.Matches[0].Method);

        // The same principal name in an unverified domain must not produce a match.
        var unverified = new HybridCorrelator().Correlate(
            evidence,
            Tenant([
                new EntraUser { ObjectId = "cloud-5", UserPrincipalName = "alice@corp.example", UserType = "Member" },
            ], "someone-else.example"));

        Assert.Empty(unverified.Matches);
    }

    [Fact]
    public void DisplayNameAloneNeverProducesAMatch()
    {
        var result = new HybridCorrelator().Correlate(
            Forest(Alice with { UserPrincipalName = null, DisplayName = "Alice Example" }),
            Tenant([
                new EntraUser
                {
                    ObjectId = "cloud-6", UserPrincipalName = "alice.example@contoso.com",
                    DisplayName = "Alice Example", UserType = "Member", OnPremisesSyncEnabled = true,
                },
            ], "contoso.com"));

        Assert.Empty(result.Matches);
        Assert.Single(result.ReviewItems);
    }

    [Fact]
    public void AmbiguousPrincipalNameBecomesAReviewItem()
    {
        var duplicate = Alice with
        {
            Sid = "S-1-5-21-1-2-3-1106",
            ObjectGuid = Guid.Parse("99999999-8888-7777-6666-555555555555"),
            DistinguishedName = "CN=Alice,OU=Contractors,DC=corp,DC=example",
        };

        var result = new HybridCorrelator().Correlate(
            Forest(Alice, duplicate),
            Tenant([
                new EntraUser { ObjectId = "cloud-7", UserPrincipalName = "alice@corp.example", UserType = "Member" },
            ], "corp.example"));

        Assert.Empty(result.Matches);
        var review = Assert.Single(result.ReviewItems);
        Assert.Equal(2, review.AdCandidates.Count);
    }

    [Fact]
    public void SynchronisedCloudObjectWithNoOnPremisesCounterpartIsOrphaned()
    {
        var result = new HybridCorrelator().Correlate(
            Forest(Alice),
            Tenant([
                new EntraUser
                {
                    ObjectId = "cloud-8", UserPrincipalName = "ghost@contoso.com", UserType = "Member",
                    OnPremisesSyncEnabled = true, OnPremisesSecurityIdentifier = "S-1-5-21-9-9-9-1200",
                },
            ], "contoso.com"));

        Assert.Empty(result.Matches);
        Assert.Equal("cloud-8", Assert.Single(result.OrphanedCloudObjectIds));
        Assert.Single(result.ReviewItems);
    }

    [Fact]
    public void DuplicateAnchorsAreReported()
    {
        var immutableId = Convert.ToBase64String(AliceGuid.ToByteArray());

        var result = new HybridCorrelator().Correlate(
            Forest(Alice),
            Tenant([
                new EntraUser
                {
                    ObjectId = "cloud-9", UserPrincipalName = "alice@contoso.com", UserType = "Member",
                    OnPremisesImmutableId = immutableId,
                },
                new EntraUser
                {
                    ObjectId = "cloud-10", UserPrincipalName = "alice.duplicate@contoso.com", UserType = "Member",
                    OnPremisesImmutableId = immutableId,
                },
            ], "contoso.com"));

        Assert.Equal(immutableId, Assert.Single(result.DuplicateAnchors));
    }

    [Fact]
    public void CorrelationIsDeterministic()
    {
        var forest = Forest(Alice);
        var tenant = Tenant([
            new EntraUser
            {
                ObjectId = "cloud-11", UserPrincipalName = "alice@contoso.com", UserType = "Member",
                OnPremisesSyncEnabled = true, OnPremisesSecurityIdentifier = "S-1-5-21-1-2-3-1105",
            },
        ], "contoso.com");

        var first = new HybridCorrelator().Correlate(forest, tenant);
        var second = new HybridCorrelator().Correlate(forest, tenant);

        Assert.Equal(
            first.Matches.Select(match => (match.AdSid, match.EntraObjectId, match.Method)),
            second.Matches.Select(match => (match.AdSid, match.EntraObjectId, match.Method)));
    }

    [Fact]
    public void ImmutableIdentifierDecodesBackToTheObjectGuid()
    {
        var encoded = Convert.ToBase64String(AliceGuid.ToByteArray());

        Assert.Equal(AliceGuid, HybridCorrelator.DecodeImmutableId(encoded));
        Assert.Null(HybridCorrelator.DecodeImmutableId("not base64!"));
        Assert.Null(HybridCorrelator.DecodeImmutableId(null));
    }

    [Theory]
    [InlineData("alice@corp.example", "corp.example")]
    [InlineData("alice", null)]
    [InlineData("alice@", null)]
    [InlineData(null, null)]
    public void PrincipalNameSuffixIsExtracted(string? upn, string? expected) =>
        Assert.Equal(expected, HybridCorrelator.SuffixOf(upn));

    [Fact]
    public void PrivilegedSynchronisedAccountsAreIdentified()
    {
        var forest = Forest(Alice);

        var tenant = Tenant([
            new EntraUser
            {
                ObjectId = "cloud-12", UserPrincipalName = "alice@contoso.com", UserType = "Member",
                OnPremisesSyncEnabled = true, OnPremisesSecurityIdentifier = "S-1-5-21-1-2-3-1105",
            },
        ], "contoso.com") with
        {
            RoleAssignments =
            [
                new EntraRoleAssignment
                {
                    RoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10",
                    RoleName = "Global Administrator",
                    PrincipalId = "cloud-12",
                    PrincipalDisplayName = "alice@contoso.com",
                    PrincipalType = "user",
                },
            ],
        };

        var correlation = new HybridCorrelator().Correlate(forest, tenant);
        var privileged = HybridCollector.FindPrivilegedSynchronised(forest, tenant, correlation);

        Assert.Equal("S-1-5-21-1-2-3-1105", Assert.Single(privileged));
    }
}
