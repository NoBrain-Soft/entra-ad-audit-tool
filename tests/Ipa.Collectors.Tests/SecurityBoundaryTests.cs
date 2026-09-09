using Ipa.Collectors.ActiveDirectory.Connection;
using Ipa.Collectors.ActiveDirectory.Sysvol;
using Ipa.Collectors.Entra.Authentication;
using Ipa.Collectors.Entra.Permissions;
using Ipa.Contracts;
using Ipa.Contracts.Security;
using Xunit;

namespace Ipa.Collectors.Tests;

/// <summary>
/// Tests for the boundaries the product must not cross: no write permissions, no credential over an
/// unprotected channel, no path escape, and no secret in a log message.
/// </summary>
public sealed class SecurityBoundaryTests
{
    [Fact]
    public void EveryRequestedGraphPermissionIsReadOnly()
    {
        foreach (var permission in PermissionManifest.All)
        {
            Assert.True(
                PermissionManifest.IsReadOnly(permission.Scope),
                $"{permission.Scope} is not a read-only permission.");
        }
    }

    [Fact]
    public void ScopesAreRequestedOnlyForSelectedCheckGroups()
    {
        var authenticationOnly = PermissionManifest.ScopesFor([CheckGroup.EntraAuthentication]);

        Assert.DoesNotContain("Application.Read.All", authenticationOnly);
        Assert.DoesNotContain("SecurityEvents.Read.All", authenticationOnly);
        Assert.Contains("Policy.Read.All", authenticationOnly);
    }

    [Fact]
    public void SecureScoreScopeIsRequestedOnlyWithItsGroup()
    {
        Assert.Contains("SecurityEvents.Read.All", PermissionManifest.ScopesFor([CheckGroup.EntraSecureScore]));
        Assert.DoesNotContain("SecurityEvents.Read.All", PermissionManifest.ScopesFor([CheckGroup.EntraApplications]));
    }

    [Fact]
    public void ExplicitCredentialsOverAnUnprotectedChannelAreRefused()
    {
        using var password = new System.Security.SecureString();
        password.AppendChar('x');

        var settings = new DirectoryConnectionSettings
        {
            Server = "dc01.corp.example",
            AuthenticationMode = DirectoryAuthenticationMode.ExplicitCredentials,
            TransportSecurity = DirectoryTransportSecurity.SignAndSeal,
            Credential = new DirectoryCredential("auditor", "CORP", password),
        };

        var exception = Assert.Throws<InvalidOperationException>(settings.Validate);
        Assert.Contains("LDAPS or StartTLS", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ExplicitCredentialsRequireACredential()
    {
        var settings = new DirectoryConnectionSettings
        {
            Server = "dc01.corp.example",
            AuthenticationMode = DirectoryAuthenticationMode.ExplicitCredentials,
            TransportSecurity = DirectoryTransportSecurity.Ldaps,
        };

        Assert.Throws<InvalidOperationException>(settings.Validate);
    }

    [Fact]
    public void ExplicitCredentialsOverLdapsAreAccepted()
    {
        using var password = new System.Security.SecureString();
        password.AppendChar('x');

        var settings = new DirectoryConnectionSettings
        {
            Server = "dc01.corp.example",
            AuthenticationMode = DirectoryAuthenticationMode.ExplicitCredentials,
            TransportSecurity = DirectoryTransportSecurity.Ldaps,
            Credential = new DirectoryCredential("auditor", "CORP", password),
        };

        settings.Validate();
        Assert.Equal(636, settings.EffectivePort);
    }

    [Fact]
    public void StartTlsUsesThePlainPortByDefault()
    {
        var settings = new DirectoryConnectionSettings
        {
            Server = "dc01.corp.example",
            TransportSecurity = DirectoryTransportSecurity.StartTls,
            AuthenticationMode = DirectoryAuthenticationMode.WindowsIntegrated,
        };

        Assert.Equal(389, settings.EffectivePort);
    }

    [Theory]
    [InlineData(@"\\dc01\SYSVOL\corp.example\Policies\{GUID}", @"corp.example\Policies\{GUID}")]
    [InlineData("corp.example/Policies/{GUID}", @"corp.example\Policies\{GUID}")]
    [InlineData(@"\corp.example\Policies\", @"corp.example\Policies")]
    public void SysvolPathsAreNormalisedToShareRelativeForm(string input, string expected) =>
        Assert.Equal(expected, SysvolClient.Normalise(input));

    [Theory]
    [InlineData(@"corp.example\..\..\Windows")]
    [InlineData("../etc/passwd")]
    public void SysvolPathsThatEscapeTheShareAreRefused(string path) =>
        Assert.Throws<ArgumentException>(() => SysvolClient.Normalise(path));

    [Fact]
    public void RedactionRemovesBearerTokens()
    {
        var scrubbed = Redaction.Scrub(
            "Request failed. Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature");

        Assert.DoesNotContain("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", scrubbed, StringComparison.Ordinal);
        Assert.Contains(Redaction.Placeholder, scrubbed, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactionRemovesRefreshTokensAndSecrets()
    {
        var scrubbed = Redaction.Scrub("refresh_token=0.AXoAabc123&client_secret=Qk7~verysecret");

        Assert.DoesNotContain("0.AXoAabc123", scrubbed, StringComparison.Ordinal);
        Assert.DoesNotContain("Qk7~verysecret", scrubbed, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactionRemovesPasswordAssignments()
    {
        var scrubbed = Redaction.Scrub(@"bind failed for CORP\auditor password=Winter2026!");

        Assert.DoesNotContain("Winter2026!", scrubbed, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("unicodePwd")]
    [InlineData("ms-Mcs-AdmPwd")]
    [InlineData("msLAPS-Password")]
    [InlineData("supplementalCredentials")]
    public void SensitiveDirectoryAttributesAreNeverReturnedRaw(string attribute)
    {
        Assert.True(Redaction.IsSensitiveAttribute(attribute));
        Assert.Equal(Redaction.Placeholder, Redaction.SafeAttributeValue(attribute, "any value"));
        Assert.Equal("[absent]", Redaction.SafeAttributeValue(attribute, null));
    }

    [Fact]
    public void OrdinaryAttributesPassThroughRedactionUnchanged() =>
        Assert.Equal("alice", Redaction.SafeAttributeValue("sAMAccountName", "alice"));

    [Fact]
    public void RegistrationProfileRequiresALoopbackRedirect()
    {
        var profile = new AppRegistrationProfile
        {
            TenantId = "contoso.onmicrosoft.com",
            ClientId = Guid.NewGuid().ToString(),
            RedirectUri = "https://example.com/callback",
        };

        Assert.Contains(profile.Validate(), problem =>
            problem.Contains("loopback", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RegistrationProfileRejectsANonGuidClientIdentifier()
    {
        var profile = new AppRegistrationProfile { TenantId = "contoso.onmicrosoft.com", ClientId = "not-a-guid" };

        Assert.Contains(profile.Validate(), problem =>
            problem.Contains("globally unique identifier", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidRegistrationProfilePassesAndBuildsAConsentUrl()
    {
        var clientId = Guid.NewGuid().ToString();

        var profile = new AppRegistrationProfile
        {
            TenantId = "contoso.onmicrosoft.com",
            ClientId = clientId,
        };

        Assert.Empty(profile.Validate());

        var url = profile.BuildAdminConsentUrl([CheckGroup.EntraAuthentication]);

        Assert.StartsWith("https://login.microsoftonline.com/", url, StringComparison.Ordinal);
        Assert.Contains("adminconsent", url, StringComparison.Ordinal);
        Assert.Contains(clientId, url, StringComparison.Ordinal);
        Assert.DoesNotContain("client_secret", url, StringComparison.Ordinal);
    }
}
