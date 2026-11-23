using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.Extensions.Options;
using SecurityRules.Application.Abstractions;
using SecurityRules.Infrastructure.Security;

namespace SecurityRules.UnitTests;

public class TokenServiceTests
{
    private static TokenService CreateService() => new(
        Options.Create(new JwtOptions
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            SigningKey = "unit-test-signing-key-0123456789abcdef",
            AccessTokenMinutes = 15
        }),
        TimeProvider.System);

    private static TokenSubject Subject() => new(
        Guid.NewGuid(), "user@test.local", ["Reviewer"], "Finance", 1);

    [Fact]
    public void Access_token_carries_subject_email_roles_department_and_clearance()
    {
        var service = CreateService();
        var subject = Subject();

        var token = service.CreateAccessToken(subject);
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var parsed = handler.ReadJwtToken(token.Value);

        Assert.Equal(subject.UserId.ToString(), parsed.Claims.Single(c => c.Type == "sub").Value);
        Assert.Equal(subject.Email, parsed.Claims.Single(c => c.Type == "email").Value);
        Assert.Equal("Reviewer", parsed.Claims.Single(c => c.Type == "role").Value);
        Assert.Equal("Finance", parsed.Claims.Single(c => c.Type == "department").Value);
        Assert.Equal("1", parsed.Claims.Single(c => c.Type == "clearance").Value);
        Assert.Equal("test-issuer", parsed.Issuer);
        Assert.Contains("test-audience", parsed.Audiences);
    }

    [Fact]
    public void Access_token_expires_after_the_configured_lifetime()
    {
        var service = CreateService();
        var before = DateTimeOffset.UtcNow;

        var token = service.CreateAccessToken(Subject());

        Assert.InRange(token.ExpiresAt,
            before.AddMinutes(14), before.AddMinutes(16));
    }

    [Fact]
    public void Refresh_tokens_are_unique_and_url_safe()
    {
        var service = CreateService();
        var a = service.GenerateRefreshTokenValue();
        var b = service.GenerateRefreshTokenValue();

        Assert.NotEqual(a, b);
        Assert.DoesNotContain("+", a);
        Assert.DoesNotContain("/", a);
        Assert.DoesNotContain("=", a);
    }

    [Fact]
    public void Token_hashing_is_deterministic_and_value_sensitive()
    {
        var service = CreateService();
        var token = service.GenerateRefreshTokenValue();

        Assert.Equal(service.HashToken(token), service.HashToken(token));
        Assert.NotEqual(service.HashToken(token), service.HashToken(token + "x"));
    }
}
