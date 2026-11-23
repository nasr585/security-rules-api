using System.Net;
using System.Net.Http.Json;

namespace SecurityRules.IntegrationTests;

public class AuthFlowTests(SecurityRulesApiFactory factory) : IClassFixture<SecurityRulesApiFactory>
{
    [Fact]
    public async Task Register_returns_tokens_and_the_token_works()
    {
        using var client = factory.CreateClient();

        var response = await TestClient.Register(client, "alice@test.local");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var tokens = AuthTokens.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));

        TestClient.UseBearer(client, tokens.AccessToken);
        var me = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Contains("alice@test.local", await me.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Me_without_a_token_is_401()
    {
        using var client = factory.CreateClient();
        var response = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Wrong_password_is_401_and_a_valid_payload_is_400()
    {
        using var client = factory.CreateClient();
        await TestClient.Register(client, "bob@test.local");

        var wrong = await TestClient.Login(client, "bob@test.local", "Wr0ng!Password1");
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);

        var invalid = await TestClient.Login(client, "bob@test.local", "");
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [Fact]
    public async Task Five_failed_logins_lock_the_account()
    {
        using var client = factory.CreateClient();
        await TestClient.Register(client, "carol@test.local");

        for (var attempt = 1; attempt <= 4; attempt++)
        {
            var failed = await TestClient.Login(client, "carol@test.local", "Wr0ng!Password1");
            Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);
        }

        var fifth = await TestClient.Login(client, "carol@test.local", "Wr0ng!Password1");
        Assert.Equal((HttpStatusCode)423, fifth.StatusCode);

        // Even the right password is refused while locked.
        var locked = await TestClient.Login(client, "carol@test.local", "Str0ng!Password");
        Assert.Equal((HttpStatusCode)423, locked.StatusCode);
    }

    [Fact]
    public async Task Refresh_rotates_and_replaying_the_old_token_kills_the_family()
    {
        using var client = factory.CreateClient();
        var tokens = await TestClient.RegisterAndLogin(client, "dave@test.local");

        // First refresh: token A rotates into token B.
        var rotated = await client.PostAsJsonAsync("/api/auth/refresh",
            new { refreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var rotatedTokens = AuthTokens.Parse(await rotated.Content.ReadAsStringAsync());
        Assert.NotEqual(tokens.RefreshToken, rotatedTokens.RefreshToken);

        // Replaying token A signals theft: the family is revoked.
        var replay = await client.PostAsJsonAsync("/api/auth/refresh",
            new { refreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        // Token B, the newest one, is now revoked too.
        var afterReuse = await client.PostAsJsonAsync("/api/auth/refresh",
            new { refreshToken = rotatedTokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, afterReuse.StatusCode);
    }

    [Fact]
    public async Task Logout_revokes_the_refresh_token()
    {
        using var client = factory.CreateClient();
        var tokens = await TestClient.RegisterAndLogin(client, "erin@test.local");

        var logout = await client.PostAsJsonAsync("/api/auth/logout",
            new { refreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var refresh = await client.PostAsJsonAsync("/api/auth/refresh",
            new { refreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }
}
