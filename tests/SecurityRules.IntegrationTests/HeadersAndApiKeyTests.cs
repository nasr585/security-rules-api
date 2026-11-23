using System.Net;

namespace SecurityRules.IntegrationTests;

public class SecurityHeadersTests(SecurityRulesApiFactory factory) : IClassFixture<SecurityRulesApiFactory>
{
    [Fact]
    public async Task Responses_carry_the_security_headers_and_hide_the_server()
    {
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/auth/me"); // 401, still passes the middleware

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("default-src 'none'", string.Join(" ", response.Headers.GetValues("Content-Security-Policy")));
        Assert.False(response.Headers.Contains("Server"));
    }

    [Fact]
    public async Task The_correlation_id_round_trips()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
        request.Headers.Add("X-Correlation-ID", "corr-42");

        var response = await client.SendAsync(request);

        Assert.Equal("corr-42", response.Headers.GetValues("X-Correlation-ID").Single());
    }
}

public class ApiKeyTests(SecurityRulesApiFactory factory) : IClassFixture<SecurityRulesApiFactory>
{
    [Fact]
    public async Task Ping_without_a_key_is_401()
    {
        using var client = factory.CreateClient();
        var response = await client.GetAsync("/api/service/ping");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Ping_with_a_wrong_key_is_401()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/service/ping");
        request.Headers.Add("X-API-Key", "not-the-key");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Ping_with_the_configured_key_is_200()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/service/ping");
        request.Headers.Add("X-API-Key", SecurityRulesApiFactory.ServiceApiKey);

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
