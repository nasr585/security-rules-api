using System.Net;

namespace SecurityRules.IntegrationTests;

/// <summary>
/// A factory with a tiny auth bucket: the 4th credential attempt within the
/// window must be rejected with 429. This class gets its own factory (and
/// database) so the strict limit does not leak into other tests.
/// </summary>
public class RateLimitingTests
    : IClassFixture<RateLimitingTests.StrictFactory>
{
    public class StrictFactory() : SecurityRulesApiFactory(new Dictionary<string, string?>
    {
        ["RateLimiting:AuthPermitLimit"] = "3",
        ["RateLimiting:AuthWindowSeconds"] = "300"
    });

    private readonly StrictFactory _factory;

    public RateLimitingTests(StrictFactory factory) => _factory = factory;

    [Fact]
    public async Task The_auth_bucket_rejects_the_burst()
    {
        using var client = _factory.CreateClient();

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var response = await TestClient.Login(client, "nobody@test.local", "Wr0ng!Password1");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        var limited = await TestClient.Login(client, "nobody@test.local", "Wr0ng!Password1");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }
}
