using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace SecurityRules.IntegrationTests;

public class AuditTrailTests(SecurityRulesApiFactory factory) : IClassFixture<SecurityRulesApiFactory>
{
    private static async Task<List<JsonElement>> ReadAudit(HttpClient client, string adminToken)
    {
        TestClient.UseBearer(client, adminToken);
        var response = await client.GetAsync("/api/audit?take=500");
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.EnumerateArray().Select(e => e.Clone()).ToList();
    }

    [Fact]
    public async Task The_audit_trail_is_admin_only()
    {
        using var client = factory.CreateClient();
        var reviewer = await TestClient.RegisterAndLogin(client, "audit-reviewer@test.local");

        TestClient.UseBearer(client, reviewer.AccessToken);
        var response = await client.GetAsync("/api/audit");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Failed_logins_and_denied_access_are_recorded()
    {
        using var client = factory.CreateClient();
        var owner = await TestClient.RegisterAndLogin(client, "audit-owner@test.local");
        var reader = await TestClient.RegisterAndLogin(client, "audit-reader@test.local");

        await TestClient.Login(client, "audit-reader@test.local", "Wr0ng!Password1");

        TestClient.UseBearer(client, owner.AccessToken);
        var created = await client.PostAsJsonAsync("/api/documents",
            new { title = "classified", department = "HR", classification = 2 });
        created.EnsureSuccessStatusCode();
        var documentId = JsonDocument.Parse(await created.Content.ReadAsStringAsync())
            .RootElement.GetProperty("id").GetGuid();

        TestClient.UseBearer(client, reader.AccessToken);
        var denied = await client.GetAsync($"/api/documents/{documentId}");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        var admin = await TestClient.LoginAsAdmin(client);
        var events = await ReadAudit(client, admin.AccessToken);
        var types = events.Select(e => e.GetProperty("eventType").GetString()).ToList();

        Assert.Contains("LoginFailed", types);
        Assert.Contains("DocumentAccessDenied", types);
        Assert.Contains("LoginSucceeded", types);
    }

    [Fact]
    public async Task Authorization_denials_are_recorded_with_the_correlation_id()
    {
        using var client = factory.CreateClient();
        var reviewer = await TestClient.RegisterAndLogin(client, "audit-reviewer2@test.local");

        TestClient.UseBearer(client, reviewer.AccessToken);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/rules");
        request.Headers.Add("X-Correlation-ID", "deny-123");
        request.Content = JsonContent.Create(new { name = "x", description = "d", department = (string?)null, minimumClearance = 0 });
        var denied = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        var admin = await TestClient.LoginAsAdmin(client);
        var events = await ReadAudit(client, admin.AccessToken);

        var entry = events.Single(e => e.GetProperty("correlationId").GetString() == "deny-123");
        Assert.Equal("AuthorizationDenied", entry.GetProperty("eventType").GetString());
    }
}
