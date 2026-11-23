using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace SecurityRules.IntegrationTests;

public class RulesAndDocumentsTests(SecurityRulesApiFactory factory) : IClassFixture<SecurityRulesApiFactory>
{
    private static async Task<Guid> CreateDocument(
        HttpClient client, AuthTokens tokens, string title, string department, int classification)
    {
        TestClient.UseBearer(client, tokens.AccessToken);
        var response = await client.PostAsJsonAsync("/api/documents",
            new { title, department, classification });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task A_reviewer_cannot_create_rules_but_the_admin_can()
    {
        using var client = factory.CreateClient();
        var reviewer = await TestClient.RegisterAndLogin(client, "reviewer1@test.local");

        TestClient.UseBearer(client, reviewer.AccessToken);
        var denied = await client.PostAsJsonAsync("/api/rules",
            new { name = "finance-only", description = "d", department = "Finance", minimumClearance = 0 });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        var admin = await TestClient.LoginAsAdmin(client);
        TestClient.UseBearer(client, admin.AccessToken);
        var created = await client.PostAsJsonAsync("/api/rules",
            new { name = "finance-only", description = "d", department = "Finance", minimumClearance = 0 });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
    }

    [Fact]
    public async Task Rule_requiring_a_role_blocks_other_departments_members()
    {
        using var client = factory.CreateClient();
        var admin = await TestClient.LoginAsAdmin(client);
        var owner = await TestClient.RegisterAndLogin(client, "owner1@test.local", department: "Legal");
        var outsider = await TestClient.RegisterAndLogin(client, "outsider1@test.local", department: "Legal");

        // Admin restricts Legal documents to admins.
        TestClient.UseBearer(client, admin.AccessToken);
        var created = await client.PostAsJsonAsync("/api/rules",
            new { name = "legal-admins", description = "d", department = "Legal", minimumClearance = 0, requiredRole = "Admin" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var documentId = await CreateDocument(client, owner, "contract", "Legal", classification: 1);

        TestClient.UseBearer(client, outsider.AccessToken);
        var denied = await client.GetAsync($"/api/documents/{documentId}");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        TestClient.UseBearer(client, admin.AccessToken);
        var allowed = await client.GetAsync($"/api/documents/{documentId}");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    [Fact]
    public async Task Clearance_below_the_classification_is_denied_even_without_rules()
    {
        using var client = factory.CreateClient();
        var owner = await TestClient.RegisterAndLogin(client, "owner2@test.local");
        var reader = await TestClient.RegisterAndLogin(client, "reader2@test.local");

        var documentId = await CreateDocument(client, owner, "salaries", "HR", classification: 2); // Confidential

        TestClient.UseBearer(client, reader.AccessToken);
        var denied = await client.GetAsync($"/api/documents/{documentId}");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        // The owner can always open it.
        TestClient.UseBearer(client, owner.AccessToken);
        var allowed = await client.GetAsync($"/api/documents/{documentId}");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    [Fact]
    public async Task A_document_with_no_restricting_rules_is_readable_by_peers_with_clearance()
    {
        using var client = factory.CreateClient();
        var owner = await TestClient.RegisterAndLogin(client, "owner3@test.local");
        var peer = await TestClient.RegisterAndLogin(client, "peer3@test.local");

        var documentId = await CreateDocument(client, owner, "handbook", "People", classification: 1);

        TestClient.UseBearer(client, peer.AccessToken);
        var allowed = await client.GetAsync($"/api/documents/{documentId}");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    [Fact]
    public async Task Unknown_document_is_404()
    {
        using var client = factory.CreateClient();
        var tokens = await TestClient.RegisterAndLogin(client, "owner4@test.local");

        TestClient.UseBearer(client, tokens.AccessToken);
        var response = await client.GetAsync($"/api/documents/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
