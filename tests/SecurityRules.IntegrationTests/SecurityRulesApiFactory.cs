using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;

using Microsoft.Extensions.DependencyInjection;
using SecurityRules.Infrastructure.Persistence;

namespace SecurityRules.IntegrationTests;

/// <summary>
/// Boots the API against a throwaway SQLite file with test secrets and a
/// seeded administrator (admin@test.local / Admin!Passw0rd123). Each test
/// class gets its own factory, so its own isolated database.
/// </summary>
public class SecurityRulesApiFactory : WebApplicationFactory<Program>
{
    public const string AdminEmail = "admin@test.local";
    public const string AdminPassword = "Admin!Passw0rd123";
    public const string ServiceApiKey = "test-api-key";

    private readonly string _databaseFile =
        Path.Combine(Path.GetTempPath(), $"security-rules-tests-{Guid.NewGuid():N}.db");

    private readonly Dictionary<string, string?> _overrides;

    public SecurityRulesApiFactory()
    {
        _overrides = new Dictionary<string, string?>();
        EnsureInitialized();
    }

    protected SecurityRulesApiFactory(Dictionary<string, string?> overrides)
    {
        _overrides = overrides;
        EnsureInitialized();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // UseSetting wins over appsettings in the minimal-hosting builder;
        // ConfigureAppConfiguration sources are not reliably visible when
        // Program.cs reads configuration during service registration.
        var values = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Default"] = $"Data Source={_databaseFile};Pooling=False",
            ["Database:Provider"] = "Sqlite",
            ["Database:AutoMigrate"] = "false",
            ["Jwt:Issuer"] = "test-issuer",
            ["Jwt:Audience"] = "test-audience",
            ["Jwt:SigningKey"] = "integration-test-signing-key-0123456789abcdef",
            ["AdminSeed:Email"] = AdminEmail,
            ["AdminSeed:Password"] = AdminPassword,
            ["AdminSeed:Department"] = "Security",
            ["ApiKeys:KeyHashes:0"] = "4C806362B613F7496ABF284146EFD31DA90E4B16169FE001841CA17290F427C4",
            ["RateLimiting:AuthPermitLimit"] = "1000",
            ["RateLimiting:ApiPermitLimit"] = "10000"
        };
        foreach (var (key, value) in _overrides)
        {
            values[key] = value;
        }
        foreach (var (key, value) in values)
        {
            builder.UseSetting(key, value);
        }
    }

    private bool _initialized;

    private void EnsureInitialized()
    {
        if (_initialized)
        {
            return;
        }

        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
        db.Database.EnsureCreated();
        DataSeeder.SeedAsync(scope.ServiceProvider).GetAwaiter().GetResult();
        _initialized = true;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && File.Exists(_databaseFile))
        {
            try
            {
                File.Delete(_databaseFile);
            }
            catch (IOException)
            {
                // Best effort; the temp file is harmless.
            }
        }
    }
}

public sealed record AuthTokens(string AccessToken, string RefreshToken)
{
    public static AuthTokens Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        return new AuthTokens(
            root.GetProperty("accessToken").GetString()!,
            root.GetProperty("refreshToken").GetString()!);
    }
}

public static class TestClient
{
    public static async Task<HttpResponseMessage> Register(
        HttpClient client, string email, string password = "Str0ng!Password", string department = "Finance") =>
        await client.PostAsJsonAsync("/api/auth/register",
            new { email, password, department });

    public static async Task<HttpResponseMessage> Login(HttpClient client, string email, string password) =>
        await client.PostAsJsonAsync("/api/auth/login", new { email, password });

    public static async Task<AuthTokens> RegisterAndLogin(HttpClient client, string email, string department = "Finance")
    {
        var response = await Register(client, email, department: department);
        response.EnsureSuccessStatusCode();
        return AuthTokens.Parse(await response.Content.ReadAsStringAsync());
    }

    public static Task<AuthTokens> LoginAsAdmin(HttpClient client) => LoginTokens(client,
        SecurityRulesApiFactory.AdminEmail, SecurityRulesApiFactory.AdminPassword);

    public static async Task<AuthTokens> LoginTokens(HttpClient client, string email, string password)
    {
        var response = await Login(client, email, password);
        response.EnsureSuccessStatusCode();
        return AuthTokens.Parse(await response.Content.ReadAsStringAsync());
    }

    public static void UseBearer(HttpClient client, string accessToken) =>
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
}
