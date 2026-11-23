using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecurityRules.Application.Abstractions;
using SecurityRules.Domain.Enums;

namespace SecurityRules.Infrastructure.Security.ApiKey;

public static class ApiKeyDefaults
{
    public const string SchemeName = "ApiKey";
    public const string HeaderName = "X-API-Key";
}

public class ApiKeyOptions : AuthenticationSchemeOptions
{
    /// <summary>SHA-256 hashes (hex) of accepted keys. Plain keys never live in configuration.</summary>
    public string[] KeyHashes { get; set; } = [];

    public static string HashKey(string key) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));
}

/// <summary>
/// Service-to-service authentication. Keys are compared as fixed-time SHA-256
/// hashes so neither timing nor configuration leaks the accepted values.
/// </summary>
public class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<ApiKeyOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(ApiKeyDefaults.HeaderName, out var provided) ||
            string.IsNullOrWhiteSpace(provided))
        {
            return AuthenticateResult.NoResult();
        }

        var providedHash = Encoding.ASCII.GetBytes(ApiKeyOptions.HashKey(provided.ToString()));
        var accepted = Options.KeyHashes.Select(h => Encoding.ASCII.GetBytes(h));

        foreach (var acceptedHash in accepted)
        {
            if (providedHash.Length == acceptedHash.Length &&
                CryptographicOperations.FixedTimeEquals(providedHash, acceptedHash))
            {
                var identity = new ClaimsIdentity(
                    [new Claim(ClaimTypes.Name, "service")], ApiKeyDefaults.SchemeName);
                var ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(identity), ApiKeyDefaults.SchemeName);
                return AuthenticateResult.Success(ticket);
            }
        }

        var audit = Context.RequestServices.GetService<IAuditLogger>();
        if (audit is not null)
        {
            await audit.LogAsync(AuditEventType.ApiKeyRejected, false,
                null, null, Context.Connection.RemoteIpAddress?.ToString(), "invalid API key");
        }

        return AuthenticateResult.Fail("Invalid API key.");
    }
}
