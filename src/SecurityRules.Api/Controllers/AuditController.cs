using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecurityRules.Api.Security;
using SecurityRules.Application.Audit;
using SecurityRules.Infrastructure.Security.ApiKey;

namespace SecurityRules.Api.Controllers;

[ApiController]
[Authorize(Policy = Policies.AdminOnly)]
[Route("api/audit")]
[EnableRateLimiting("api")]
public class AuditController(IAuditQueryService auditQuery) : ApiControllerBase
{
    /// <summary>Most recent audit events, newest first. Admin only.</summary>
    [HttpGet]
    public async Task<IActionResult> Recent([FromQuery] int take = 100, CancellationToken ct = default) =>
        Ok(await auditQuery.GetRecentAsync(take, ct));
}

[ApiController]
[Route("api/service")]
public class ServiceController : ApiControllerBase
{
    /// <summary>
    /// Service-to-service health endpoint authenticated with an API key
    /// instead of a user token.
    /// </summary>
    [HttpGet("ping")]
    [Authorize(AuthenticationSchemes = ApiKeyDefaults.SchemeName)]
    public IActionResult Ping() => Ok(new { status = "ok", utc = DateTimeOffset.UtcNow });
}
