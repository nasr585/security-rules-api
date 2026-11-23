using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using SecurityRules.Application.Abstractions;
using SecurityRules.Domain.Enums;

namespace SecurityRules.Api.Middleware;

/// <summary>
/// Wraps the default authorization result handling so every denied request
/// from an authenticated user lands in the audit trail, then defers to the
/// framework's normal 401/403 behavior.
/// </summary>
public class AuditAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new();

    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Forbidden && context.User.Identity?.IsAuthenticated == true)
        {
            var audit = context.RequestServices.GetService<IAuditLogger>();
            if (audit is not null)
            {
                var sub = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
                await audit.LogAsync(
                    AuditEventType.AuthorizationDenied,
                    succeeded: false,
                    userId: Guid.TryParse(sub, out var id) ? id : null,
                    userName: context.User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value,
                    ipAddress: context.Connection.RemoteIpAddress?.ToString(),
                    detail: $"{context.Request.Method} {context.Request.Path}");
            }
        }

        await _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
    }
}
