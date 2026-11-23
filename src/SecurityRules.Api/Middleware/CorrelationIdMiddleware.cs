using SecurityRules.Api.Services;

namespace SecurityRules.Api.Middleware;

/// <summary>
/// Accepts a client-supplied X-Correlation-ID or generates one, stamps it on
/// the response, and makes it available to audit logging for the request.
/// </summary>
public class CorrelationIdMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = context.Request.Headers[CorrelationContext.HeaderName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(correlationId) || correlationId.Length > 64)
        {
            correlationId = Guid.NewGuid().ToString("N");
        }

        context.Items[CorrelationContext.ItemKey] = correlationId;
        context.Response.Headers[CorrelationContext.HeaderName] = correlationId;

        await next(context);
    }
}
