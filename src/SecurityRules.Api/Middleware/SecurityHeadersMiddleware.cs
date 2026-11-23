namespace SecurityRules.Api.Middleware;

/// <summary>
/// Baseline response headers for an API: strict content-type handling, no
/// framing, no referrer leakage, no browser feature access, and a deny-all
/// content security policy (this service returns JSON only).
/// </summary>
public class SecurityHeadersMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
        headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), microphone=()";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";

        await next(context);
    }
}
