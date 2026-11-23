using Microsoft.AspNetCore.Http;
using SecurityRules.Api.Middleware;

namespace SecurityRules.UnitTests;

public class SecurityHeadersMiddlewareTests
{
    [Fact]
    public async Task Response_gets_the_baseline_security_headers()
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        var middleware = new SecurityHeadersMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(context);

        Assert.Equal("nosniff", context.Response.Headers["X-Content-Type-Options"]);
        Assert.Equal("DENY", context.Response.Headers["X-Frame-Options"]);
        Assert.Equal("no-referrer", context.Response.Headers["Referrer-Policy"]);
        Assert.Contains("default-src 'none'", context.Response.Headers["Content-Security-Policy"].ToString());
        Assert.True(context.Response.Headers.ContainsKey("Permissions-Policy"));
    }
}

public class CorrelationIdMiddlewareTests
{
    [Fact]
    public async Task Incoming_correlation_id_is_kept_and_returned()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Correlation-ID"] = "abc-123";
        var middleware = new CorrelationIdMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(context);

        Assert.Equal("abc-123", context.Response.Headers["X-Correlation-ID"]);
        Assert.Equal("abc-123", context.Items["CorrelationId"]);
    }

    [Fact]
    public async Task Missing_correlation_id_generates_one()
    {
        var context = new DefaultHttpContext();
        var middleware = new CorrelationIdMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(context);

        Assert.False(string.IsNullOrWhiteSpace(context.Response.Headers["X-Correlation-ID"]));
    }
}
