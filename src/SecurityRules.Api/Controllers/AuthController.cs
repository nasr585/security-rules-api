using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecurityRules.Application.Auth;
using SecurityRules.Application.Common;

namespace SecurityRules.Api.Controllers;

[ApiController]
[Route("api/auth")]
[EnableRateLimiting("auth")]
public class AuthController(
    IAuthService authService,
    IValidator<RegisterRequest> registerValidator,
    IValidator<LoginRequest> loginValidator) : ApiControllerBase
{
    private const string RefreshCookieName = "refresh_token";

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken ct)
    {
        var validation = await registerValidator.ValidateAsync(request, ct);
        if (!validation.IsValid)
        {
            return MapFailure(Result.Invalid(validation.ToDictionary()));
        }

        var result = await authService.RegisterAsync(request, IpAddress(), ct);
        if (!result.Success)
        {
            return MapFailure(result);
        }

        SetRefreshCookie(result.Value!.RefreshToken, result.Value.RefreshTokenExpiresAt);
        return Ok(result.Value);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var validation = await loginValidator.ValidateAsync(request, ct);
        if (!validation.IsValid)
        {
            return MapFailure(Result.Invalid(validation.ToDictionary()));
        }

        var result = await authService.LoginAsync(request, IpAddress(), ct);
        if (!result.Success)
        {
            return MapFailure(result);
        }

        SetRefreshCookie(result.Value!.RefreshToken, result.Value.RefreshTokenExpiresAt);
        return Ok(result.Value);
    }

    /// <summary>
    /// Rotates a refresh token. Accepts the token in the request body or in
    /// the HttpOnly cookie set at login; browsers use the cookie, other
    /// clients use the body.
    /// </summary>
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest? request, CancellationToken ct)
    {
        var token = request?.RefreshToken
            ?? Request.Cookies[RefreshCookieName];
        if (string.IsNullOrWhiteSpace(token))
        {
            return MapFailure(Result.Fail("invalid_token"));
        }

        var result = await authService.RefreshAsync(token, IpAddress(), ct);
        if (!result.Success)
        {
            return MapFailure(result);
        }

        SetRefreshCookie(result.Value!.RefreshToken, result.Value.RefreshTokenExpiresAt);
        return Ok(result.Value);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] RefreshRequest? request, CancellationToken ct)
    {
        var token = request?.RefreshToken ?? Request.Cookies[RefreshCookieName];
        if (!string.IsNullOrWhiteSpace(token))
        {
            await authService.LogoutAsync(token, IpAddress(), ct);
        }

        Response.Cookies.Delete(RefreshCookieName, new CookieOptions { Path = "/api/auth" });
        return NoContent();
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        var sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(sub, out var userId))
        {
            return Unauthorized();
        }

        var result = await authService.GetUserAsync(userId, ct);
        return result.Success ? Ok(result.Value) : MapFailure(result);
    }

    private void SetRefreshCookie(string token, DateTimeOffset expiresAt)
    {
        Response.Cookies.Append(RefreshCookieName, token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/api/auth",
            Expires = expiresAt
        });
    }

    private string? IpAddress() => HttpContext.Connection.RemoteIpAddress?.ToString();
}
