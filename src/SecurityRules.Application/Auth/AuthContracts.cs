using SecurityRules.Application.Common;

namespace SecurityRules.Application.Auth;

public sealed record RegisterRequest(string Email, string Password, string Department);

public sealed record LoginRequest(string Email, string Password);

public sealed record RefreshRequest(string? RefreshToken);

public sealed record UserDto(
    Guid Id,
    string Email,
    string Department,
    int Clearance,
    IReadOnlyList<string> Roles);

public sealed record AuthResponse(
    string AccessToken,
    DateTimeOffset AccessTokenExpiresAt,
    string RefreshToken,
    DateTimeOffset RefreshTokenExpiresAt,
    UserDto User);

public interface IAuthService
{
    Task<Result<AuthResponse>> RegisterAsync(RegisterRequest request, string? ipAddress, CancellationToken ct = default);
    Task<Result<AuthResponse>> LoginAsync(LoginRequest request, string? ipAddress, CancellationToken ct = default);

    /// <summary>
    /// Rotates a refresh token. If a token that was already rotated is
    /// presented, the whole token family is revoked (theft detection).
    /// </summary>
    Task<Result<AuthResponse>> RefreshAsync(string refreshToken, string? ipAddress, CancellationToken ct = default);
    Task<Result> LogoutAsync(string refreshToken, string? ipAddress, CancellationToken ct = default);
    Task<Result<UserDto>> GetUserAsync(Guid userId, CancellationToken ct = default);
}
