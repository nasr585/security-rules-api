namespace SecurityRules.Application.Abstractions;

public sealed record TokenSubject(
    Guid UserId,
    string Email,
    IReadOnlyList<string> Roles,
    string Department,
    int Clearance);

public sealed record AccessToken(string Value, DateTimeOffset ExpiresAt);

/// <summary>
/// Issues signed JWT access tokens and opaque refresh tokens. Refresh tokens
/// are random values; only their SHA-256 hash is ever persisted.
/// </summary>
public interface ITokenService
{
    AccessToken CreateAccessToken(TokenSubject subject);
    string GenerateRefreshTokenValue();
    string HashToken(string value);
}
