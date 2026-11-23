namespace SecurityRules.Domain.Entities;

/// <summary>
/// A refresh token. Only the SHA-256 hash of the token is stored; the raw
/// value exists only in the response that issued it. Rotation links each
/// token to the token that replaced it, and every token belongs to a family
/// so token theft (replay of a rotated token) can revoke the whole chain.
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public Guid FamilyId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? ReplacedByTokenHash { get; set; }
    public string? CreatedByIp { get; set; }

    public bool IsExpired(DateTimeOffset now) => now >= ExpiresAt;
    public bool IsActive(DateTimeOffset now) => RevokedAt is null && !IsExpired(now);
}
