using System.ComponentModel.DataAnnotations;

namespace SecurityRules.Infrastructure.Security;

/// <summary>
/// JWT settings. The signing key is a secret: supply it through user-secrets,
/// environment variables or a mounted secret store, never in committed files.
/// Validated at startup so a missing or weak key fails fast.
/// </summary>
public class JwtOptions
{
    public const string SectionName = "Jwt";

    [Required]
    public string Issuer { get; set; } = string.Empty;

    [Required]
    public string Audience { get; set; } = string.Empty;

    [Required]
    [MinLength(32, ErrorMessage = "The signing key must be at least 32 characters.")]
    public string SigningKey { get; set; } = string.Empty;

    [Range(1, 120)]
    public int AccessTokenMinutes { get; set; } = 15;

    [Range(1, 30)]
    public int RefreshTokenDays { get; set; } = 7;
}
