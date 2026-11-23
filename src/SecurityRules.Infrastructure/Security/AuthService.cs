using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecurityRules.Application.Abstractions;
using SecurityRules.Application.Auth;
using SecurityRules.Application.Common;
using SecurityRules.Domain.Entities;
using SecurityRules.Domain.Enums;
using SecurityRules.Infrastructure.Identity;

namespace SecurityRules.Infrastructure.Security;

/// <summary>
/// Registration, login with lockout, and refresh-token rotation with
/// reuse detection. Refresh tokens are single-use: each refresh issues a new
/// token and revokes the old one. Presenting an already-rotated token means
/// the token leaked, so the whole family is revoked.
/// </summary>
public class AuthService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IApplicationDbContext db,
    ITokenService tokenService,
    IAuditLogger audit,
    TimeProvider time,
    Microsoft.Extensions.Options.IOptions<JwtOptions> jwtOptions) : IAuthService
{
    public async Task<Result<AuthResponse>> RegisterAsync(RegisterRequest request, string? ipAddress, CancellationToken ct = default)
    {
        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = request.Email,
            Email = request.Email,
            Department = request.Department.Trim(),
            Clearance = (int)ClearanceLevel.Internal,
            LockoutEnabled = true
        };

        var created = await userManager.CreateAsync(user, request.Password);
        if (!created.Succeeded)
        {
            return Result<AuthResponse>.Invalid(
                created.Errors
                    .GroupBy(e => e.Code)
                    .ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
        }

        await userManager.AddToRoleAsync(user, "Reviewer");

        await audit.LogAsync(AuditEventType.UserRegistered, true,
            user.Id, user.Email, ipAddress, null, ct);

        return Result<AuthResponse>.Ok(await IssueTokensAsync(user, ipAddress, familyId: null, ct));
    }

    public async Task<Result<AuthResponse>> LoginAsync(LoginRequest request, string? ipAddress, CancellationToken ct = default)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            // Run a dummy password check so unknown and known accounts take
            // a comparable code path (user-enumeration resistance).
            await signInManager.CheckPasswordSignInAsync(new ApplicationUser(), request.Password, lockoutOnFailure: false);
            await audit.LogAsync(AuditEventType.LoginFailed, false, null, request.Email, ipAddress, "unknown account", ct);
            return Result<AuthResponse>.Fail("invalid_credentials");
        }

        var attempt = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (attempt.IsLockedOut)
        {
            await audit.LogAsync(AuditEventType.AccountLocked, false, user.Id, user.Email, ipAddress, "too many failed attempts", ct);
            return Result<AuthResponse>.Fail("locked_out");
        }

        if (!attempt.Succeeded)
        {
            await audit.LogAsync(AuditEventType.LoginFailed, false, user.Id, user.Email, ipAddress, "wrong password", ct);
            return Result<AuthResponse>.Fail("invalid_credentials");
        }

        await audit.LogAsync(AuditEventType.LoginSucceeded, true, user.Id, user.Email, ipAddress, null, ct);
        return Result<AuthResponse>.Ok(await IssueTokensAsync(user, ipAddress, familyId: null, ct));
    }

    public async Task<Result<AuthResponse>> RefreshAsync(string refreshToken, string? ipAddress, CancellationToken ct = default)
    {
        var hash = tokenService.HashToken(refreshToken);
        var stored = await db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == hash, ct);
        var now = time.GetUtcNow();

        if (stored is null || stored.IsExpired(now))
        {
            return Result<AuthResponse>.Fail("invalid_token");
        }

        if (stored.RevokedAt is not null)
        {
            if (stored.ReplacedByTokenHash is not null)
            {
                // A rotated token was presented again: treat the family as compromised.
                var family = await db.RefreshTokens
                    .Where(t => t.FamilyId == stored.FamilyId && t.RevokedAt == null)
                    .ToListAsync(ct);
                foreach (var token in family)
                {
                    token.RevokedAt = now;
                }
                await db.SaveChangesAsync(ct);

                await audit.LogAsync(AuditEventType.RefreshTokenReuseDetected, false,
                    stored.UserId, null, ipAddress, $"family {stored.FamilyId} revoked", ct);
                return Result<AuthResponse>.Fail("token_reuse_detected");
            }

            return Result<AuthResponse>.Fail("invalid_token");
        }

        var user = await userManager.FindByIdAsync(stored.UserId.ToString());
        if (user is null)
        {
            return Result<AuthResponse>.Fail("invalid_token");
        }

        var response = await IssueTokensAsync(user, ipAddress, stored.FamilyId, ct);

        stored.RevokedAt = now;
        stored.ReplacedByTokenHash = tokenService.HashToken(response.RefreshToken);
        await db.SaveChangesAsync(ct);

        await audit.LogAsync(AuditEventType.TokenRefreshed, true, user.Id, user.Email, ipAddress, null, ct);
        return Result<AuthResponse>.Ok(response);
    }

    public async Task<Result> LogoutAsync(string refreshToken, string? ipAddress, CancellationToken ct = default)
    {
        var hash = tokenService.HashToken(refreshToken);
        var stored = await db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == hash, ct);

        if (stored is not null && stored.RevokedAt is null)
        {
            stored.RevokedAt = time.GetUtcNow();
            await db.SaveChangesAsync(ct);
            await audit.LogAsync(AuditEventType.Logout, true, stored.UserId, null, ipAddress, null, ct);
        }

        // Idempotent: unknown or already-revoked tokens get the same response.
        return Result.Ok();
    }

    public async Task<Result<UserDto>> GetUserAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());
        if (user is null)
        {
            return Result<UserDto>.Fail("not_found");
        }

        var roles = await userManager.GetRolesAsync(user);
        return Result<UserDto>.Ok(new UserDto(user.Id, user.Email!, user.Department, user.Clearance, roles.ToList()));
    }

    private async Task<AuthResponse> IssueTokensAsync(
        ApplicationUser user, string? ipAddress, Guid? familyId, CancellationToken ct)
    {
        var roles = await userManager.GetRolesAsync(user);
        var accessToken = tokenService.CreateAccessToken(
            new TokenSubject(user.Id, user.Email!, roles.ToList(), user.Department, user.Clearance));

        var rawRefresh = tokenService.GenerateRefreshTokenValue();
        db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = tokenService.HashToken(rawRefresh),
            FamilyId = familyId ?? Guid.NewGuid(),
            CreatedAt = time.GetUtcNow(),
            ExpiresAt = time.GetUtcNow().AddDays(jwtOptions.Value.RefreshTokenDays),
            CreatedByIp = ipAddress
        });
        await db.SaveChangesAsync(ct);

        return new AuthResponse(
            accessToken.Value,
            accessToken.ExpiresAt,
            rawRefresh,
            time.GetUtcNow().AddDays(jwtOptions.Value.RefreshTokenDays),
            new UserDto(user.Id, user.Email!, user.Department, user.Clearance, roles.ToList()));
    }
}
