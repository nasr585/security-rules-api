using System.Security.Claims;
using SecurityRules.Application.Abstractions;
using SecurityRules.Domain.Enums;

namespace SecurityRules.Api.Services;

/// <summary>
/// Reads the authenticated caller from the JWT claims. The bearer handler
/// applies the standard inbound claim mapping, so identity claims surface as
/// NameIdentifier/Email/Role and the custom claims keep their token names
/// ("department", "clearance").
/// </summary>
public class CurrentUserService(IHttpContextAccessor accessor) : ICurrentUserService
{
    public Guid? UserId
    {
        get
        {
            var sub = accessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            return Guid.TryParse(sub, out var id) ? id : null;
        }
    }

    public string? Email => accessor.HttpContext?.User.FindFirstValue(ClaimTypes.Email);

    public string Department => accessor.HttpContext?.User.FindFirstValue("department") ?? string.Empty;

    public ClearanceLevel Clearance =>
        int.TryParse(accessor.HttpContext?.User.FindFirstValue("clearance"), out var level)
            ? (ClearanceLevel)level
            : ClearanceLevel.Public;

    public IReadOnlyList<string> Roles =>
        accessor.HttpContext?.User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList()
        ?? (IReadOnlyList<string>)[];

    public string? IpAddress => accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
}
