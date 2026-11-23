using SecurityRules.Domain.Enums;

namespace SecurityRules.Application.Abstractions;

/// <summary>
/// The authenticated caller of the current request.
/// </summary>
public interface ICurrentUserService
{
    Guid? UserId { get; }
    string? Email { get; }
    string Department { get; }
    ClearanceLevel Clearance { get; }
    IReadOnlyList<string> Roles { get; }
    string? IpAddress { get; }
}
