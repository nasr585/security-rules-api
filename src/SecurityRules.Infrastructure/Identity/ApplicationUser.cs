using Microsoft.AspNetCore.Identity;

namespace SecurityRules.Infrastructure.Identity;

/// <summary>
/// The application user. Department and clearance are part of the security
/// model: they are set by administrators, never by the user self-registering.
/// </summary>
public class ApplicationUser : IdentityUser<Guid>
{
    public string Department { get; set; } = string.Empty;
    public int Clearance { get; set; } = (int)SecurityRules.Domain.Enums.ClearanceLevel.Internal;
}
