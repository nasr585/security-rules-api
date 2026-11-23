using SecurityRules.Domain.Enums;

namespace SecurityRules.Domain.Security;

/// <summary>
/// The attributes of the user asking for access, reduced to what the
/// evaluator needs so the decision logic stays free of ASP.NET types.
/// </summary>
public sealed record AccessContext(
    Guid UserId,
    string Department,
    ClearanceLevel Clearance,
    IReadOnlyCollection<string> Roles);
