namespace SecurityRules.Api.Security;

public static class Policies
{
    /// <summary>Create and update access rules: Admin and Manager.</summary>
    public const string CanManageRules = "CanManageRules";

    /// <summary>Administrative surfaces (audit trail, rule deletion): Admin only.</summary>
    public const string AdminOnly = "AdminOnly";
}
