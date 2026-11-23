using SecurityRules.Domain.Entities;

namespace SecurityRules.Domain.Security;

/// <summary>
/// Pure access-decision logic. A user may open a document when:
/// 1. they own it; otherwise
/// 2. their clearance covers the document classification, and
/// 3. every active rule that applies to the document's department is satisfied
///    (minimum clearance, required role, required department).
/// Denials name the first failing condition so the caller can audit it.
/// </summary>
public static class DocumentAccessEvaluator
{
    public static AccessDecision Evaluate(
        AccessContext user,
        Document document,
        IReadOnlyCollection<AccessRule> rules)
    {
        if (user.UserId == document.OwnerId)
        {
            return AccessDecision.Allow("caller owns the document");
        }

        if (user.Clearance < document.Classification)
        {
            return AccessDecision.Deny(
                $"clearance {user.Clearance} is below classification {document.Classification}");
        }

        var applicable = rules.Where(r =>
            r.IsActive && (r.Department is null || r.Department == document.Department));

        foreach (var rule in applicable)
        {
            if (user.Clearance < (Enums.ClearanceLevel)rule.MinimumClearance)
            {
                return AccessDecision.Deny(
                    $"rule '{rule.Name}' requires clearance {(Enums.ClearanceLevel)rule.MinimumClearance}");
            }

            if (rule.RequiredRole is not null && !user.Roles.Contains(rule.RequiredRole))
            {
                return AccessDecision.Deny($"rule '{rule.Name}' requires role {rule.RequiredRole}");
            }

            if (rule.RequiredDepartment is not null && user.Department != rule.RequiredDepartment)
            {
                return AccessDecision.Deny(
                    $"rule '{rule.Name}' requires department {rule.RequiredDepartment}");
            }
        }

        return AccessDecision.Allow("classification and rules satisfied");
    }
}
