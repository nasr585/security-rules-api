namespace SecurityRules.Domain.Entities;

/// <summary>
/// An access rule defined by an administrator. Rules restrict which users may
/// open documents in a department on top of the baseline clearance check.
/// A null condition means "no constraint from this dimension".
/// </summary>
public class AccessRule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    /// <summary>When set, the rule applies only to documents of this department.</summary>
    public string? Department { get; set; }

    /// <summary>Minimum clearance a user needs when this rule applies.</summary>
    public int MinimumClearance { get; set; }

    /// <summary>Role the user must hold when this rule applies.</summary>
    public string? RequiredRole { get; set; }

    /// <summary>Department the user must belong to when this rule applies.</summary>
    public string? RequiredDepartment { get; set; }

    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public Guid CreatedBy { get; set; }
}
