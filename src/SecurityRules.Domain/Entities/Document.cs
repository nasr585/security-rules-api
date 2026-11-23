using SecurityRules.Domain.Enums;

namespace SecurityRules.Domain.Entities;

/// <summary>
/// A protected document. Access is decided by ownership, classification and
/// the active access rules for its department.
/// </summary>
public class Document
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Title { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;
    public ClearanceLevel Classification { get; set; } = ClearanceLevel.Internal;
    public Guid OwnerId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
