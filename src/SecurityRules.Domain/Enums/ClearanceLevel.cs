namespace SecurityRules.Domain.Enums;

/// <summary>
/// Clearance levels, ordered. A user may access a document when their
/// clearance is at least the document's classification.
/// </summary>
public enum ClearanceLevel
{
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Secret = 3
}
