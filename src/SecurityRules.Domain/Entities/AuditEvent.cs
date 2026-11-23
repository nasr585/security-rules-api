using SecurityRules.Domain.Enums;

namespace SecurityRules.Domain.Entities;

/// <summary>
/// One append-only entry in the security audit trail. Entries are written for
/// authentication, authorization and administrative events and are never
/// updated or deleted by the application.
/// </summary>
public class AuditEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTimeOffset Timestamp { get; set; }
    public AuditEventType EventType { get; set; }
    public bool Succeeded { get; set; }
    public Guid? UserId { get; set; }
    public string? UserName { get; set; }
    public string? IpAddress { get; set; }
    public string? CorrelationId { get; set; }
    public string? Detail { get; set; }
}
