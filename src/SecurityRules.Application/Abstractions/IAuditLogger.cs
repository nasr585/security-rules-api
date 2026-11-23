using SecurityRules.Domain.Enums;

namespace SecurityRules.Application.Abstractions;

/// <summary>
/// Appends security events to the audit trail. Implementations must never
/// throw into the caller's request path for an audit-write failure; they log
/// the failure through the normal logging pipeline instead.
/// </summary>
public interface IAuditLogger
{
    Task LogAsync(
        AuditEventType eventType,
        bool succeeded,
        Guid? userId = null,
        string? userName = null,
        string? ipAddress = null,
        string? detail = null,
        CancellationToken cancellationToken = default);
}
