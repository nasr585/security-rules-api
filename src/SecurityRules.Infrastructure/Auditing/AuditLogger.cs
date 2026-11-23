using Microsoft.Extensions.Logging;
using SecurityRules.Application.Abstractions;
using SecurityRules.Domain.Entities;
using SecurityRules.Domain.Enums;

namespace SecurityRules.Infrastructure.Auditing;

/// <summary>
/// Appends security events to the audit trail and mirrors them to structured
/// logs. A failing audit write must not break the request, so persistence
/// errors are caught and logged here.
/// </summary>
public class AuditLogger(
    IApplicationDbContext db,
    ICorrelationContext correlation,
    TimeProvider time,
    ILogger<AuditLogger> logger) : IAuditLogger
{
    public async Task LogAsync(
        AuditEventType eventType,
        bool succeeded,
        Guid? userId = null,
        string? userName = null,
        string? ipAddress = null,
        string? detail = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            db.AuditEvents.Add(new AuditEvent
            {
                Timestamp = time.GetUtcNow(),
                EventType = eventType,
                Succeeded = succeeded,
                UserId = userId,
                UserName = userName,
                IpAddress = ipAddress,
                CorrelationId = correlation.CorrelationId,
                Detail = detail
            });
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to persist audit event {EventType} for user {UserId}", eventType, userId);
        }

        logger.LogInformation(
            "Audit {EventType} succeeded={Succeeded} user={UserName} ip={IpAddress} correlation={CorrelationId} detail={Detail}",
            eventType, succeeded, userName, ipAddress, correlation.CorrelationId, detail);
    }
}
