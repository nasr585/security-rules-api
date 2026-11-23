using Microsoft.EntityFrameworkCore;
using SecurityRules.Application.Abstractions;

namespace SecurityRules.Application.Audit;

public sealed record AuditEventDto(
    Guid Id,
    DateTimeOffset Timestamp,
    string EventType,
    bool Succeeded,
    Guid? UserId,
    string? UserName,
    string? IpAddress,
    string? CorrelationId,
    string? Detail);

public interface IAuditQueryService
{
    Task<IReadOnlyList<AuditEventDto>> GetRecentAsync(int take, CancellationToken ct = default);
}

public class AuditQueryService(IApplicationDbContext db) : IAuditQueryService
{
    public async Task<IReadOnlyList<AuditEventDto>> GetRecentAsync(int take, CancellationToken ct = default)
    {
        take = Math.Clamp(take, 1, 500);

        // SQL Server orders in the database. SQLite (the integration-test
        // provider) cannot ORDER BY DateTimeOffset, so ordering falls back to
        // memory there; the audit trail is small in that scenario.
        var sqlite = db is DbContext context &&
                     context.Database.ProviderName?.Contains("Sqlite") == true;

        var events = sqlite
            ? (await db.AuditEvents.ToListAsync(ct))
                .OrderByDescending(e => e.Timestamp)
                .Take(take)
            : await db.AuditEvents
                .OrderByDescending(e => e.Timestamp)
                .Take(take)
                .ToListAsync(ct);

        return events.Select(e => new AuditEventDto(
                e.Id, e.Timestamp, e.EventType.ToString(), e.Succeeded,
                e.UserId, e.UserName, e.IpAddress, e.CorrelationId, e.Detail))
            .ToList();
    }
}
