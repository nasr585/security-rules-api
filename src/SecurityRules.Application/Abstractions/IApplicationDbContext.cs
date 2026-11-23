using Microsoft.EntityFrameworkCore;
using SecurityRules.Domain.Entities;

namespace SecurityRules.Application.Abstractions;

/// <summary>
/// The persistence surface the application layer depends on. Identity tables
/// are managed by the infrastructure context that implements this interface.
/// </summary>
public interface IApplicationDbContext
{
    DbSet<AccessRule> AccessRules { get; }
    DbSet<Document> Documents { get; }
    DbSet<AuditEvent> AuditEvents { get; }
    DbSet<RefreshToken> RefreshTokens { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
