using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecurityRules.Application.Abstractions;
using SecurityRules.Domain.Entities;
using SecurityRules.Infrastructure.Identity;
using SecurityRules.Infrastructure.Persistence.Configurations;

namespace SecurityRules.Infrastructure.Persistence;

public class SecurityDbContext(DbContextOptions<SecurityDbContext> options)
    : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>(options), IApplicationDbContext
{
    public DbSet<AccessRule> AccessRules => Set<AccessRule>();
    public DbSet<Document> Documents => Set<Document>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfiguration(new AccessRuleConfiguration());
        builder.ApplyConfiguration(new DocumentConfiguration());
        builder.ApplyConfiguration(new AuditEventConfiguration());
        builder.ApplyConfiguration(new RefreshTokenConfiguration());
    }
}
