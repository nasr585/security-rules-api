using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecurityRules.Domain.Entities;

namespace SecurityRules.Infrastructure.Persistence.Configurations;

public class AccessRuleConfiguration : IEntityTypeConfiguration<AccessRule>
{
    public void Configure(EntityTypeBuilder<AccessRule> builder)
    {
        builder.Property(r => r.Name).HasMaxLength(100).IsRequired();
        builder.Property(r => r.Description).HasMaxLength(500);
        builder.Property(r => r.Department).HasMaxLength(100);
        builder.Property(r => r.RequiredRole).HasMaxLength(50);
        builder.Property(r => r.RequiredDepartment).HasMaxLength(100);
        builder.HasIndex(r => r.Department);
    }
}

public class DocumentConfiguration : IEntityTypeConfiguration<Document>
{
    public void Configure(EntityTypeBuilder<Document> builder)
    {
        builder.Property(d => d.Title).HasMaxLength(200).IsRequired();
        builder.Property(d => d.Department).HasMaxLength(100).IsRequired();
        builder.HasIndex(d => d.OwnerId);
    }
}

public class AuditEventConfiguration : IEntityTypeConfiguration<AuditEvent>
{
    public void Configure(EntityTypeBuilder<AuditEvent> builder)
    {
        builder.Property(e => e.EventType).HasConversion<string>().HasMaxLength(64);
        builder.Property(e => e.UserName).HasMaxLength(256);
        builder.Property(e => e.IpAddress).HasMaxLength(45);
        builder.Property(e => e.CorrelationId).HasMaxLength(64);
        builder.Property(e => e.Detail).HasMaxLength(1000);
        builder.HasIndex(e => e.Timestamp);
        builder.HasIndex(e => e.UserId);
    }
}

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.Property(t => t.TokenHash).HasMaxLength(128).IsRequired();
        builder.Property(t => t.ReplacedByTokenHash).HasMaxLength(128);
        builder.Property(t => t.CreatedByIp).HasMaxLength(45);
        builder.HasIndex(t => t.TokenHash).IsUnique();
        builder.HasIndex(t => t.UserId);
        builder.HasIndex(t => t.FamilyId);
    }
}
