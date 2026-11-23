using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SecurityRules.Infrastructure.Persistence;

/// <summary>
/// Lets `dotnet ef` build the context without starting the web host. The
/// connection string comes from the ConnectionStrings__Default environment
/// variable, with a local development fallback.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<SecurityDbContext>
{
    public SecurityDbContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("ConnectionStrings__Default")
            ?? "Server=localhost,1433;Database=SecurityRulesDesign;User Id=sa;Password=Design-Time-Only!;TrustServerCertificate=True";

        var options = new DbContextOptionsBuilder<SecurityDbContext>()
            .UseSqlServer(connectionString)
            .Options;

        return new SecurityDbContext(options);
    }
}
