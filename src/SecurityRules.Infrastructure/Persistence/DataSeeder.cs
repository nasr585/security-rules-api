using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecurityRules.Infrastructure.Identity;
using SecurityRules.Infrastructure.Persistence;

namespace SecurityRules.Infrastructure.Persistence;

public static class RoleNames
{
    public const string Admin = "Admin";
    public const string Manager = "Manager";
    public const string Reviewer = "Reviewer";

    public static readonly string[] All = [Admin, Manager, Reviewer];
}

/// <summary>
/// Seeds roles and, only when configured, a first administrator. The admin
/// password comes from configuration (user-secrets / environment), never from
/// committed files; without it the seeder creates roles only.
/// </summary>
public static class DataSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        foreach (var role in RoleNames.All)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole<Guid>(role));
            }
        }

        var configuration = services.GetRequiredService<IConfiguration>();
        var email = configuration["AdminSeed:Email"];
        var password = configuration["AdminSeed:Password"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            return;
        }

        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var existing = await userManager.Users.FirstOrDefaultAsync(u => u.Email == email);
        if (existing is not null)
        {
            return;
        }

        var admin = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = email,
            Email = email,
            Department = configuration["AdminSeed:Department"] ?? "Security",
            Clearance = (int)SecurityRules.Domain.Enums.ClearanceLevel.Secret,
            LockoutEnabled = true
        };

        var result = await userManager.CreateAsync(admin, password);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                "Failed to seed the administrator: " +
                string.Join("; ", result.Errors.Select(e => e.Description)));
        }

        await userManager.AddToRoleAsync(admin, RoleNames.Admin);
    }
}
