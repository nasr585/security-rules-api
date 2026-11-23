using System.Text;
using System.Threading.RateLimiting;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecurityRules.Api.ExceptionHandling;
using SecurityRules.Api.Middleware;
using SecurityRules.Api.Security;
using SecurityRules.Api.Services;
using SecurityRules.Application;
using SecurityRules.Application.Abstractions;
using SecurityRules.Application.Auth;
using SecurityRules.Application.Validation;
using SecurityRules.Infrastructure;
using SecurityRules.Infrastructure.Persistence;
using SecurityRules.Infrastructure.Security;
using SecurityRules.Infrastructure.Security.ApiKey;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

builder.Services.AddControllers();
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);
builder.Services.AddValidatorsFromAssemblyContaining<RegisterRequestValidator>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUserService, CurrentUserService>();
builder.Services.AddScoped<ICorrelationContext, CorrelationContext>();

var jwt = builder.Configuration.GetSection(JwtOptions.SectionName);
var configuredKey = jwt["SigningKey"];
var signingKey = new SymmetricSecurityKey(
    Encoding.UTF8.GetBytes(string.IsNullOrEmpty(configuredKey) ? new string('0', 32) : configuredKey));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt["Issuer"],
            ValidateAudience = true,
            ValidAudience = jwt["Audience"],
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    })
    .AddScheme<ApiKeyOptions, ApiKeyAuthenticationHandler>(ApiKeyDefaults.SchemeName, options =>
    {
        options.KeyHashes = builder.Configuration
            .GetSection("ApiKeys:KeyHashes")
            .Get<string[]>() ?? [];
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(Policies.CanManageRules, policy =>
        policy.RequireRole(RoleNames.Admin, RoleNames.Manager))
    .AddPolicy(Policies.AdminOnly, policy =>
        policy.RequireRole(RoleNames.Admin));

builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, AuditAuthorizationResultHandler>();

var rateLimiting = builder.Configuration.GetSection("RateLimiting");
var authPermitLimit = rateLimiting.GetValue("AuthPermitLimit", 5);
var authWindowSeconds = rateLimiting.GetValue("AuthWindowSeconds", 60);
var apiPermitLimit = rateLimiting.GetValue("ApiPermitLimit", 100);
var apiWindowSeconds = rateLimiting.GetValue("ApiWindowSeconds", 60);

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Strict per-IP bucket on credential endpoints against brute force.
    options.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = authPermitLimit,
            Window = TimeSpan.FromSeconds(authWindowSeconds),
            QueueLimit = 0
        }));

    // Generous per-user bucket for normal API traffic.
    options.AddPolicy("api", context => RateLimitPartition.GetSlidingWindowLimiter(
        context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? context.Connection.RemoteIpAddress?.ToString()
            ?? "unknown",
        _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = apiPermitLimit,
            Window = TimeSpan.FromSeconds(apiWindowSeconds),
            SegmentsPerWindow = 4,
            QueueLimit = 0
        }));

    options.OnRejected = async (context, cancellationToken) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString();
        }

        context.HttpContext.Response.ContentType = "application/problem+json";
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            status = StatusCodes.Status429TooManyRequests,
            title = "Too many requests. Slow down and retry."
        }, cancellationToken);
    };
});

var corsOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
if (corsOrigins.Length > 0)
{
    builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
        policy.WithOrigins(corsOrigins).AllowAnyHeader().AllowAnyMethod()));
}

builder.Services.AddHealthChecks().AddDbContextCheck<SecurityDbContext>();

var app = builder.Build();

app.UseExceptionHandler();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

if (corsOrigins.Length > 0)
{
    app.UseCors();
}

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health");

// Migrations and seeding run on startup. Integration tests disable this and
// manage the schema themselves.
if (app.Configuration.GetValue("Database:AutoMigrate", true))
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
    await db.Database.MigrateAsync();
    await DataSeeder.SeedAsync(scope.ServiceProvider);
}

app.Run();

public partial class Program;
