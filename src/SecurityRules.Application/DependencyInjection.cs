using Microsoft.Extensions.DependencyInjection;
using SecurityRules.Application.Audit;
using SecurityRules.Application.Documents;
using SecurityRules.Application.Rules;

namespace SecurityRules.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddScoped<IRuleService, RuleService>();
        services.AddScoped<IDocumentService, DocumentService>();
        services.AddScoped<IAuditQueryService, AuditQueryService>();
        services.AddSingleton(TimeProvider.System);
        return services;
    }
}
