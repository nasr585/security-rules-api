using SecurityRules.Application.Abstractions;

namespace SecurityRules.Api.Services;

public class CorrelationContext(IHttpContextAccessor accessor) : ICorrelationContext
{
    public const string ItemKey = "CorrelationId";
    public const string HeaderName = "X-Correlation-ID";

    public string CorrelationId =>
        accessor.HttpContext?.Items[ItemKey] as string ?? string.Empty;
}
