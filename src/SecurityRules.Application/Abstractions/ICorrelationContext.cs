namespace SecurityRules.Application.Abstractions;

/// <summary>
/// Correlation id of the current request, set by middleware and stamped onto
/// audit entries so a request can be traced across logs and the audit trail.
/// </summary>
public interface ICorrelationContext
{
    string CorrelationId { get; }
}
