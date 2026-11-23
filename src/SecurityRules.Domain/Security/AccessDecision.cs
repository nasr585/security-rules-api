namespace SecurityRules.Domain.Security;

public sealed record AccessDecision(bool Allowed, string Reason)
{
    public static AccessDecision Allow(string reason) => new(true, reason);
    public static AccessDecision Deny(string reason) => new(false, reason);
}
