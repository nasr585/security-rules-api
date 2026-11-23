namespace SecurityRules.Domain.Enums;

/// <summary>
/// The security-relevant events recorded in the audit trail.
/// </summary>
public enum AuditEventType
{
    UserRegistered,
    LoginSucceeded,
    LoginFailed,
    AccountLocked,
    TokenRefreshed,
    RefreshTokenReuseDetected,
    Logout,
    AuthorizationDenied,
    RuleCreated,
    RuleUpdated,
    RuleDeleted,
    DocumentCreated,
    DocumentAccessed,
    DocumentAccessDenied,
    ApiKeyRejected
}
