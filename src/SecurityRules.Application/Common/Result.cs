namespace SecurityRules.Application.Common;

/// <summary>
/// Result of an application operation. Error carries a stable machine-readable
/// code (e.g. "invalid_credentials", "locked_out", "forbidden", "not_found")
/// that controllers translate into an HTTP status.
/// </summary>
public class Result
{
    public bool Success { get; }
    public string? Error { get; }
    public IDictionary<string, string[]>? ValidationErrors { get; }

    protected Result(bool success, string? error, IDictionary<string, string[]>? validationErrors)
    {
        Success = success;
        Error = error;
        ValidationErrors = validationErrors;
    }

    public static Result Ok() => new(true, null, null);
    public static Result Fail(string error) => new(false, error, null);
    public static Result Invalid(IDictionary<string, string[]> errors) => new(false, "validation_failed", errors);
}

public class Result<T> : Result
{
    public T? Value { get; }

    private Result(bool success, T? value, string? error, IDictionary<string, string[]>? validationErrors)
        : base(success, error, validationErrors)
    {
        Value = value;
    }

    public static Result<T> Ok(T value) => new(true, value, null, null);
    public new static Result<T> Fail(string error) => new(false, default, error, null);
    public new static Result<T> Invalid(IDictionary<string, string[]> errors) => new(false, default, "validation_failed", errors);
}
