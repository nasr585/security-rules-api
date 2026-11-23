using Microsoft.AspNetCore.Mvc;
using SecurityRules.Application.Common;

namespace SecurityRules.Api.Controllers;

public abstract class ApiControllerBase : ControllerBase
{
    /// <summary>
    /// Maps application result codes to HTTP statuses with problem details.
    /// </summary>
    protected IActionResult MapFailure(Result result) => result.Error switch
    {
        "validation_failed" => ValidationProblem(new ValidationProblemDetails(
            result.ValidationErrors ?? new Dictionary<string, string[]>())),
        "not_found" => Problem(statusCode: StatusCodes.Status404NotFound, title: "Not found."),
        "forbidden" => Problem(statusCode: StatusCodes.Status403Forbidden, title: "Access denied."),
        "locked_out" => Problem(statusCode: StatusCodes.Status423Locked,
            title: "Account locked after too many failed attempts. Try again later."),
        "invalid_credentials" or "invalid_token" or "token_reuse_detected" or "unauthorized" =>
            Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Authentication failed."),
        _ => Problem(statusCode: StatusCodes.Status500InternalServerError, title: "Request failed.")
    };
}
