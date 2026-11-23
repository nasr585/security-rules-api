using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecurityRules.Api.Security;
using SecurityRules.Application.Common;
using SecurityRules.Application.Rules;

namespace SecurityRules.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/rules")]
[EnableRateLimiting("api")]
public class RulesController(
    IRuleService ruleService,
    IValidator<CreateRuleRequest> createValidator,
    IValidator<UpdateRuleRequest> updateValidator) : ApiControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct) =>
        Ok(await ruleService.ListAsync(ct));

    [HttpPost]
    [Authorize(Policy = Policies.CanManageRules)]
    public async Task<IActionResult> Create(CreateRuleRequest request, CancellationToken ct)
    {
        var validation = await createValidator.ValidateAsync(request, ct);
        if (!validation.IsValid)
        {
            return MapFailure(Result.Invalid(validation.ToDictionary()));
        }

        var result = await ruleService.CreateAsync(request, ct);
        return result.Success
            ? CreatedAtAction(nameof(List), new { }, result.Value)
            : MapFailure(result);
    }

    [HttpPut("{id:guid}")]
    [Authorize(Policy = Policies.CanManageRules)]
    public async Task<IActionResult> Update(Guid id, UpdateRuleRequest request, CancellationToken ct)
    {
        var validation = await updateValidator.ValidateAsync(request, ct);
        if (!validation.IsValid)
        {
            return MapFailure(Result.Invalid(validation.ToDictionary()));
        }

        var result = await ruleService.UpdateAsync(id, request, ct);
        return result.Success ? Ok(result.Value) : MapFailure(result);
    }

    [HttpDelete("{id:guid}")]
    [Authorize(Policy = Policies.AdminOnly)]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var result = await ruleService.DeleteAsync(id, ct);
        return result.Success ? NoContent() : MapFailure(result);
    }
}
