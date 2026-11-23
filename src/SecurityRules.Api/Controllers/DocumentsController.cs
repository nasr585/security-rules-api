using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecurityRules.Application.Common;
using SecurityRules.Application.Documents;

namespace SecurityRules.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/documents")]
[EnableRateLimiting("api")]
public class DocumentsController(
    IDocumentService documentService,
    IValidator<CreateDocumentRequest> createValidator) : ApiControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Create(CreateDocumentRequest request, CancellationToken ct)
    {
        var validation = await createValidator.ValidateAsync(request, ct);
        if (!validation.IsValid)
        {
            return MapFailure(Result.Invalid(validation.ToDictionary()));
        }

        var result = await documentService.CreateAsync(request, ct);
        return result.Success
            ? CreatedAtAction(nameof(Get), new { id = result.Value!.Id }, result.Value)
            : MapFailure(result);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct)
    {
        var result = await documentService.GetAsync(id, ct);
        return result.Success ? Ok(result.Value) : MapFailure(result);
    }
}
