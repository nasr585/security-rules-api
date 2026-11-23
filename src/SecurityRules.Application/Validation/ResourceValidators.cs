using FluentValidation;
using SecurityRules.Application.Documents;
using SecurityRules.Application.Rules;
using SecurityRules.Domain.Enums;

namespace SecurityRules.Application.Validation;

public class CreateRuleRequestValidator : AbstractValidator<CreateRuleRequest>
{
    public CreateRuleRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().Length(3, 100);
        RuleFor(x => x.Description).MaximumLength(500);
        RuleFor(x => x.MinimumClearance)
            .InclusiveBetween((int)ClearanceLevel.Public, (int)ClearanceLevel.Secret);
        RuleFor(x => x.Department).MaximumLength(100);
        RuleFor(x => x.RequiredRole).MaximumLength(50);
        RuleFor(x => x.RequiredDepartment).MaximumLength(100);
    }
}

public class UpdateRuleRequestValidator : AbstractValidator<UpdateRuleRequest>
{
    public UpdateRuleRequestValidator()
    {
        RuleFor(x => x.Description).MaximumLength(500);
        RuleFor(x => x.MinimumClearance)
            .InclusiveBetween((int)ClearanceLevel.Public, (int)ClearanceLevel.Secret);
        RuleFor(x => x.Department).MaximumLength(100);
        RuleFor(x => x.RequiredRole).MaximumLength(50);
        RuleFor(x => x.RequiredDepartment).MaximumLength(100);
    }
}

public class CreateDocumentRequestValidator : AbstractValidator<CreateDocumentRequest>
{
    public CreateDocumentRequestValidator()
    {
        RuleFor(x => x.Title).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Department).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Classification).IsInEnum();
    }
}
