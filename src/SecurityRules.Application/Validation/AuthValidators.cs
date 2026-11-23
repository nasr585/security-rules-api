using FluentValidation;
using SecurityRules.Application.Auth;

namespace SecurityRules.Application.Validation;

public class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress().MaximumLength(256);
        RuleFor(x => x.Department).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Password)
            .NotEmpty()
            .MinimumLength(12).WithMessage("Passwords must be at least 12 characters.")
            .Matches("[a-z]").WithMessage("Passwords need a lowercase letter.")
            .Matches("[A-Z]").WithMessage("Passwords need an uppercase letter.")
            .Matches("[0-9]").WithMessage("Passwords need a digit.")
            .Matches("[^a-zA-Z0-9]").WithMessage("Passwords need a symbol.");
    }
}

public class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress().MaximumLength(256);
        RuleFor(x => x.Password).NotEmpty();
    }
}
