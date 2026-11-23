using SecurityRules.Application.Auth;
using SecurityRules.Application.Documents;
using SecurityRules.Application.Rules;
using SecurityRules.Application.Validation;
using SecurityRules.Domain.Enums;

namespace SecurityRules.UnitTests;

public class ValidatorTests
{
    private readonly RegisterRequestValidator _registerValidator = new();
    private readonly CreateRuleRequestValidator _ruleValidator = new();
    private readonly CreateDocumentRequestValidator _documentValidator = new();

    [Fact]
    public void Registration_rejects_a_weak_password()
    {
        var result = _registerValidator.Validate(
            new RegisterRequest("user@test.local", "short", "Finance"));
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == "Password");
    }

    [Fact]
    public void Registration_rejects_a_bad_email()
    {
        var result = _registerValidator.Validate(
            new RegisterRequest("not-an-email", "Str0ng!Password", "Finance"));
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == "Email");
    }

    [Fact]
    public void Registration_accepts_a_valid_request()
    {
        var result = _registerValidator.Validate(
            new RegisterRequest("user@test.local", "Str0ng!Password", "Finance"));
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Rule_rejects_clearance_outside_the_enum()
    {
        var result = _ruleValidator.Validate(
            new CreateRuleRequest("sensitive", null, null, 9, null, null));
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == "MinimumClearance");
    }

    [Fact]
    public void Document_rejects_an_empty_title()
    {
        var result = _documentValidator.Validate(
            new CreateDocumentRequest("", "Finance", ClearanceLevel.Internal));
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == "Title");
    }
}
