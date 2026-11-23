using SecurityRules.Domain.Entities;
using SecurityRules.Domain.Enums;
using SecurityRules.Domain.Security;

namespace SecurityRules.UnitTests;

public class DocumentAccessEvaluatorTests
{
    private static readonly Guid OwnerId = Guid.NewGuid();
    private static readonly Guid OtherId = Guid.NewGuid();

    private static Document Doc(ClearanceLevel classification = ClearanceLevel.Internal, string department = "Finance") =>
        new() { Title = "Report", Department = department, Classification = classification, OwnerId = OwnerId };

    private static AccessContext User(
        ClearanceLevel clearance = ClearanceLevel.Internal,
        string department = "Finance",
        params string[] roles) =>
        new(OtherId, department, clearance, roles);

    [Fact]
    public void Owner_can_always_open_their_document()
    {
        var context = new AccessContext(OwnerId, "Sales", ClearanceLevel.Public, []);
        var decision = DocumentAccessEvaluator.Evaluate(context, Doc(ClearanceLevel.Secret), []);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Clearance_below_classification_is_denied()
    {
        var decision = DocumentAccessEvaluator.Evaluate(
            User(ClearanceLevel.Internal), Doc(ClearanceLevel.Confidential), []);
        Assert.False(decision.Allowed);
        Assert.Contains("clearance", decision.Reason);
    }

    [Fact]
    public void Clearance_covering_classification_is_allowed_without_rules()
    {
        var decision = DocumentAccessEvaluator.Evaluate(
            User(ClearanceLevel.Confidential), Doc(ClearanceLevel.Internal), []);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Active_rule_requiring_a_role_blocks_users_without_it()
    {
        var rules = new[]
        {
            new AccessRule { Name = "managers", Department = "Finance", RequiredRole = "Manager", MinimumClearance = 0 }
        };
        var decision = DocumentAccessEvaluator.Evaluate(
            User(ClearanceLevel.Secret, "Finance", "Reviewer"), Doc(), rules);
        Assert.False(decision.Allowed);
        Assert.Contains("Manager", decision.Reason);
    }

    [Fact]
    public void Active_rule_requiring_a_role_passes_holders()
    {
        var rules = new[]
        {
            new AccessRule { Name = "managers", Department = "Finance", RequiredRole = "Manager", MinimumClearance = 0 }
        };
        var decision = DocumentAccessEvaluator.Evaluate(
            User(ClearanceLevel.Internal, "Finance", "Manager"), Doc(), rules);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Inactive_rule_is_ignored()
    {
        var rules = new[]
        {
            new AccessRule { Name = "managers", Department = "Finance", RequiredRole = "Manager", IsActive = false }
        };
        var decision = DocumentAccessEvaluator.Evaluate(User(), Doc(), rules);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Rule_for_another_department_does_not_apply()
    {
        var rules = new[]
        {
            new AccessRule { Name = "legal-only", Department = "Legal", RequiredRole = "Manager" }
        };
        var decision = DocumentAccessEvaluator.Evaluate(User(), Doc(department: "Finance"), rules);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Rule_raising_minimum_clearance_blocks_lower_users()
    {
        var rules = new[]
        {
            new AccessRule { Name = "sensitive", MinimumClearance = (int)ClearanceLevel.Confidential }
        };
        var denied = DocumentAccessEvaluator.Evaluate(User(ClearanceLevel.Internal), Doc(), rules);
        var allowed = DocumentAccessEvaluator.Evaluate(User(ClearanceLevel.Confidential), Doc(), rules);
        Assert.False(denied.Allowed);
        Assert.True(allowed.Allowed);
    }
}
