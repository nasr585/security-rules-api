using Microsoft.EntityFrameworkCore;
using SecurityRules.Application.Abstractions;
using SecurityRules.Application.Common;
using SecurityRules.Domain.Entities;
using SecurityRules.Domain.Enums;

namespace SecurityRules.Application.Rules;

public sealed record CreateRuleRequest(
    string Name,
    string? Description,
    string? Department,
    int MinimumClearance,
    string? RequiredRole,
    string? RequiredDepartment);

public sealed record UpdateRuleRequest(
    string? Description,
    string? Department,
    int MinimumClearance,
    string? RequiredRole,
    string? RequiredDepartment,
    bool IsActive);

public sealed record RuleDto(
    Guid Id,
    string Name,
    string Description,
    string? Department,
    int MinimumClearance,
    string? RequiredRole,
    string? RequiredDepartment,
    bool IsActive,
    DateTimeOffset CreatedAt);

public interface IRuleService
{
    Task<IReadOnlyList<RuleDto>> ListAsync(CancellationToken ct = default);
    Task<Result<RuleDto>> CreateAsync(CreateRuleRequest request, CancellationToken ct = default);
    Task<Result<RuleDto>> UpdateAsync(Guid ruleId, UpdateRuleRequest request, CancellationToken ct = default);
    Task<Result> DeleteAsync(Guid ruleId, CancellationToken ct = default);
}

public class RuleService(
    IApplicationDbContext db,
    ICurrentUserService currentUser,
    IAuditLogger audit,
    TimeProvider time) : IRuleService
{
    public async Task<IReadOnlyList<RuleDto>> ListAsync(CancellationToken ct = default)
    {
        return await db.AccessRules
            .OrderBy(r => r.Name)
            .Select(r => ToDto(r))
            .ToListAsync(ct);
    }

    public async Task<Result<RuleDto>> CreateAsync(CreateRuleRequest request, CancellationToken ct = default)
    {
        var rule = new AccessRule
        {
            Name = request.Name.Trim(),
            Description = request.Description?.Trim() ?? string.Empty,
            Department = string.IsNullOrWhiteSpace(request.Department) ? null : request.Department.Trim(),
            MinimumClearance = request.MinimumClearance,
            RequiredRole = string.IsNullOrWhiteSpace(request.RequiredRole) ? null : request.RequiredRole.Trim(),
            RequiredDepartment = string.IsNullOrWhiteSpace(request.RequiredDepartment) ? null : request.RequiredDepartment.Trim(),
            CreatedAt = time.GetUtcNow(),
            CreatedBy = currentUser.UserId ?? Guid.Empty
        };

        db.AccessRules.Add(rule);
        await db.SaveChangesAsync(ct);

        await audit.LogAsync(AuditEventType.RuleCreated, true,
            currentUser.UserId, currentUser.Email, currentUser.IpAddress,
            $"rule '{rule.Name}' ({rule.Id})", ct);

        return Result<RuleDto>.Ok(ToDto(rule));
    }

    public async Task<Result<RuleDto>> UpdateAsync(Guid ruleId, UpdateRuleRequest request, CancellationToken ct = default)
    {
        var rule = await db.AccessRules.FirstOrDefaultAsync(r => r.Id == ruleId, ct);
        if (rule is null)
        {
            return Result<RuleDto>.Fail("not_found");
        }

        rule.Description = request.Description?.Trim() ?? string.Empty;
        rule.Department = string.IsNullOrWhiteSpace(request.Department) ? null : request.Department.Trim();
        rule.MinimumClearance = request.MinimumClearance;
        rule.RequiredRole = string.IsNullOrWhiteSpace(request.RequiredRole) ? null : request.RequiredRole.Trim();
        rule.RequiredDepartment = string.IsNullOrWhiteSpace(request.RequiredDepartment) ? null : request.RequiredDepartment.Trim();
        rule.IsActive = request.IsActive;

        await db.SaveChangesAsync(ct);

        await audit.LogAsync(AuditEventType.RuleUpdated, true,
            currentUser.UserId, currentUser.Email, currentUser.IpAddress,
            $"rule '{rule.Name}' ({rule.Id})", ct);

        return Result<RuleDto>.Ok(ToDto(rule));
    }

    public async Task<Result> DeleteAsync(Guid ruleId, CancellationToken ct = default)
    {
        var rule = await db.AccessRules.FirstOrDefaultAsync(r => r.Id == ruleId, ct);
        if (rule is null)
        {
            return Result.Fail("not_found");
        }

        db.AccessRules.Remove(rule);
        await db.SaveChangesAsync(ct);

        await audit.LogAsync(AuditEventType.RuleDeleted, true,
            currentUser.UserId, currentUser.Email, currentUser.IpAddress,
            $"rule '{rule.Name}' ({rule.Id})", ct);

        return Result.Ok();
    }

    private static RuleDto ToDto(AccessRule r) => new(
        r.Id, r.Name, r.Description, r.Department, r.MinimumClearance,
        r.RequiredRole, r.RequiredDepartment, r.IsActive, r.CreatedAt);
}
