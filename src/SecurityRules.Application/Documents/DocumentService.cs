using Microsoft.EntityFrameworkCore;
using SecurityRules.Application.Abstractions;
using SecurityRules.Application.Common;
using SecurityRules.Domain.Entities;
using SecurityRules.Domain.Enums;
using SecurityRules.Domain.Security;

namespace SecurityRules.Application.Documents;

public sealed record CreateDocumentRequest(string Title, string Department, ClearanceLevel Classification);

public sealed record DocumentDto(
    Guid Id,
    string Title,
    string Department,
    string Classification,
    Guid OwnerId,
    DateTimeOffset CreatedAt);

public interface IDocumentService
{
    Task<Result<DocumentDto>> CreateAsync(CreateDocumentRequest request, CancellationToken ct = default);
    Task<Result<DocumentDto>> GetAsync(Guid documentId, CancellationToken ct = default);
}

public class DocumentService(
    IApplicationDbContext db,
    ICurrentUserService currentUser,
    IAuditLogger audit,
    TimeProvider time) : IDocumentService
{
    public async Task<Result<DocumentDto>> CreateAsync(CreateDocumentRequest request, CancellationToken ct = default)
    {
        var userId = currentUser.UserId;
        if (userId is null)
        {
            return Result<DocumentDto>.Fail("unauthorized");
        }

        var document = new Document
        {
            Title = request.Title.Trim(),
            Department = request.Department.Trim(),
            Classification = request.Classification,
            OwnerId = userId.Value,
            CreatedAt = time.GetUtcNow()
        };

        db.Documents.Add(document);
        await db.SaveChangesAsync(ct);

        await audit.LogAsync(AuditEventType.DocumentCreated, true,
            userId, currentUser.Email, currentUser.IpAddress,
            $"document '{document.Title}' ({document.Id})", ct);

        return Result<DocumentDto>.Ok(ToDto(document));
    }

    public async Task<Result<DocumentDto>> GetAsync(Guid documentId, CancellationToken ct = default)
    {
        var userId = currentUser.UserId;
        if (userId is null)
        {
            return Result<DocumentDto>.Fail("unauthorized");
        }

        var document = await db.Documents.FirstOrDefaultAsync(d => d.Id == documentId, ct);
        if (document is null)
        {
            return Result<DocumentDto>.Fail("not_found");
        }

        var rules = await db.AccessRules.Where(r => r.IsActive).ToListAsync(ct);
        var context = new AccessContext(userId.Value, currentUser.Department, currentUser.Clearance, currentUser.Roles);
        var decision = DocumentAccessEvaluator.Evaluate(context, document, rules);

        if (!decision.Allowed)
        {
            await audit.LogAsync(AuditEventType.DocumentAccessDenied, false,
                userId, currentUser.Email, currentUser.IpAddress,
                $"document {document.Id}: {decision.Reason}", ct);
            return Result<DocumentDto>.Fail("forbidden");
        }

        await audit.LogAsync(AuditEventType.DocumentAccessed, true,
            userId, currentUser.Email, currentUser.IpAddress,
            $"document {document.Id}", ct);

        return Result<DocumentDto>.Ok(ToDto(document));
    }

    private static DocumentDto ToDto(Document d) => new(
        d.Id, d.Title, d.Department, d.Classification.ToString(), d.OwnerId, d.CreatedAt);
}
