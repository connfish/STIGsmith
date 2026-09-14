using Microsoft.EntityFrameworkCore;
using Stigsmith.Api.Persistence;
using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Api.Endpoints;

public static class ChecklistEndpoints
{
    public static RouteGroupBuilder MapChecklistEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/checklists").WithTags("Checklists");

        group.MapGet("/", async (StigsmithDbContext db, CancellationToken ct) =>
            await db.Checklists
                .OrderByDescending(c => c.ImportedAt)
                .Select(c => new ChecklistSummary(
                    c.Id, c.Title, c.FileName, c.HostName, c.StigId, c.SourceFormat, c.ImportedAt,
                    c.Findings.Count, c.Findings.Count(f => f.Status == FindingStatus.Open)))
                .ToListAsync(ct))
            .WithSummary("Lists imported checklists, newest first.");

        return group;
    }
}

public sealed record ChecklistSummary(
    Guid Id,
    string Title,
    string FileName,
    string HostName,
    string StigId,
    ChecklistFormat SourceFormat,
    DateTimeOffset ImportedAt,
    int FindingCount,
    int OpenCount);
