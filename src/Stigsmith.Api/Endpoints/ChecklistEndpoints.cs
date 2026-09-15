using System.Text;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Stigsmith.Api.Persistence;
using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Api.Endpoints;

public static class ChecklistEndpoints
{
    /// <summary>
    /// A 1500-finding .ckl runs a few megabytes. 32 MB leaves generous headroom while still refusing
    /// an accidental upload of something that is not a checklist at all.
    /// </summary>
    private const long MaxUploadBytes = 32L * 1024 * 1024;

    public static RouteGroupBuilder MapChecklistEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/checklists").WithTags("Checklists");

        group.MapGet("/", ListChecklists)
            .WithSummary("Lists imported checklists, newest first.");

        group.MapGet("/{id:guid}", GetChecklist)
            .WithSummary("Returns one checklist with its findings.");

        group.MapPost("/import", Import)
            .WithSummary("Imports a .ckl, .cklb, XCCDF results, or ARF file. Format is detected from content.")
            .DisableAntiforgery()
            .WithRequestTimeout(TimeSpan.FromMinutes(2));

        group.MapGet("/{id:guid}/export", Export)
            .WithSummary("Exports a checklist as .ckl or .cklb, carrying current statuses and comments.");

        return group;
    }

    private static async Task<List<ChecklistSummary>> ListChecklists(StigsmithDbContext db, CancellationToken ct) =>
        await db.Checklists
            .OrderByDescending(c => c.ImportedAt)
            .Select(c => new ChecklistSummary(
                c.Id, c.Title, c.FileName, c.HostName, c.StigId, c.SourceFormat, c.ImportedAt,
                c.Findings.Count, c.Findings.Count(f => f.Status == FindingStatus.Open)))
            .ToListAsync(ct);

    private static async Task<Results<Ok<ChecklistDetail>, NotFound>> GetChecklist(
        Guid id, StigsmithDbContext db, CancellationToken ct)
    {
        var record = await db.Checklists
            .Include(c => c.Findings)
            .AsSplitQuery()
            .FirstOrDefaultAsync(c => c.Id == id, ct);

        if (record is null) return TypedResults.NotFound();

        return TypedResults.Ok(new ChecklistDetail(
            record.Id,
            record.Title,
            record.FileName,
            record.SourceFormat,
            record.ImportedAt,
            new HostView(record.HostName, record.HostIp, record.HostFqdn, record.Role),
            new StigView(record.StigId, record.StigTitle, record.StigVersion, record.StigReleaseInfo),
            record.Findings
                .OrderBy(f => f.NumericId)
                .Select(f => new FindingView(
                    f.Id, f.RuleId, f.GroupId, f.RuleVersion, f.Title, f.Severity, f.Status,
                    f.Automatability, f.IsHighRisk, f.RiskCategories))
                .ToList()));
    }

    private static async Task<Results<Created<ImportResult>, BadRequest<ProblemDetails>>> Import(
        IFormFile file, StigsmithDbContext db, ILoggerFactory loggers, CancellationToken ct)
    {
        var log = loggers.CreateLogger(typeof(ChecklistEndpoints));

        if (file.Length == 0)
            return Problem("The uploaded file is empty.");
        if (file.Length > MaxUploadBytes)
            return Problem($"The uploaded file is {file.Length:N0} bytes; the limit is {MaxUploadBytes:N0}.");

        string content;
        await using (var stream = file.OpenReadStream())
        using (var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true))
        {
            content = await reader.ReadToEndAsync(ct);
        }

        Checklist checklist;
        try
        {
            checklist = ChecklistIo.Read(content);
        }
        catch (ChecklistFormatException ex)
        {
            // The operator's file, not a server fault: say what was wrong with it and return 400.
            log.LogInformation("Rejected import of {FileName}: {Reason}", file.FileName, ex.Message);
            return Problem(ex.Message);
        }

        var record = ChecklistMapper.ToRecord(checklist, file.FileName, content);
        db.Checklists.Add(record);
        await db.SaveChangesAsync(ct);

        var counts = checklist.CountsByStatus();
        return TypedResults.Created($"/api/checklists/{record.Id}", new ImportResult(
            record.Id,
            record.SourceFormat,
            record.HostName,
            record.StigId,
            record.Findings.Count,
            counts.GetValueOrDefault(FindingStatus.Open),
            counts.GetValueOrDefault(FindingStatus.NotAFinding),
            counts.GetValueOrDefault(FindingStatus.NotApplicable),
            counts.GetValueOrDefault(FindingStatus.NotReviewed)));
    }

    private static async Task<Results<FileContentHttpResult, NotFound, BadRequest<ProblemDetails>>> Export(
        Guid id, ChecklistFormat? format, StigsmithDbContext db, CancellationToken ct)
    {
        var record = await db.Checklists.Include(c => c.Findings).FirstOrDefaultAsync(c => c.Id == id, ct);
        if (record is null) return TypedResults.NotFound();

        // Default to the format it arrived in, except for scanner output: XCCDF and ARF are results
        // documents, not review artifacts, so a scan-derived checklist exports as .ckl.
        var target = format ?? record.SourceFormat switch
        {
            ChecklistFormat.Cklb => ChecklistFormat.Cklb,
            _ => ChecklistFormat.Ckl,
        };
        if (target is not (ChecklistFormat.Ckl or ChecklistFormat.Cklb))
            return Problem($"Export supports Ckl and Cklb; '{target}' is import-only.");

        // Re-parse the original document and apply the reviews the database now holds. Rebuilding from
        // rows instead would drop every field Stigsmith does not model. See ChecklistMapper.
        var source = ChecklistIo.Read(record.OriginalDocument);
        var updated = source.WithReviews(ChecklistMapper.ToReviews(record));

        var body = Encoding.UTF8.GetBytes(ChecklistIo.Write(updated, target));
        var extension = target == ChecklistFormat.Cklb ? "cklb" : "ckl";
        var name = Path.GetFileNameWithoutExtension(record.FileName) is { Length: > 0 } stem
            ? $"{stem}.{extension}"
            : $"{record.HostName}.{extension}";

        return TypedResults.File(body, MediaTypeFor(target), name);
    }

    private static string MediaTypeFor(ChecklistFormat format) =>
        format == ChecklistFormat.Cklb ? "application/json" : "application/xml";

    private static BadRequest<ProblemDetails> Problem(string detail) =>
        TypedResults.BadRequest(new ProblemDetails
        {
            Title = "Checklist could not be imported",
            Detail = detail,
            Status = StatusCodes.Status400BadRequest,
        });
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

public sealed record ChecklistDetail(
    Guid Id,
    string Title,
    string FileName,
    ChecklistFormat SourceFormat,
    DateTimeOffset ImportedAt,
    HostView Host,
    StigView Stig,
    List<FindingView> Findings);

public sealed record HostView(string HostName, string HostIp, string HostFqdn, string Role);

public sealed record StigView(string StigId, string Title, string Version, string ReleaseInfo);

public sealed record FindingView(
    Guid Id,
    string RuleId,
    string GroupId,
    string RuleVersion,
    string Title,
    Severity Severity,
    FindingStatus Status,
    Rules.Automatability Automatability,
    bool IsHighRisk,
    string RiskCategories);

public sealed record ImportResult(
    Guid Id,
    ChecklistFormat SourceFormat,
    string HostName,
    string StigId,
    int FindingCount,
    int Open,
    int NotAFinding,
    int NotApplicable,
    int NotReviewed);
