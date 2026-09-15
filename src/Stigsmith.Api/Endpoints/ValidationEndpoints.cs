using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Stigsmith.Api.Persistence;
using Stigsmith.Api.Validation;
using Stigsmith.Validation;

namespace Stigsmith.Api.Endpoints;

public static class ValidationEndpoints
{
    public static IEndpointRouteBuilder MapValidationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/generations/{id:guid}/validate", QueueOne)
            .WithTags("Validation")
            .WithSummary("Queues one generated remediation for lint, apply, re-scan, and idempotency checks.");

        var checklists = app.MapGroup("/api/checklists").WithTags("Validation");

        checklists.MapPost("/{id:guid}/validate", QueueChecklist)
            .WithSummary("Queues validation for every generated remediation on a checklist that has usable YAML.");

        checklists.MapGet("/{id:guid}/validation-report", Report)
            .WithSummary("The pass/fail report: what validated, what needs a human, and how each was verified.");

        var validations = app.MapGroup("/api/validations").WithTags("Validation");

        validations.MapGet("/status", Status)
            .WithSummary("Reports whether a container runtime is available and how deep the validation queue is.");

        validations.MapGet("/{id:guid}", GetRun)
            .WithSummary("Returns one validation run with its full evidence bundle.");

        app.MapGet("/api/generations/{id:guid}/validations", ForGeneration)
            .WithTags("Validation")
            .WithSummary("Lists validation runs for one generation, including the repair attempt.");

        return app;
    }

    private static async Task<Results<Ok<ValidationQueueResult>, NotFound, BadRequest<ProblemDetails>>> QueueOne(
        Guid id, StigsmithDbContext db, JobQueue<ValidationJob> queue, IValidationSandbox sandbox, CancellationToken ct)
    {
        var generation = await db.Generations
            .Include(g => g.Finding)
            .FirstOrDefaultAsync(g => g.Id == id, ct);
        if (generation?.Finding is null) return TypedResults.NotFound();

        if (!await sandbox.IsAvailableAsync(ct)) return NoRuntime(sandbox);

        if (generation.Yaml.Length == 0)
            return TypedResults.BadRequest(new ProblemDetails
            {
                Title = "Nothing to validate",
                Detail = generation.Error is { Length: > 0 } error
                    ? $"This generation produced no usable YAML: {error}"
                    : "This generation produced no usable YAML, so there is no playbook to validate.",
                Status = StatusCodes.Status400BadRequest,
            });

        var runId = Guid.CreateVersion7();
        await queue.EnqueueAsync(new ValidationJob(runId, generation.Finding.ChecklistId, generation.Id), ct);

        return TypedResults.Ok(new ValidationQueueResult(
            generation.Finding.ChecklistId, sandbox.Image, 1, 0, queue.Depth,
            [new QueuedValidation(runId, generation.Id, generation.Finding.RuleVersion)], []));
    }

    /// <summary>
    /// Queues every generation on a checklist that has usable YAML, newest per finding.
    /// </summary>
    /// <remarks>
    /// Newest only: a finding regenerated after a failed validation should be validated as it is now, not once per
    /// historical attempt. Generations with no YAML are reported as skipped with the reason, because "nothing to
    /// validate" is a different problem from "validation failed".
    /// </remarks>
    private static async Task<Results<Ok<ValidationQueueResult>, NotFound, BadRequest<ProblemDetails>>> QueueChecklist(
        Guid id, StigsmithDbContext db, JobQueue<ValidationJob> queue, IValidationSandbox sandbox, CancellationToken ct)
    {
        if (!await db.Checklists.AnyAsync(c => c.Id == id, ct)) return TypedResults.NotFound();
        if (!await sandbox.IsAvailableAsync(ct)) return NoRuntime(sandbox);

        // Newest generation per finding. Projected to the few columns needed and grouped in memory: a "latest per
        // group" query with the finding joined in is not something EF Core translates, and a checklist has at most
        // a few thousand generations.
        var latest = (await db.Generations
                .Where(g => g.Finding!.ChecklistId == id)
                .OrderByDescending(g => g.CreatedAt)
                .Select(g => new
                {
                    g.Id, g.FindingId, g.Error,
                    HasYaml = g.Yaml.Length > 0,
                    g.Finding!.RuleVersion,
                    g.Finding.NumericId,
                })
                .ToListAsync(ct))
            .DistinctBy(g => g.FindingId)
            .OrderBy(g => g.NumericId, StringComparer.Ordinal);

        var queued = new List<QueuedValidation>();
        var skipped = new List<SkippedValidation>();

        foreach (var generation in latest)
        {
            if (!generation.HasYaml)
            {
                skipped.Add(new SkippedValidation(generation.Id, generation.RuleVersion,
                    generation.Error is { Length: > 0 } error
                        ? $"No usable YAML: {error}"
                        : "No usable YAML; the model reported it could not automate this rule."));
                continue;
            }

            var runId = Guid.CreateVersion7();
            await queue.EnqueueAsync(new ValidationJob(runId, id, generation.Id), ct);
            queued.Add(new QueuedValidation(runId, generation.Id, generation.RuleVersion));
        }

        return TypedResults.Ok(new ValidationQueueResult(
            id, sandbox.Image, queued.Count, skipped.Count, queue.Depth, queued, skipped));
    }

    /// <summary>
    /// The pass/fail report. Reports the four outcomes separately rather than as a percentage: most non-passes are
    /// rules a container cannot validate or rules that need a human, and those are different problems with different
    /// owners.
    /// </summary>
    private static async Task<Results<Ok<ValidationReportResponse>, NotFound>> Report(
        Guid id, StigsmithDbContext db, CancellationToken ct)
    {
        if (!await db.Checklists.AnyAsync(c => c.Id == id, ct)) return TypedResults.NotFound();

        var runs = await db.ValidationRuns
            .AsNoTracking()
            .Where(r => r.Generation!.Finding!.ChecklistId == id)
            .Include(r => r.Generation!).ThenInclude(g => g.Finding)
            .ToListAsync(ct);

        // One row per finding, from its newest run; earlier rows are the repair history and belong on the detail view.
        var rows = runs
            .GroupBy(r => r.Generation!.FindingId)
            .Select(g => new
            {
                Attempts = g.Count(),
                Run = g.OrderByDescending(r => r.RepairAttempt).ThenByDescending(r => r.StartedAt).First(),
            })
            .Select(x =>
            {
                var evidence = ValidationEvidence.FromJson(x.Run.EvidenceJson);
                return new ValidationReportRow(
                    x.Run.Generation!.Finding!.RuleId,
                    x.Run.Generation.Finding.RuleVersion,
                    x.Run.Outcome,
                    Enum.TryParse<ValidationStage>(x.Run.FailedStage, out var stage) ? stage : null,
                    x.Attempts,
                    x.Run.ScanStatusBefore,
                    x.Run.ScanStatusAfter,
                    evidence?.VerifiedBy ?? ComplianceVerifierKind.None,
                    x.Run.IdempotencyChangedCount,
                    evidence?.Summary ?? "");
            })
            .OrderBy(r => r.RuleVersion, StringComparer.Ordinal)
            .ToList();

        var report = new ValidationReport { Rows = rows };
        return TypedResults.Ok(new ValidationReportResponse(
            id, report.Total, report.Passed, report.NeedsHumanReview, report.Failed, report.Skipped,
            report.PassedAfterRepair, report.VerifiedByOscap, report.Summary(), rows));
    }

    private static async Task<Results<Ok<ValidationRunDetail>, NotFound>> GetRun(
        Guid id, StigsmithDbContext db, CancellationToken ct)
    {
        var run = await db.ValidationRuns
            .AsNoTracking()
            .Include(r => r.Generation!).ThenInclude(g => g.Finding)
            .FirstOrDefaultAsync(r => r.Id == id, ct);

        return run is null ? TypedResults.NotFound() : TypedResults.Ok(ToDetail(run));
    }

    private static async Task<List<ValidationRunDetail>> ForGeneration(
        Guid id, StigsmithDbContext db, CancellationToken ct) =>
        [.. (await db.ValidationRuns
                .AsNoTracking()
                .Where(r => r.GenerationId == id)
                .Include(r => r.Generation!).ThenInclude(g => g.Finding)
                .OrderBy(r => r.RepairAttempt)
                .ToListAsync(ct))
            .Select(ToDetail)];

    private static async Task<Ok<SandboxStatus>> Status(
        IValidationSandbox sandbox, JobQueue<ValidationJob> queue, CancellationToken ct) =>
        TypedResults.Ok(new SandboxStatus(
            sandbox.Image, await sandbox.IsAvailableAsync(ct), queue.Depth));

    private static ValidationRunDetail ToDetail(ValidationRunRecord r) => new(
        r.Id,
        r.GenerationId,
        r.Generation?.Finding?.RuleId ?? "",
        r.Generation?.Finding?.RuleVersion ?? "",
        r.Outcome,
        r.FailedStage,
        r.RepairAttempt,
        r.ContainerImage,
        r.LintOutput,
        r.SyntaxCheckOutput,
        r.ApplyOutput,
        r.ScanStatusBefore,
        r.ScanStatusAfter,
        r.IdempotencyOutput,
        r.IdempotencyChangedCount,
        r.EvidenceJson,
        r.StartedAt,
        r.CompletedAt);

    private static BadRequest<ProblemDetails> NoRuntime(IValidationSandbox sandbox) =>
        TypedResults.BadRequest(new ProblemDetails
        {
            Title = "No container runtime is available",
            Detail = "Validation applies remediation in a disposable container, so it needs a reachable container "
                   + $"runtime and the image '{sandbox.Image}'. Build it with: "
                   + "docker build -t stigsmith/validation:el8 docker/validation",
            Status = StatusCodes.Status400BadRequest,
        });
}

public sealed record ValidationQueueResult(
    Guid ChecklistId,
    string ContainerImage,
    int Queued,
    int Skipped,
    int QueueDepth,
    List<QueuedValidation> QueuedItems,
    List<SkippedValidation> SkippedItems);

public sealed record QueuedValidation(Guid ValidationRunId, Guid GenerationId, string RuleVersion);

public sealed record SkippedValidation(Guid GenerationId, string RuleVersion, string Reason);

public sealed record ValidationReportResponse(
    Guid ChecklistId,
    int Total,
    int Passed,
    int NeedsHumanReview,
    int Failed,
    int Skipped,
    int PassedAfterRepair,
    int VerifiedByOscap,
    string Summary,
    List<ValidationReportRow> Rows);

public sealed record ValidationRunDetail(
    Guid Id,
    Guid GenerationId,
    string RuleId,
    string RuleVersion,
    ValidationOutcome Outcome,
    string FailedStage,
    int RepairAttempt,
    string ContainerImage,
    string LintOutput,
    string SyntaxCheckOutput,
    string ApplyOutput,
    string ScanStatusBefore,
    string ScanStatusAfter,
    string IdempotencyOutput,
    int IdempotencyChangedCount,
    string EvidenceJson,
    DateTimeOffset StartedAt,
    DateTimeOffset? CompletedAt);

public sealed record SandboxStatus(string ContainerImage, bool Available, int QueueDepth);
