using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Stigsmith.Api.Generation;
using Stigsmith.Api.Persistence;
using Stigsmith.Checklists.Model;
using Stigsmith.Generation.Providers;
using Stigsmith.Rules;

namespace Stigsmith.Api.Endpoints;

public static class GenerationEndpoints
{
    public static IEndpointRouteBuilder MapGenerationEndpoints(this IEndpointRouteBuilder app)
    {
        var checklists = app.MapGroup("/api/checklists").WithTags("Generation");

        checklists.MapPost("/{id:guid}/generate", Queue)
            .WithSummary("Queues remediation generation for a checklist's automatable open findings.");

        var generations = app.MapGroup("/api/generations").WithTags("Generation");

        generations.MapGet("/status", Status)
            .WithSummary("Reports whether the model provider is reachable and how deep the queue is.");

        generations.MapGet("/{id:guid}", GetGeneration)
            .WithSummary("Returns one generation with the exact prompt, model, and parameters used.");

        app.MapGet("/api/findings/{id:guid}/generations", ForFinding)
            .WithTags("Generation")
            .WithSummary("Lists generations for one finding, newest first.");

        return app;
    }

    /// <summary>
    /// Selects the findings worth generating for and queues them, reporting exactly what was skipped and why.
    /// </summary>
    /// <remarks>
    /// The skip reasons are the interesting output. An operator who asks for 45 open findings and gets 29 queued
    /// needs to see that 6 were policy rules and 10 need their judgement — otherwise the tool looks like it
    /// silently dropped their work. High-risk rules without an opt-in are reported the same way, naming the
    /// domains to opt into.
    /// </remarks>
    private static async Task<Results<Ok<QueueResult>, NotFound, BadRequest<ProblemDetails>>> Queue(
        Guid id,
        GenerateRequest? request,
        StigsmithDbContext db,
        GenerationQueue queue,
        IRemediationProvider provider,
        IOptions<GenerationOptions> options,
        ILoggerFactory loggers,
        CancellationToken ct)
    {
        var log = loggers.CreateLogger(typeof(GenerationEndpoints));
        request ??= new GenerateRequest();

        if (!await db.Checklists.AnyAsync(c => c.Id == id, ct))
            return TypedResults.NotFound();

        if (!await provider.IsAvailableAsync(ct))
            return TypedResults.BadRequest(new ProblemDetails
            {
                Title = "The model provider is not available",
                Detail = $"Provider '{provider.Name}' with model '{provider.Model}' could not be reached. "
                       + "Check that it is running and that the model is installed.",
                Status = StatusCodes.Status400BadRequest,
            });

        var optedIn = ParseDomains(request.OptInRiskDomains, out var unknownDomain);
        if (unknownDomain is not null)
            return TypedResults.BadRequest(new ProblemDetails
            {
                Title = "Unknown risk domain",
                Detail = $"'{unknownDomain}' is not a risk domain. Valid values: "
                       + string.Join(", ", Enum.GetValues<RiskDomain>().Select(d => d.ToToken())),
                Status = StatusCodes.Status400BadRequest,
            });

        var candidates = await db.Findings
            .Where(f => f.ChecklistId == id)
            .Where(f => request.IncludeAllStatuses || f.Status == FindingStatus.Open)
            .Where(f => request.RuleVersions == null || request.RuleVersions.Contains(f.RuleVersion))
            .OrderBy(f => f.NumericId)
            .ToListAsync(ct);

        var targetOs = request.TargetOs is { Length: > 0 } os ? os : options.Value.TargetOs;
        var queued = new List<QueuedGeneration>();
        var skipped = new List<SkippedGeneration>();

        foreach (var finding in candidates)
        {
            var classification = RuleClassifier.Classify(GenerationWorker.ToRuleContent(finding));
            var decision = GenerationEligibility.Evaluate(classification, optedIn);

            if (!decision.IsEligible)
            {
                skipped.Add(new SkippedGeneration(
                    finding.Id, finding.RuleVersion, decision.Verdict.ToString(), decision.Reason));
                continue;
            }

            var generationId = Guid.CreateVersion7();
            await queue.EnqueueAsync(
                new GenerationJob(generationId, id, finding.Id, targetOs, decision.RequireCheckMode), ct);

            queued.Add(new QueuedGeneration(
                generationId, finding.Id, finding.RuleVersion, decision.RequireCheckMode));
        }

        log.LogInformation(
            "Queued {Queued} generations for checklist {ChecklistId}, skipped {Skipped} of {Total} candidates.",
            queued.Count, id, skipped.Count, candidates.Count);

        return TypedResults.Ok(new QueueResult(
            id, provider.Name, provider.Model, targetOs,
            candidates.Count, queued.Count, skipped.Count, queue.Depth, queued, skipped));
    }

    private static async Task<Results<Ok<GenerationDetail>, NotFound>> GetGeneration(
        Guid id, StigsmithDbContext db, CancellationToken ct)
    {
        var record = await db.Generations
            .AsNoTracking()
            .Include(g => g.Finding)
            .FirstOrDefaultAsync(g => g.Id == id, ct);

        return record is null
            ? TypedResults.NotFound()
            : TypedResults.Ok(ToDetail(record));
    }

    private static async Task<List<GenerationSummary>> ForFinding(
        Guid id, StigsmithDbContext db, CancellationToken ct) =>
        await db.Generations
            .AsNoTracking()
            .Where(g => g.FindingId == id)
            .OrderByDescending(g => g.CreatedAt)
            .Select(g => new GenerationSummary(
                g.Id, g.Provider, g.Model, g.CreatedAt, g.Yaml.Length > 0, g.Error, g.CompletionTokens))
            .ToListAsync(ct);

    private static async Task<Ok<ProviderStatus>> Status(
        IRemediationProvider provider, GenerationQueue queue, CancellationToken ct) =>
        TypedResults.Ok(new ProviderStatus(
            provider.Name, provider.Model, await provider.IsAvailableAsync(ct), queue.Depth));

    /// <summary>
    /// The whole generation record, prompt included. An ISSO asking "what exactly did the model see?" gets an
    /// answer from this endpoint, which is also how the constraint 3 guarantee stays checkable in production.
    /// </summary>
    private static GenerationDetail ToDetail(GenerationRecord g) => new(
        g.Id,
        g.FindingId,
        g.Finding?.RuleId ?? "",
        g.Finding?.RuleVersion ?? "",
        g.Provider,
        g.Model,
        g.ParametersJson,
        g.TargetOs,
        g.SystemPrompt,
        g.UserPrompt,
        g.PromptSha256,
        g.RetrievedExampleIds.Split(',', StringSplitOptions.RemoveEmptyEntries),
        g.RawResponse,
        g.Yaml,
        g.Error,
        g.PromptTokens,
        g.CompletionTokens,
        g.CreatedAt);

    private static HashSet<RiskDomain> ParseDomains(string[]? tokens, out string? unknown)
    {
        unknown = null;
        var result = new HashSet<RiskDomain>();
        if (tokens is null) return result;

        var byToken = Enum.GetValues<RiskDomain>()
            .ToDictionary(d => d.ToToken(), d => d, StringComparer.OrdinalIgnoreCase);

        foreach (var token in tokens)
        {
            if (byToken.TryGetValue(token.Trim(), out var domain)) result.Add(domain);
            else { unknown = token; return result; }
        }
        return result;
    }
}

/// <param name="OptInRiskDomains">
/// Risk domains the operator accepts generation for, as tokens: sshd, pam, selinux, firewall, authentication,
/// network. Per-domain rather than a single switch: being willing to let the tool touch PAM on a lab host is not
/// consent to it rewriting the firewall.
/// </param>
public sealed record GenerateRequest(
    string[]? RuleVersions = null,
    string[]? OptInRiskDomains = null,
    string? TargetOs = null,
    bool IncludeAllStatuses = false);

public sealed record QueueResult(
    Guid ChecklistId,
    string Provider,
    string Model,
    string TargetOs,
    int Candidates,
    int Queued,
    int Skipped,
    int QueueDepth,
    List<QueuedGeneration> QueuedItems,
    List<SkippedGeneration> SkippedItems);

public sealed record QueuedGeneration(Guid GenerationId, Guid FindingId, string RuleVersion, bool RequiresCheckMode);

public sealed record SkippedGeneration(Guid FindingId, string RuleVersion, string Verdict, string Reason);

public sealed record GenerationSummary(
    Guid Id,
    string Provider,
    string Model,
    DateTimeOffset CreatedAt,
    bool HasYaml,
    string? Error,
    int CompletionTokens);

public sealed record GenerationDetail(
    Guid Id,
    Guid FindingId,
    string RuleId,
    string RuleVersion,
    string Provider,
    string Model,
    string ParametersJson,
    string TargetOs,
    string SystemPrompt,
    string UserPrompt,
    string PromptSha256,
    string[] RetrievedExamples,
    string RawResponse,
    string Yaml,
    string? Error,
    int PromptTokens,
    int CompletionTokens,
    DateTimeOffset CreatedAt);

public sealed record ProviderStatus(string Provider, string Model, bool Available, int QueueDepth);
