using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Stigsmith.Api.Persistence;
using Stigsmith.Checklists.Model;
using Stigsmith.Generation.Conventions;

namespace Stigsmith.Api.Endpoints;

public static class ConventionEndpoints
{
    public static RouteGroupBuilder MapConventionEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/conventions").WithTags("Conventions");

        group.MapGet("/", Describe)
            .WithSummary("Reports the indexed convention role: task count, inferred house style, and anything that failed to parse.");

        group.MapPost("/reindex", Reindex)
            .WithSummary("Re-reads the convention role from disk. Use after pulling changes to it.");

        group.MapGet("/examples/{findingId:guid}", ExamplesForFinding)
            .WithSummary("Shows the existing role tasks that would be used as few-shot examples for a finding.");

        return group;
    }

    private static Ok<ConventionReport> Describe(ConventionIndexProvider provider) =>
        TypedResults.Ok(Report(provider.Current, provider.Options));

    private static Ok<ConventionReport> Reindex(ConventionIndexProvider provider) =>
        TypedResults.Ok(Report(provider.Reindex(), provider.Options));

    private static ConventionReport Report(RoleIndex index, ConventionRoleOptions options) => new(
        options.Path,
        index.RolePath,
        index.Tasks.Count,
        index.UnavailableReason,
        index.Conventions.VariablePrefix,
        index.Conventions.RuleToggleTemplate,
        index.Conventions.UsesFullyQualifiedModules,
        [.. index.Conventions.CommonModules],
        [.. index.Conventions.HandlerNames],
        [.. index.Conventions.CommonTags],
        index.Conventions.Describe(),
        [.. index.SkippedFiles]);

    /// <summary>
    /// Shows what retrieval would feed the model for a given finding. Exists so an operator can check that
    /// their role indexed usefully before trusting anything generated from it — "these three tasks are what
    /// the model will imitate" is inspectable in a way that a similarity score is not.
    /// </summary>
    private static async Task<Results<Ok<ExamplesResponse>, NotFound>> ExamplesForFinding(
        Guid findingId,
        int? count,
        StigsmithDbContext db,
        ConventionIndexProvider provider,
        CancellationToken ct)
    {
        var finding = await db.Findings.AsNoTracking().FirstOrDefaultAsync(f => f.Id == findingId, ct);
        if (finding is null) return TypedResults.NotFound();

        // Built from the stored rule fields only. Note what is absent: this is a RuleContent, so there is no
        // host metadata available here even by accident (constraint 3).
        var rule = new RuleContent
        {
            RuleId = finding.RuleId,
            GroupId = finding.GroupId,
            RuleVersion = finding.RuleVersion,
            Title = finding.Title,
            Severity = finding.Severity,
            FixText = finding.FixText,
            CheckContent = finding.CheckContent,
            Discussion = finding.Discussion,
        };

        var index = provider.Current;
        var retrieved = index.Retrieve(rule, count ?? provider.Options.ExampleCount);

        return TypedResults.Ok(new ExamplesResponse(
            finding.RuleId,
            finding.RuleVersion,
            index.UnavailableReason,
            index.Conventions.Describe(),
            [.. retrieved.Select(r => new ExampleTask(
                r.Task.Reference,
                r.Task.Name,
                r.Task.Module,
                r.Kind.ToString(),
                double.IsInfinity(r.Score) ? null : Math.Round(r.Score, 3),
                r.Reason,
                r.Task.RawYaml))]));
    }
}

public sealed record ConventionReport(
    string? ConfiguredPath,
    string ResolvedPath,
    int TaskCount,
    string? UnavailableReason,
    string? VariablePrefix,
    string? RuleToggleTemplate,
    bool UsesFullyQualifiedModules,
    List<string> CommonModules,
    List<string> HandlerNames,
    List<string> CommonTags,
    string Description,
    List<string> SkippedFiles);

public sealed record ExamplesResponse(
    string RuleId,
    string RuleVersion,
    string? UnavailableReason,
    string ConventionDescription,
    List<ExampleTask> Examples);

public sealed record ExampleTask(
    string Reference,
    string Name,
    string Module,
    string MatchKind,
    double? Score,
    string Reason,
    string Yaml);
