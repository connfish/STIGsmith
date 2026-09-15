using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Stigsmith.Api.Generation;
using Stigsmith.Api.Persistence;
using Stigsmith.Generation.Conventions;
using Stigsmith.Generation.Prompting;
using Stigsmith.Generation.Providers;
using Stigsmith.Rules;
using Stigsmith.Validation;

namespace Stigsmith.Api.Validation;

/// <summary>
/// Drains the validation queue: runs the loop for one generation and stores the evidence.
/// </summary>
/// <remarks>
/// <para>
/// One job at a time. Each job starts containers, applies a playbook twice, and runs a scan; several in parallel would
/// compete for the same CPU and disk and make every run slower while making the streamed log unreadable.
/// </para>
/// <para>
/// The repair callback is what connects this to the model: on a stage failure the tool output goes back through
/// <see cref="RemediationPromptAssembler.AssembleRepair"/>, the model's answer replaces the tasks, and the loop runs
/// again in a <b>fresh</b> container. Every attempt gets its own <see cref="ValidationRunRecord"/>, so the evidence
/// shows what was tried and what the error was, not just the final verdict.
/// </para>
/// </remarks>
public sealed class ValidationWorker(
    JobQueue<ValidationJob> queue,
    IServiceScopeFactory scopes,
    IValidationSandbox sandbox,
    IRemediationProvider provider,
    ConventionIndexProvider conventions,
    IHubContext<GenerationHub> hub,
    IOptions<ValidationOptions> validationOptions,
    IOptions<GenerationOptions> generationOptions,
    ILogger<ValidationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Validation worker started. Sandbox image {Image}.", sandbox.Image);

        await foreach (var job in queue.ReadAllAsync(stoppingToken))
        {
            try
            {
                await RunAsync(job, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // One rule's validation blowing up must not drain-stop the queue, and it must not vanish either: a run
                // with no row looks like it was never queued.
                logger.LogError(ex, "Validation run {ValidationRunId} failed unexpectedly.", job.ValidationRunId);
                await RecordFailureAsync(job, ex.Message, stoppingToken);
            }
        }
    }

    private async Task RunAsync(ValidationJob job, CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<StigsmithDbContext>();

        var generation = await db.Generations
            .Include(g => g.Finding)
            .FirstOrDefaultAsync(g => g.Id == job.GenerationId, cancellationToken);

        if (generation?.Finding is null)
        {
            logger.LogWarning("Validation {RunId} skipped: generation {GenerationId} no longer exists.",
                job.ValidationRunId, job.GenerationId);
            return;
        }

        if (generation.Yaml.Length == 0)
        {
            logger.LogInformation(
                "Validation {RunId} skipped: generation {GenerationId} produced no usable YAML.",
                job.ValidationRunId, job.GenerationId);
            return;
        }

        var finding = generation.Finding;
        var rule = GenerationWorker.ToRuleContent(finding);
        var classification = RuleClassifier.Classify(rule);
        var index = conventions.Current;
        var group = hub.Clients.Group(GenerationHub.GroupFor(job.ChecklistId));

        await group.SendAsync(
            ValidationEvents.Started,
            new ValidationStarted(job.ValidationRunId, generation.Id, finding.RuleVersion, sandbox.Image),
            cancellationToken);

        var request = new ValidationRequest
        {
            Rule = rule,
            TasksYaml = generation.Yaml,
            // Every variable the operator's role would supply, plus this rule's toggle, so a guarded task does not
            // skip as undefined and get misreported as "applied nothing".
            ReferencedVariables = [.. ReferencedVariables(index, rule)],
            RequireCheckMode = classification.IsHighRisk,
            RoleVarsFiles = [.. index.VarsFiles.Select(f => f.Content)],
            HandlerNames = index.HandlerNames,
        };

        var promptRequest = new RemediationRequest
        {
            Rule = rule,
            TargetOs = generation.TargetOs is { Length: > 0 } os ? os : generationOptions.Value.TargetOs,
            Examples = index.Retrieve(rule, conventions.Options.ExampleCount),
            Conventions = index.Conventions,
            RequireCheckMode = classification.IsHighRisk,
            RiskDomains = [.. classification.HighRiskDomains],
        };

        var validator = new RemediationValidator(
            sandbox,
            new ComplianceVerifier(validationOptions.Value),
            validationOptions.Value,
            scope.ServiceProvider.GetRequiredService<ILogger<RemediationValidator>>());

        var attempts = await validator.ValidateAsync(
            request,
            (repair, ct) => RepairAsync(promptRequest, repair, ct),
            cancellationToken);

        // One row per attempt. The first attempt's error is the reason the repair happened, and hiding it would leave
        // a reviewer unable to see what the model got wrong.
        for (var i = 0; i < attempts.Count; i++)
            db.ValidationRuns.Add(ToRecord(
                i == 0 ? job.ValidationRunId : Guid.CreateVersion7(), generation.Id, attempts[i]));
        await db.SaveChangesAsync(cancellationToken);

        var final = attempts[^1];
        logger.LogInformation(
            "Validated {RuleVersion}: {Outcome} after {Attempts} attempt(s). {Summary}",
            finding.RuleVersion, final.Outcome, attempts.Count, final.Summary);

        foreach (var stage in final.Stages)
            await group.SendAsync(
                ValidationEvents.Stage,
                new ValidationStageEvent(
                    job.ValidationRunId, stage.Stage.ToString(), stage.Passed, stage.ExitCode,
                    stage.Duration.TotalSeconds, stage.Output),
                cancellationToken);

        await group.SendAsync(
            ValidationEvents.Completed,
            new ValidationCompleted(
                job.ValidationRunId, generation.Id, finding.RuleVersion,
                final.Outcome.ToString(), final.FailedStage?.ToString(), attempts.Count,
                final.ScanStatusBefore, final.ScanStatusAfter, final.VerifiedBy.ToString(),
                final.IdempotencyChangedCount, final.Summary),
            cancellationToken);
    }

    private async Task RecordFailureAsync(ValidationJob job, string error, CancellationToken cancellationToken)
    {
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<StigsmithDbContext>();
            if (await db.ValidationRuns.AnyAsync(r => r.Id == job.ValidationRunId, cancellationToken)) return;

            var evidence = new ValidationEvidence
            {
                Outcome = ValidationOutcome.NeedsHumanReview,
                ContainerImage = sandbox.Image,
                Summary = $"Validation did not complete: {error}",
                CompletedAt = DateTimeOffset.UtcNow,
            };
            db.ValidationRuns.Add(ToRecord(job.ValidationRunId, job.GenerationId, evidence));
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // Already in the failure path; log and move on rather than losing the rest of the queue.
            logger.LogError(ex, "Could not record the failure of validation run {ValidationRunId}.", job.ValidationRunId);
        }
    }

    private async Task<string?> RepairAsync(
        RemediationRequest promptRequest, RepairRequest repair, CancellationToken cancellationToken)
    {
        var prompt = RemediationPromptAssembler.AssembleRepair(
            promptRequest, repair.PreviousYaml, repair.FailedStage.ToString(), repair.ErrorOutput);

        var response = new System.Text.StringBuilder();
        try
        {
            await foreach (var chunk in provider.StreamAsync(
                prompt, generationOptions.Value.Parameters, cancellationToken))
                response.Append(chunk.Text);
        }
        catch (Exception ex) when (ex is RemediationProviderException or HttpRequestException)
        {
            // A model that cannot be reached during repair is not a repair failure worth retrying: return nothing and
            // let the loop mark the rule for a human.
            logger.LogWarning(ex, "The repair attempt could not reach the model.");
            return null;
        }

        var extracted = AnsibleYamlExtractor.Extract(response.ToString());
        return extracted.IsUsable ? extracted.Yaml : null;
    }

    /// <summary>
    /// Variables the generated tasks may reference and the role's own files do not define, plus this rule's per-rule
    /// toggle derived from the role's template. The toggle is included even when the role defines it, because the
    /// placeholder file is applied last and the sandbox must run the task whatever the operator's default says.
    /// </summary>
    private static IEnumerable<string> ReferencedVariables(RoleIndex index, Stigsmith.Checklists.Model.RuleContent rule)
    {
        var defined = index.VarsFiles.SelectMany(f => f.Names).ToHashSet(StringComparer.Ordinal);
        foreach (var name in index.Tasks.SelectMany(t => t.Variables).Distinct(StringComparer.Ordinal))
            if (!defined.Contains(name)) yield return name;

        if (index.Conventions.RuleToggleTemplate is { Length: > 0 } template && rule.NumericId is { Length: > 0 })
            yield return template.Replace("<vuln number>", rule.NumericId, StringComparison.Ordinal);
    }

    private static ValidationRunRecord ToRecord(Guid id, Guid generationId, ValidationEvidence evidence) => new()
    {
        Id = id,
        GenerationId = generationId,
        Outcome = evidence.Outcome,
        FailedStage = evidence.FailedStage?.ToString() ?? "",
        RepairAttempt = evidence.RepairAttempt,
        LintOutput = evidence.Stage(ValidationStage.Lint)?.Output ?? "",
        SyntaxCheckOutput = evidence.Stage(ValidationStage.SyntaxCheck)?.Output ?? "",
        ApplyOutput = evidence.Stage(ValidationStage.Apply)?.Output ?? "",
        ScanStatusBefore = evidence.ScanStatusBefore,
        ScanStatusAfter = evidence.ScanStatusAfter,
        IdempotencyOutput = evidence.Stage(ValidationStage.Idempotency)?.Output ?? "",
        IdempotencyChangedCount = evidence.IdempotencyChangedCount,
        ContainerImage = evidence.ContainerImage,
        EvidenceJson = evidence.ToJson(),
        StartedAt = evidence.StartedAt,
        CompletedAt = evidence.CompletedAt,
    };
}
