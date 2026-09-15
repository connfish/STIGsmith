using System.Text;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Stigsmith.Api.Persistence;
using Stigsmith.Checklists.Model;
using Stigsmith.Generation.Conventions;
using Stigsmith.Generation.Prompting;
using Stigsmith.Generation.Providers;
using Stigsmith.Rules;

namespace Stigsmith.Api.Generation;

/// <summary>
/// Drains the generation queue: assembles a prompt, streams the model's answer to subscribers, and persists the
/// result.
/// </summary>
/// <remarks>
/// <para>
/// One job at a time, deliberately. The default provider is a local model that serves one request at a time
/// anyway, so concurrency here would only queue requests inside Ollama instead of in the channel, while making
/// the streamed output interleave incomprehensibly for anyone watching.
/// </para>
/// <para>
/// The <see cref="GenerationRecord"/> is written <b>before</b> the model is called, carrying the full prompt,
/// model, and parameters. If the call then fails, the prompt that failed is still on record — which is the point
/// of persisting it, and is also what keeps the constraint 3 guarantee auditable after the fact rather than only
/// at test time.
/// </para>
/// </remarks>
public sealed class GenerationWorker(
    JobQueue<GenerationJob> queue,
    IServiceScopeFactory scopes,
    IRemediationProvider provider,
    ConventionIndexProvider conventions,
    IHubContext<GenerationHub> hub,
    IOptions<GenerationOptions> options,
    ILogger<GenerationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation(
            "Generation worker started. Provider {Provider}, model {Model}.", provider.Name, provider.Model);

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
                // A single rule failing must not take the worker down; the rest of the queue is still worth
                // draining, and the failure is recorded against its own generation row.
                logger.LogError(ex, "Generation {GenerationId} failed unexpectedly.", job.GenerationId);
                await RecordFailureAsync(job, ex.Message, stoppingToken);
            }
        }
    }

    private async Task RunAsync(GenerationJob job, CancellationToken cancellationToken)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<StigsmithDbContext>();

        var finding = await db.Findings.FirstOrDefaultAsync(f => f.Id == job.FindingId, cancellationToken);
        if (finding is null)
        {
            logger.LogWarning("Generation {GenerationId} skipped: finding {FindingId} no longer exists.",
                job.GenerationId, job.FindingId);
            return;
        }

        var rule = ToRuleContent(finding);
        var classification = RuleClassifier.Classify(rule);
        var index = conventions.Current;
        var examples = index.Retrieve(rule, conventions.Options.ExampleCount);

        var prompt = RemediationPromptAssembler.Assemble(new RemediationRequest
        {
            Rule = rule,
            TargetOs = job.TargetOs,
            Examples = examples,
            Conventions = index.Conventions,
            RequireCheckMode = job.RequireCheckMode,
            RiskDomains = [.. classification.HighRiskDomains],
        });

        var parameters = options.Value.Parameters;
        var record = new GenerationRecord
        {
            Id = job.GenerationId,
            FindingId = finding.Id,
            Provider = provider.Name,
            Model = provider.Model,
            ParametersJson = parameters.ToJson(),
            SystemPrompt = prompt.System,
            UserPrompt = prompt.User,
            PromptSha256 = prompt.Sha256Hex,
            TargetOs = job.TargetOs,
            RetrievedExampleIds = string.Join(',', examples.Select(e => e.Task.Reference)),
        };
        db.Generations.Add(record);
        await db.SaveChangesAsync(cancellationToken);

        var group = hub.Clients.Group(GenerationHub.GroupFor(job.ChecklistId));
        await group.SendAsync(
            GenerationEvents.Started,
            new GenerationStarted(record.Id, finding.Id, finding.RuleVersion, provider.Name, provider.Model),
            cancellationToken);

        var response = new StringBuilder();
        var promptTokens = 0;
        var completionTokens = 0;

        try
        {
            await foreach (var chunk in provider.StreamAsync(prompt, parameters, cancellationToken))
            {
                if (chunk.Text.Length > 0)
                {
                    response.Append(chunk.Text);
                    await group.SendAsync(
                        GenerationEvents.Chunk,
                        new GenerationChunkEvent(record.Id, chunk.Text),
                        cancellationToken);
                }

                if (!chunk.IsFinal) continue;
                promptTokens = chunk.PromptTokens;
                completionTokens = chunk.CompletionTokens;
            }
        }
        catch (Exception ex) when (ex is RemediationProviderException or HttpRequestException)
        {
            record.Error = ex.Message;
            record.RawResponse = response.ToString();
            await db.SaveChangesAsync(cancellationToken);

            logger.LogError(ex, "Generation for {RuleVersion} failed: {Message}", finding.RuleVersion, ex.Message);
            await group.SendAsync(
                GenerationEvents.Failed,
                new GenerationFailed(record.Id, finding.Id, finding.RuleVersion, ex.Message),
                cancellationToken);
            return;
        }

        var extracted = AnsibleYamlExtractor.Extract(response.ToString());

        record.RawResponse = response.ToString();
        record.Yaml = extracted.IsUsable ? extracted.Yaml : "";
        record.PromptTokens = promptTokens;
        record.CompletionTokens = completionTokens;
        // "Cannot automate" is the model answering correctly, not failing, so it is not an Error. Invalid YAML
        // is a failure, and its message is what M6 feeds back on the repair attempt.
        record.Error = extracted.Kind == GeneratedYamlKind.Invalid ? extracted.Message : null;
        await db.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "Generated {RuleVersion}: {Kind} ({TaskCount} tasks, {CompletionTokens} tokens). {Message}",
            finding.RuleVersion, extracted.Kind, extracted.TaskNames.Count, completionTokens, extracted.Message);

        await group.SendAsync(
            GenerationEvents.Completed,
            new GenerationCompleted(
                record.Id, finding.Id, finding.RuleVersion,
                extracted.Kind.ToString(), extracted.Message, extracted.TaskNames.Count,
                promptTokens, completionTokens),
            cancellationToken);
    }

    private async Task RecordFailureAsync(GenerationJob job, string error, CancellationToken cancellationToken)
    {
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<StigsmithDbContext>();
            var record = await db.Generations.FirstOrDefaultAsync(g => g.Id == job.GenerationId, cancellationToken);
            if (record is null)
            {
                // The failure came before the prompt was persisted. A row still has to exist, or the generation the
                // operator was told about is a 404 forever.
                record = new GenerationRecord
                {
                    Id = job.GenerationId,
                    FindingId = job.FindingId,
                    Provider = provider.Name,
                    Model = provider.Model,
                    TargetOs = job.TargetOs,
                };
                db.Generations.Add(record);
            }

            record.Error = error;
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // Already in the failure path; log and move on rather than losing the rest of the queue.
            logger.LogError(ex, "Could not record the failure of generation {GenerationId}.", job.GenerationId);
        }
    }

    /// <summary>
    /// Builds the model's view of a finding. Note what is absent: this is a <see cref="RuleContent"/>, so no host
    /// column is reachable from here, and neither are the finding's own details or comments — those are scan
    /// output that quotes the live system (constraint 3).
    /// </summary>
    internal static RuleContent ToRuleContent(FindingRecord finding) => new()
    {
        RuleId = finding.RuleId,
        GroupId = finding.GroupId,
        RuleVersion = finding.RuleVersion,
        Title = finding.Title,
        Severity = finding.Severity,
        FixText = finding.FixText,
        CheckContent = finding.CheckContent,
        Discussion = finding.Discussion,
        CciRefs = finding.CciRefs.Split(',', StringSplitOptions.RemoveEmptyEntries),
    };
}

/// <summary>Generation defaults.</summary>
public sealed class GenerationOptions
{
    public const string SectionName = "Stigsmith:Generation";

    /// <summary>
    /// Stated rather than inferred from the checklist: a RHEL 8 benchmark gets applied to Rocky and Alma hosts
    /// too, and the playbook needs to name what it actually targets.
    /// </summary>
    public string TargetOs { get; set; } = "Red Hat Enterprise Linux 8";

    public GenerationParameters Parameters { get; set; } = new();
}
