using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Validation;

/// <summary>What the validator is asked to prove about one generated remediation.</summary>
public sealed record ValidationRequest
{
    public required RuleContent Rule { get; init; }

    /// <summary>The generated Ansible tasks, as extracted from the model's response.</summary>
    public required string TasksYaml { get; init; }

    /// <summary>
    /// Variables the tasks reference, so a vars file can supply them. Without this, a task guarded by the operator's
    /// per-rule toggle skips as undefined and the loop would report "applied nothing" against correct Ansible.
    /// </summary>
    public IReadOnlyCollection<string> ReferencedVariables { get; init; } = [];

    /// <summary>True for a high-risk rule: the loop additionally proves the tasks survive <c>--check</c>.</summary>
    public bool RequireCheckMode { get; init; }
}

/// <summary>Asks the model to fix its own output, given the error. Injected so the loop does not depend on the generation stack.</summary>
/// <param name="Rule">The rule being remediated.</param>
/// <param name="PreviousYaml">What was tried.</param>
/// <param name="FailedStage">Where it failed.</param>
/// <param name="ErrorOutput">The tool output to feed back, verbatim.</param>
public sealed record RepairRequest(RuleContent Rule, string PreviousYaml, ValidationStage FailedStage, string ErrorOutput);

/// <summary>
/// Runs the validation loop: lint, syntax check, apply, re-scan, prove idempotent — with one repair attempt.
/// </summary>
/// <remarks>
/// <para>
/// This is the product. Generated Ansible is worthless until it has been linted, applied in a disposable container,
/// re-scanned, and proven idempotent, and the evidence of all four is what an ISSO actually accepts. The stages run
/// in order and stop at the first failure, because a playbook that does not lint cannot usefully be applied and a
/// playbook that did not apply cannot be re-scanned.
/// </para>
/// <para>
/// Each attempt gets a <b>fresh container</b>. Reusing one would mean the second apply starts from a host the first
/// apply already changed, which is exactly the state that makes a non-idempotent playbook look idempotent. The
/// idempotency check is the one place a second apply happens in the <em>same</em> container, which is the point.
/// </para>
/// <para>
/// On failure the error output is fed back for exactly one repair attempt. Failing again is not retried further:
/// a model that cannot fix its own output given the error twice will not manage it on a third go, and
/// "needs-human-review" is a more useful answer than a third round of the same mistake.
/// </para>
/// </remarks>
public sealed class RemediationValidator(
    IValidationSandbox sandbox,
    ComplianceVerifier verifier,
    ValidationOptions options,
    ILogger<RemediationValidator>? logger = null)
{
    /// <summary>
    /// Validates one remediation, repairing once on failure.
    /// </summary>
    /// <param name="repair">
    /// Asked for new YAML when a stage fails. Null disables repair, in which case a first failure goes straight to
    /// <see cref="ValidationOutcome.NeedsHumanReview"/>.
    /// </param>
    public async Task<IReadOnlyList<ValidationEvidence>> ValidateAsync(
        ValidationRequest request,
        Func<RepairRequest, CancellationToken, Task<string?>>? repair = null,
        CancellationToken cancellationToken = default)
    {
        var attempts = new List<ValidationEvidence>();
        var yaml = request.TasksYaml;

        for (var attempt = 0; attempt <= options.MaxRepairAttempts; attempt++)
        {
            var evidence = await RunOnceAsync(request with { TasksYaml = yaml }, attempt, cancellationToken);
            attempts.Add(evidence);

            if (evidence.Outcome == ValidationOutcome.Passed)
                return attempts;

            var isLastAttempt = attempt == options.MaxRepairAttempts;
            if (isLastAttempt || repair is null)
            {
                // Mark the final attempt as needing a human rather than merely failed: the difference is whether
                // anyone is expected to look at it, and a queue of "failed" with no owner is a queue nobody works.
                attempts[^1] = evidence with
                {
                    Outcome = ValidationOutcome.NeedsHumanReview,
                    Summary = evidence.Summary + (repair is null
                        ? " No repair was attempted."
                        : " The repair attempt also failed; this needs a human."),
                };
                return attempts;
            }

            logger?.LogInformation(
                "Validation of {RuleVersion} failed at {Stage}; attempting one repair.",
                request.Rule.RuleVersion, evidence.FailedStage);

            var repaired = await repair(
                new RepairRequest(
                    request.Rule, yaml, evidence.FailedStage ?? ValidationStage.Lint,
                    evidence.Stages.LastOrDefault()?.Output ?? evidence.Summary),
                cancellationToken);

            if (string.IsNullOrWhiteSpace(repaired))
            {
                attempts[^1] = evidence with
                {
                    Outcome = ValidationOutcome.NeedsHumanReview,
                    Summary = evidence.Summary + " The model produced no repaired playbook; this needs a human.",
                };
                return attempts;
            }

            yaml = repaired;
        }

        return attempts;
    }

    private async Task<ValidationEvidence> RunOnceAsync(
        ValidationRequest request, int attempt, CancellationToken cancellationToken)
    {
        var playbook = PlaybookBuilder.Build(request.TasksYaml, request.Rule.RuleVersion);
        var stages = new List<StageEvidence>();
        var startedAt = DateTimeOffset.UtcNow;

        ValidationEvidence Result(
            ValidationOutcome outcome,
            ValidationStage? failedStage,
            string summary,
            string before = "",
            string after = "",
            ComplianceVerifierKind verifiedBy = ComplianceVerifierKind.None,
            int changed = -1) => new()
            {
                Outcome = outcome,
                FailedStage = failedStage,
                RepairAttempt = attempt,
                ContainerImage = sandbox.Image,
                Stages = stages,
                ScanStatusBefore = before,
                ScanStatusAfter = after,
                VerifiedBy = verifiedBy,
                IdempotencyChangedCount = changed,
                Playbook = playbook,
                Summary = summary,
                StartedAt = startedAt,
                CompletedAt = DateTimeOffset.UtcNow,
            };

        if (!await sandbox.IsAvailableAsync(cancellationToken))
        {
            stages.Add(StageEvidence.Skipped(ValidationStage.Lint, "No container runtime is available."));
            return Result(ValidationOutcome.Skipped, null,
                "Validation was not attempted: no container runtime is available. Generated remediation is "
                + "unvalidated and must not be treated as verified.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.PerRuleTimeout);
        var ct = timeout.Token;

        await using var session = await sandbox.StartAsync(ct);
        var work = options.WorkDirectory;

        await session.WriteFileAsync($"{work}/playbook.yml", playbook, ct);
        await session.WriteFileAsync(
            $"{work}/vars.yml",
            PlaybookBuilder.BuildVarsFile(request.ReferencedVariables),
            ct);

        var runPlaybook = $"cd {work} && ansible-playbook -i localhost, -c local -e @vars.yml playbook.yml";

        // --- 1. Lint ---
        var lint = await Timed(ValidationStage.Lint, stages,
            $"cd {work} && ansible-lint --nocolor playbook.yml", session, ct,
            passed: AnsibleOutputParser.LintPassed);
        if (!lint.Passed)
            return Result(ValidationOutcome.Failed, ValidationStage.Lint,
                "ansible-lint rejected the generated playbook.");

        // --- 1b. Syntax check ---
        var syntax = await Timed(ValidationStage.SyntaxCheck, stages,
            $"{runPlaybook} --syntax-check", session, ct);
        if (!syntax.Passed)
            return Result(ValidationOutcome.Failed, ValidationStage.SyntaxCheck,
                "ansible-playbook --syntax-check rejected the generated playbook.");

        // --- 2. Status before, so the re-scan afterwards means something ---
        var before = await verifier.VerifyAsync(session, request.Rule, ct);
        stages.Add(new StageEvidence(
            ValidationStage.Rescan, Passed: true, before.Command, before.Output.ExitCode,
            $"before remediation: {before.Status}\n{before.Output.Combined}", TimeSpan.Zero));

        // --- 2b. Check mode, for high-risk rules, before touching anything ---
        if (request.RequireCheckMode)
        {
            var checkMode = await Timed(ValidationStage.Apply, stages, $"{runPlaybook} --check", session, ct,
                passed: r => AnsibleOutputParser.ParseRecap(r.Combined).Clean && r.Succeeded);
            if (!checkMode.Passed)
                return Result(ValidationOutcome.Failed, ValidationStage.Apply,
                    "This is a high-risk rule and the playbook failed under --check, so an operator could not "
                    + "dry-run it safely.",
                    before: before.Status, verifiedBy: before.Kind);
        }

        // --- 3. Apply ---
        var apply = await Timed(ValidationStage.Apply, stages, runPlaybook, session, ct,
            passed: r => AnsibleOutputParser.AppliedSomething(AnsibleOutputParser.ParseRecap(r.Combined)));
        var applyRecap = AnsibleOutputParser.ParseRecap(apply.Output);
        if (!apply.Passed)
            return Result(ValidationOutcome.Failed, ValidationStage.Apply,
                applyRecap.Clean
                    ? "The playbook ran but applied nothing — every task was skipped, so the finding is untouched."
                    : $"The playbook failed to apply ({applyRecap.Failed} failed task(s)).",
                before: before.Status, verifiedBy: before.Kind);

        // --- 4. Re-scan and confirm the finding flipped ---
        var after = await verifier.VerifyAsync(session, request.Rule, ct);
        stages.Add(new StageEvidence(
            ValidationStage.Rescan, after.Passed, after.Command, after.Output.ExitCode,
            $"after remediation: {after.Status}\n{after.Output.Combined}", TimeSpan.Zero));

        if (!after.Passed)
            return Result(ValidationOutcome.Failed, ValidationStage.Rescan,
                after.Kind == ComplianceVerifierKind.None
                    ? "The playbook applied cleanly, but the finding could not be verified, so nothing here proves "
                      + "the rule now passes."
                    : $"The playbook applied cleanly but the rule still reports '{after.Status}' after remediation.",
                before: before.Status, after: after.Status, verifiedBy: after.Kind);

        // --- 5. Idempotency: apply again, expect zero changes ---
        var second = await Timed(ValidationStage.Idempotency, stages, runPlaybook, session, ct,
            passed: r => AnsibleOutputParser.ParseRecap(r.Combined).Idempotent);
        var secondRecap = AnsibleOutputParser.ParseRecap(second.Output);
        if (!second.Passed)
            return Result(ValidationOutcome.Failed, ValidationStage.Idempotency,
                $"The playbook is not idempotent: a second apply reported {secondRecap.Changed} changed task(s).",
                before: before.Status, after: after.Status, verifiedBy: after.Kind,
                changed: secondRecap.Changed);

        return Result(ValidationOutcome.Passed, null,
            $"Linted clean, applied {applyRecap.Changed} changed task(s), the rule flipped from "
            + $"'{before.Status}' to '{after.Status}' ({after.Kind}), and a second apply changed nothing.",
            before: before.Status, after: after.Status, verifiedBy: after.Kind, changed: secondRecap.Changed);
    }

    private static async Task<StageEvidence> Timed(
        ValidationStage stage,
        List<StageEvidence> stages,
        string command,
        IValidationSession session,
        CancellationToken cancellationToken,
        Func<ExecResult, bool>? passed = null)
    {
        var clock = Stopwatch.StartNew();
        var result = await session.ExecAsync(command, cancellationToken);
        clock.Stop();

        var evidence = new StageEvidence(
            stage,
            passed?.Invoke(result) ?? result.Succeeded,
            command,
            result.ExitCode,
            result.Combined,
            clock.Elapsed);

        stages.Add(evidence);
        return evidence;
    }
}
