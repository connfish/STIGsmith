using Microsoft.Extensions.Logging.Abstractions;
using Stigsmith.Checklists.Model;
using Stigsmith.Tests.Support;
using Stigsmith.Validation;

namespace Stigsmith.Tests.Validation;

/// <summary>
/// The validation loop's decision logic, driven against <see cref="ScriptedSandbox"/>.
/// </summary>
/// <remarks>
/// Every failure path gets a test, because the loop's value is entirely in what it refuses to pass. A loop that
/// reported success on a playbook that applied nothing, or on one that is not idempotent, would be worse than no
/// loop at all — it would produce evidence for something that did not happen.
/// </remarks>
public class RemediationValidatorTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly RuleContent SshRule = new()
    {
        RuleId = "SV-230296r1130296_rule",
        GroupId = "V-230296",
        RuleVersion = "RHEL-08-010550",
        Title = "RHEL 8 must not permit direct logons to the root account using remote access via SSH.",
        Severity = Severity.Medium,
        FixText = "Edit \"/etc/ssh/sshd_config\" and set:\n\nPermitRootLogin no",
        CheckContent = "Verify the setting with the following command:\n\n"
                     + "$ sudo grep -i permitrootlogin /etc/ssh/sshd_config\nPermitRootLogin no\n\n"
                     + "If it is set to any other value, this is a finding.",
    };

    private static RemediationValidator Validator(ScriptedSandbox sandbox, ValidationOptions? options = null)
    {
        options ??= new ValidationOptions();
        return new RemediationValidator(
            sandbox, new ComplianceVerifier(options), options, NullLogger<RemediationValidator>.Instance);
    }

    private static ValidationRequest Request(string? tasks = null, bool highRisk = false) => new()
    {
        Rule = SshRule,
        TasksYaml = tasks ?? """
            - name: "RHEL-08-010550 | PATCH | Root SSH logon"
              ansible.builtin.lineinfile:
                path: /etc/ssh/sshd_config
                regexp: '^(?i)\s*PermitRootLogin'
                line: PermitRootLogin no
            """,
        ReferencedVariables = ["stigsmith_rhel8_rule_230296"],
        RequireCheckMode = highRisk,
    };

    [Fact]
    public async Task A_good_remediation_passes_every_stage_and_records_the_evidence()
    {
        var sandbox = new ScriptedSandbox();

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        var evidence = attempts.ShouldHaveSingleItem();
        evidence.Outcome.ShouldBe(ValidationOutcome.Passed);
        evidence.FailedStage.ShouldBeNull();
        evidence.RepairAttempt.ShouldBe(0);

        // The stages an ISSO reads, in order.
        evidence.Stage(ValidationStage.Lint)!.Passed.ShouldBeTrue();
        evidence.Stage(ValidationStage.SyntaxCheck)!.Passed.ShouldBeTrue();
        evidence.Stage(ValidationStage.Apply)!.Passed.ShouldBeTrue();
        evidence.Stage(ValidationStage.Idempotency)!.Passed.ShouldBeTrue();

        // The claim that actually matters: the finding flipped.
        evidence.ScanStatusBefore.ShouldBe("fail");
        evidence.ScanStatusAfter.ShouldBe("pass");
        evidence.VerifiedBy.ShouldBe(ComplianceVerifierKind.CheckContent);
        evidence.IdempotencyChangedCount.ShouldBe(0);
        evidence.Playbook.ShouldContain("hosts: localhost");
        evidence.Playbook.ShouldContain("PermitRootLogin no");
        evidence.Summary.ShouldContain("flipped from 'fail' to 'pass'");
        evidence.CompletedAt.ShouldNotBeNull();
        sandbox.SessionsDisposed.ShouldBe(sandbox.SessionsStarted);
    }

    [Fact]
    public async Task Lint_failure_stops_before_anything_is_applied()
    {
        var sandbox = new ScriptedSandbox { LintFails = true };

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        attempts[^1].FailedStage.ShouldBe(ValidationStage.Lint);
        attempts[^1].Outcome.ShouldBe(ValidationOutcome.NeedsHumanReview);
        attempts[^1].Stage(ValidationStage.Apply).ShouldBeNull();
        sandbox.Commands.ShouldNotContain(c => c.Contains("ansible-playbook") && !c.Contains("--syntax-check"));
    }

    [Fact]
    public async Task Syntax_check_failure_stops_before_anything_is_applied()
    {
        var sandbox = new ScriptedSandbox { SyntaxFails = true };

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        attempts[^1].FailedStage.ShouldBe(ValidationStage.SyntaxCheck);
        attempts[^1].Stage(ValidationStage.Apply).ShouldBeNull();
    }

    [Fact]
    public async Task A_failed_apply_is_reported_with_the_failure_count()
    {
        var sandbox = new ScriptedSandbox { ApplyFails = true };

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        attempts[^1].FailedStage.ShouldBe(ValidationStage.Apply);
        attempts[^1].Summary.ShouldContain("failed to apply");
    }

    /// <summary>
    /// The most dangerous shape: ansible-playbook exits 0 with every task skipped. Trusting the exit code would
    /// record a pass for a run that touched nothing.
    /// </summary>
    [Fact]
    public async Task A_playbook_that_applies_nothing_is_not_a_pass()
    {
        var sandbox = new ScriptedSandbox { ApplyChangesNothing = true };

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        attempts[^1].Outcome.ShouldBe(ValidationOutcome.NeedsHumanReview);
        attempts[^1].FailedStage.ShouldBe(ValidationStage.Apply);
        attempts[^1].Summary.ShouldContain("applied nothing");
    }

    /// <summary>
    /// Applied cleanly and the finding still fails. This is the case that separates "the YAML ran" from "the rule is
    /// fixed", and it is the whole reason step 3 exists.
    /// </summary>
    [Fact]
    public async Task Remediation_that_does_not_fix_the_finding_fails_at_the_rescan()
    {
        var sandbox = new ScriptedSandbox { RescanNeverPasses = true };

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        attempts[^1].FailedStage.ShouldBe(ValidationStage.Rescan);
        attempts[^1].ScanStatusAfter.ShouldBe("fail");
        attempts[^1].Summary.ShouldContain("still reports 'fail'");
    }

    [Fact]
    public async Task A_non_idempotent_playbook_fails_the_second_apply()
    {
        var sandbox = new ScriptedSandbox { NotIdempotent = true };

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        attempts[^1].FailedStage.ShouldBe(ValidationStage.Idempotency);
        attempts[^1].IdempotencyChangedCount.ShouldBe(1);
        attempts[^1].Summary.ShouldContain("not idempotent");
        // It still flipped the finding; that is recorded, because it is true and useful.
        attempts[^1].ScanStatusAfter.ShouldBe("pass");
    }

    /// <summary>
    /// A high-risk rule is dry-run before it is applied. An operator who cannot --check a playbook that could lock
    /// them out has no safe way to review it.
    /// </summary>
    [Fact]
    public async Task A_high_risk_rule_that_fails_check_mode_never_gets_applied()
    {
        var sandbox = new ScriptedSandbox { CheckModeFails = true };

        var attempts = await Validator(sandbox).ValidateAsync(Request(highRisk: true), cancellationToken: Ct);

        attempts[^1].FailedStage.ShouldBe(ValidationStage.Apply);
        attempts[^1].Summary.ShouldContain("--check");
        sandbox.Commands.ShouldContain(c => c.Contains("--check"));
    }

    [Fact]
    public async Task A_high_risk_rule_that_survives_check_mode_passes()
    {
        var sandbox = new ScriptedSandbox();

        var attempts = await Validator(sandbox).ValidateAsync(Request(highRisk: true), cancellationToken: Ct);

        attempts[^1].Outcome.ShouldBe(ValidationOutcome.Passed);
        sandbox.Commands.ShouldContain(c => c.Contains("--check"));
    }

    // --- The repair attempt ---

    [Fact]
    public async Task A_failure_is_repaired_once_and_passes()
    {
        var sandbox = new ScriptedSandbox();
        var repairs = 0;

        var attempts = await Validator(sandbox).ValidateAsync(
            Request(tasks: $"- name: broken {ScriptedSandbox.BrokenMarker}\n  ansible.builtin.nonsense: {{}}"),
            repair: (request, _) =>
            {
                repairs++;
                request.FailedStage.ShouldBe(ValidationStage.Lint);
                // The error output must reach the model verbatim — that is the point of feeding it back.
                request.ErrorOutput.ShouldContain("couldn't resolve module");
                request.PreviousYaml.ShouldContain(ScriptedSandbox.BrokenMarker);
                return Task.FromResult<string?>("""
                    - name: "RHEL-08-010550 | PATCH | Root SSH logon"
                      ansible.builtin.lineinfile:
                        path: /etc/ssh/sshd_config
                        line: PermitRootLogin no
                    """);
            },
            cancellationToken: Ct);

        repairs.ShouldBe(1);
        attempts.Count.ShouldBe(2);
        attempts[0].Outcome.ShouldBe(ValidationOutcome.Failed);
        attempts[0].RepairAttempt.ShouldBe(0);
        attempts[1].Outcome.ShouldBe(ValidationOutcome.Passed);
        attempts[1].RepairAttempt.ShouldBe(1);
        // A fresh container per attempt: reusing one would let the first apply's changes make a non-idempotent
        // playbook look idempotent.
        sandbox.SessionsStarted.ShouldBe(2);
        sandbox.SessionsDisposed.ShouldBe(2);
    }

    /// <summary>The milestone's deliberately-broken case: fails, is repaired once, fails again, needs a human.</summary>
    [Fact]
    public async Task A_failure_that_survives_the_repair_lands_in_needs_human_review()
    {
        var sandbox = new ScriptedSandbox();
        var repairs = 0;
        var broken = $"- name: still broken {ScriptedSandbox.BrokenMarker}\n  ansible.builtin.nonsense: {{}}";

        var attempts = await Validator(sandbox).ValidateAsync(
            Request(tasks: broken),
            repair: (_, _) => { repairs++; return Task.FromResult<string?>(broken); },
            cancellationToken: Ct);

        repairs.ShouldBe(1);
        attempts.Count.ShouldBe(2);
        attempts[1].Outcome.ShouldBe(ValidationOutcome.NeedsHumanReview);
        attempts[1].Summary.ShouldContain("needs a human");
        attempts[1].FailedStage.ShouldBe(ValidationStage.Lint);
    }

    [Fact]
    public async Task A_model_that_returns_nothing_to_repair_with_needs_a_human()
    {
        var sandbox = new ScriptedSandbox();

        var attempts = await Validator(sandbox).ValidateAsync(
            Request(tasks: $"- name: broken {ScriptedSandbox.BrokenMarker}\n  x: {{}}"),
            repair: (_, _) => Task.FromResult<string?>(null),
            cancellationToken: Ct);

        attempts[^1].Outcome.ShouldBe(ValidationOutcome.NeedsHumanReview);
        attempts[^1].Summary.ShouldContain("no repaired playbook");
    }

    [Fact]
    public async Task Repair_can_be_disabled()
    {
        var options = new ValidationOptions { MaxRepairAttempts = 0 };
        var sandbox = new ScriptedSandbox { LintFails = true };

        var attempts = await Validator(sandbox, options).ValidateAsync(Request(), cancellationToken: Ct);

        attempts.Count.ShouldBe(1);
        attempts[0].Outcome.ShouldBe(ValidationOutcome.NeedsHumanReview);
        attempts[0].Summary.ShouldContain("No repair was attempted");
    }

    // --- Honest degradation ---

    /// <summary>
    /// Without a container runtime the loop must say so, not quietly report success. An unvalidated remediation
    /// presented as validated is the worst thing this tool could produce.
    /// </summary>
    [Fact]
    public async Task No_container_runtime_is_reported_as_skipped_not_passed()
    {
        var sandbox = new ScriptedSandbox { Available = false };

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        attempts[^1].Outcome.ShouldNotBe(ValidationOutcome.Passed);
        attempts[^1].Summary.ShouldContain("no container runtime is available");
        attempts[^1].Summary.ShouldContain("must not be treated as verified");
    }

    /// <summary>
    /// A rule that cannot be verified at all applied cleanly but proves nothing, so it does not pass. Saying "the
    /// playbook ran" while implying "the rule is fixed" is the failure this guards against.
    /// </summary>
    [Fact]
    public async Task A_rule_that_cannot_be_verified_does_not_pass()
    {
        var sandbox = new ScriptedSandbox { NoVerifierAvailable = true };

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        attempts[^1].Outcome.ShouldNotBe(ValidationOutcome.Passed);
        attempts[^1].FailedStage.ShouldBe(ValidationStage.Rescan);
    }

    [Fact]
    public async Task Evidence_serialises_to_json_for_storage()
    {
        var sandbox = new ScriptedSandbox();

        var attempts = await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);
        var json = attempts[^1].ToJson();

        json.ShouldContain("\"Outcome\": \"Passed\"");
        json.ShouldContain("Idempotency");
        json.ShouldContain("ScanStatusAfter");
        json.ShouldContain("CheckContent");
    }

    [Fact]
    public async Task A_vars_file_is_supplied_so_guarded_tasks_are_not_skipped()
    {
        var sandbox = new ScriptedSandbox();

        await Validator(sandbox).ValidateAsync(Request(), cancellationToken: Ct);

        sandbox.Commands.ShouldContain(c => c.Contains("-e @vars.yml"));
    }
}
