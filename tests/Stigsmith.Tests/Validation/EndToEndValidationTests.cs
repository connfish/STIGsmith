using Microsoft.Extensions.Logging.Abstractions;
using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;
using Stigsmith.Generation.Conventions;
using Stigsmith.Generation.Prompting;
using Stigsmith.Generation.Providers;
using Stigsmith.Rules;
using Stigsmith.Tests.Support;
using Stigsmith.Validation;
using Xunit;

namespace Stigsmith.Tests.Validation;

/// <summary>
/// M6's acceptance criterion: an end-to-end run over at least ten synthetic automatable rules produces a pass/fail
/// report with evidence, and at least one deliberately-broken rule lands in needs-human-review.
/// </summary>
/// <remarks>
/// Runs the real pipeline — classify, retrieve conventions, assemble prompt, generate, extract YAML, validate — with
/// two things scripted: the model (<see cref="ScriptedRemediationProvider"/>) and the container
/// (<see cref="ScriptedSandbox"/>). Everything between them is the production code path.
/// <para>
/// What this does <b>not</b> show is that a real playbook applies in a real container. That needs Docker, which this
/// machine does not have. <see cref="DockerSandboxTests"/> covers it and skips here.
/// </para>
/// </remarks>
public class EndToEndValidationTests(ITestOutputHelper output)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static RoleIndex Role() => new AnsibleRoleIndexer().Index(new ConventionRoleOptions
    {
        Path = TestEnvironment.ExampleRolePath,
    });

    [Fact]
    public async Task An_end_to_end_run_over_a_batch_produces_a_pass_fail_report_with_evidence()
    {
        var role = Role();
        var model = new ScriptedRemediationProvider();
        var sandbox = new ScriptedSandbox();
        var options = new ValidationOptions();
        var validator = new RemediationValidator(
            sandbox, new ComplianceVerifier(options), options, NullLogger<RemediationValidator>.Instance);

        var rules = ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"))
            .Findings
            .Where(f => f.Status == FindingStatus.Open)
            .Select(f => (f.Rule, Classification: RuleClassifier.Classify(f.Rule)))
            .Where(p => p.Classification.Automatability == Automatability.Automatable)
            .Take(18)
            .ToArray();

        var results = new List<(string, string, IReadOnlyList<ValidationEvidence>)>();
        var evidenceBundles = new List<ValidationEvidence>();

        foreach (var (rule, classification) in rules)
        {
            // Generate, for real, through the production prompt and extraction path.
            var prompt = RemediationPromptAssembler.Assemble(new RemediationRequest
            {
                Rule = rule,
                TargetOs = "Red Hat Enterprise Linux 8",
                Examples = role.Retrieve(rule),
                Conventions = role.Conventions,
                RequireCheckMode = classification.IsHighRisk,
                RiskDomains = [.. classification.HighRiskDomains],
            });

            var response = new System.Text.StringBuilder();
            await foreach (var chunk in model.StreamAsync(prompt, new GenerationParameters(), Ct))
                response.Append(chunk.Text);

            var generated = AnsibleYamlExtractor.Extract(response.ToString());
            if (!generated.IsUsable)
            {
                // A cannot-automate answer is not sent to validation: there is nothing to validate.
                output.WriteLine($"{rule.RuleVersion,-18} not validated: {generated.Kind} — {generated.Message}");
                continue;
            }

            var attempts = await validator.ValidateAsync(
                new ValidationRequest
                {
                    Rule = rule,
                    TasksYaml = generated.Yaml,
                    ReferencedVariables = [$"stigsmith_rhel8_rule_{rule.NumericId}"],
                    RequireCheckMode = classification.IsHighRisk,
                },
                repair: (_, _) => Task.FromResult<string?>(generated.Yaml),
                cancellationToken: Ct);

            results.Add((rule.RuleId, rule.RuleVersion, attempts));
            evidenceBundles.Add(attempts[^1]);
        }

        var report = ValidationReport.From(results);

        output.WriteLine("");
        output.WriteLine(report.Summary());
        output.WriteLine("");
        foreach (var row in report.Rows)
            output.WriteLine($"{row.RuleVersion,-18} {row.Outcome,-18} "
                + $"{row.ScanStatusBefore}->{row.ScanStatusAfter,-6} "
                + $"changed={row.IdempotencyChangedCount} attempts={row.Attempts}");

        report.Total.ShouldBeGreaterThanOrEqualTo(10, "the milestone asks for at least ten rules");
        report.Passed.ShouldBe(report.Total, "every rule with valid generated YAML should validate in this world");
        report.Summary().ShouldContain("passed");

        // Every pass carries the full evidence bundle, which is the artifact that makes it acceptable.
        foreach (var evidence in evidenceBundles)
        {
            evidence.Stage(ValidationStage.Lint)!.Output.ShouldNotBeNullOrWhiteSpace();
            evidence.Stage(ValidationStage.SyntaxCheck).ShouldNotBeNull();
            evidence.Stage(ValidationStage.Apply).ShouldNotBeNull();
            evidence.Stage(ValidationStage.Idempotency).ShouldNotBeNull();
            evidence.ScanStatusBefore.ShouldBe("fail");
            evidence.ScanStatusAfter.ShouldBe("pass");
            evidence.IdempotencyChangedCount.ShouldBe(0);
            evidence.Playbook.ShouldContain("hosts: localhost");
            evidence.ContainerImage.ShouldNotBeNullOrWhiteSpace();
            evidence.ToJson().ShouldContain("ScanStatusAfter");
        }
    }

    /// <summary>
    /// The deliberately-broken rule. Its remediation fails lint, the repair returns the same broken YAML, and it must
    /// land in needs-human-review rather than being retried forever or quietly recorded as failed with no owner.
    /// </summary>
    [Fact]
    public async Task A_deliberately_broken_rule_lands_in_needs_human_review()
    {
        var options = new ValidationOptions();
        var sandbox = new ScriptedSandbox();
        var validator = new RemediationValidator(
            sandbox, new ComplianceVerifier(options), options, NullLogger<RemediationValidator>.Instance);

        var rule = ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"))
            .Findings.Single(f => f.Rule.RuleVersion == "RHEL-08-040000").Rule;

        var broken = $"""
            - name: "RHEL-08-040000 | PATCH | deliberately broken {ScriptedSandbox.BrokenMarker}"
              ansible.builtin.no_such_module:
                name: telnet-server
                state: absent
            """;

        var attempts = await validator.ValidateAsync(
            new ValidationRequest { Rule = rule, TasksYaml = broken },
            repair: (_, _) => Task.FromResult<string?>(broken),
            cancellationToken: Ct);

        var report = ValidationReport.From([(rule.RuleId, rule.RuleVersion, attempts)]);
        output.WriteLine(report.Summary());
        output.WriteLine(attempts[^1].Summary);

        report.NeedsHumanReview.ShouldBe(1);
        report.Passed.ShouldBe(0);
        report.Rows[0].FailedStage.ShouldBe(ValidationStage.Lint);
        report.Rows[0].Attempts.ShouldBe(2);

        // The evidence has to say what went wrong, or a human has nothing to work from.
        attempts[^1].Stage(ValidationStage.Lint)!.Output.ShouldContain("couldn't resolve module");
        attempts[^1].Summary.ShouldContain("needs a human");
    }

    [Fact]
    public void A_report_reports_each_outcome_separately_rather_than_a_percentage()
    {
        var report = ValidationReport.From(
        [
            ("SV-1_rule", "TEST-00-000001", [Evidence(ValidationOutcome.Passed)]),
            ("SV-2_rule", "TEST-00-000002", [Evidence(ValidationOutcome.Passed), Evidence(ValidationOutcome.Passed)]),
            ("SV-3_rule", "TEST-00-000003", [Evidence(ValidationOutcome.NeedsHumanReview)]),
            ("SV-4_rule", "TEST-00-000004", [Evidence(ValidationOutcome.Skipped)]),
        ]);

        report.Total.ShouldBe(4);
        report.Passed.ShouldBe(2);
        report.PassedAfterRepair.ShouldBe(1);
        report.NeedsHumanReview.ShouldBe(1);
        report.Skipped.ShouldBe(1);
        report.Summary().ShouldContain("2 passed, 1 need human review");
        report.Summary().ShouldContain("1 passed only after one repair");
    }

    private static ValidationEvidence Evidence(ValidationOutcome outcome) => new()
    {
        Outcome = outcome,
        ContainerImage = "test",
        Summary = outcome.ToString(),
    };
}
