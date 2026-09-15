using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;
using Stigsmith.Generation.Conventions;
using Stigsmith.Generation.Prompting;
using Stigsmith.Generation.Providers;
using Stigsmith.Rules;
using Stigsmith.Tests.Support;
using Xunit;

namespace Stigsmith.Tests.Generation;

/// <summary>
/// M5's acceptance criterion, minus the database: generate for a batch of automatable rules and check that what
/// comes out is syntactically valid YAML.
/// </summary>
/// <remarks>
/// The model is scripted (see <see cref="ScriptedRemediationProvider"/>), so this proves the pipeline handles
/// realistic model output — bare YAML, fenced YAML, YAML buried in prose, and a "cannot automate" answer — and
/// that nothing in prompt assembly or extraction falls over on real rule text. It proves nothing about the
/// quality of a real model's Ansible; that needs a real model, and this machine has none.
/// </remarks>
public class BatchGenerationTests(ITestOutputHelper output)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static RoleIndex Role() => new AnsibleRoleIndexer().Index(new ConventionRoleOptions
    {
        Path = TestEnvironment.ExampleRolePath,
    });

    private static (RuleContent Rule, RuleClassification Classification)[] AutomatableOpenRules()
    {
        var checklist = ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"));
        return [.. checklist.Findings
            .Where(f => f.Status == FindingStatus.Open)
            .Select(f => (f.Rule, Classification: RuleClassifier.Classify(f.Rule)))
            .Where(p => p.Classification.Automatability == Automatability.Automatable)];
    }

    [Fact]
    public async Task Generating_for_a_batch_of_automatable_rules_produces_valid_yaml()
    {
        var role = Role();
        var provider = new ScriptedRemediationProvider();
        var batch = AutomatableOpenRules();

        var tasks = 0;
        var cannotAutomate = 0;
        var invalid = new List<string>();

        foreach (var (rule, classification) in batch)
        {
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
            await foreach (var chunk in provider.StreamAsync(prompt, new GenerationParameters(), Ct))
                response.Append(chunk.Text);

            var extracted = AnsibleYamlExtractor.Extract(response.ToString());
            switch (extracted.Kind)
            {
                case GeneratedYamlKind.Tasks:
                    tasks++;
                    extracted.Yaml.ShouldNotBeNullOrWhiteSpace();
                    extracted.TaskNames.ShouldNotBeEmpty();
                    // Re-parsing the extracted YAML is the actual "syntactically valid" claim.
                    AnsibleYamlExtractor.Extract(extracted.Yaml).Kind.ShouldBe(GeneratedYamlKind.Tasks);
                    break;
                case GeneratedYamlKind.CannotAutomate:
                    cannotAutomate++;
                    extracted.Message.ShouldNotBeNullOrWhiteSpace();
                    break;
                default:
                    invalid.Add($"{rule.RuleVersion}: {extracted.Message}");
                    break;
            }
        }

        output.WriteLine($"{batch.Length} automatable open rules: {tasks} produced tasks, "
            + $"{cannotAutomate} reported cannot-automate, {invalid.Count} invalid.");

        batch.Length.ShouldBeGreaterThanOrEqualTo(20, "the batch must be large enough to be meaningful");
        invalid.ShouldBeEmpty("responses that did not yield valid YAML:\n" + string.Join("\n", invalid));
        tasks.ShouldBeGreaterThan(0);
        // The scripted provider returns a cannot-automate answer for rules whose number is 3 mod 4, so this also
        // confirms that answer is recognised rather than counted as a failure.
        cannotAutomate.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task Every_prompt_in_the_batch_carries_the_rule_and_the_conventions()
    {
        var role = Role();
        var provider = new ScriptedRemediationProvider();

        foreach (var (rule, classification) in AutomatableOpenRules().Take(10))
        {
            var prompt = RemediationPromptAssembler.Assemble(new RemediationRequest
            {
                Rule = rule,
                TargetOs = "Red Hat Enterprise Linux 8",
                Examples = role.Retrieve(rule),
                Conventions = role.Conventions,
                RequireCheckMode = classification.IsHighRisk,
                RiskDomains = [.. classification.HighRiskDomains],
            });

            await foreach (var _ in provider.StreamAsync(prompt, new GenerationParameters(), Ct)) { }

            prompt.User.ShouldContain(rule.RuleId);
            prompt.User.ShouldContain(rule.RuleVersion);
            prompt.User.ShouldContain("stigsmith_rhel8_");
            prompt.System.ShouldContain("translation task, not a design task");

            if (classification.IsHighRisk)
                prompt.User.ShouldContain("--check", Case.Insensitive);
        }

        provider.Prompts.Count.ShouldBe(10);
    }

    /// <summary>
    /// Every generated prompt has a distinct hash, and the same rule hashes the same way twice. Both matter for
    /// the audit trail: the first means a stored hash identifies one rule's prompt, the second means a
    /// reproduced run is recognisable as the same input.
    /// </summary>
    [Fact]
    public void Prompt_hashes_are_stable_and_distinct()
    {
        var role = Role();
        var batch = AutomatableOpenRules().Take(25).ToArray();

        RemediationPrompt Assemble(RuleContent rule) => RemediationPromptAssembler.Assemble(new RemediationRequest
        {
            Rule = rule,
            TargetOs = "Red Hat Enterprise Linux 8",
            Examples = role.Retrieve(rule),
            Conventions = role.Conventions,
        });

        var hashes = batch.Select(p => Assemble(p.Rule).Sha256Hex).ToArray();

        hashes.Distinct().Count().ShouldBe(batch.Length);
        Assemble(batch[0].Rule).Sha256Hex.ShouldBe(hashes[0]);
        hashes.ShouldAllBe(h => h.Length == 64);
    }

    [Fact]
    public async Task A_high_risk_rule_is_told_to_support_check_mode()
    {
        var role = Role();
        var rule = ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"))
            .Findings.Single(f => f.Rule.RuleVersion == "RHEL-08-010550").Rule;
        var classification = RuleClassifier.Classify(rule);

        classification.IsHighRisk.ShouldBeTrue();

        var prompt = RemediationPromptAssembler.Assemble(new RemediationRequest
        {
            Rule = rule,
            TargetOs = "Red Hat Enterprise Linux 8",
            Examples = role.Retrieve(rule),
            Conventions = role.Conventions,
            RequireCheckMode = true,
            RiskDomains = [.. classification.HighRiskDomains],
        });

        prompt.User.ShouldContain("high-risk (sshd)");
        prompt.User.ShouldContain("ansible-playbook --check");

        var provider = new ScriptedRemediationProvider();
        var response = new System.Text.StringBuilder();
        await foreach (var chunk in provider.StreamAsync(prompt, new GenerationParameters(), Ct))
            response.Append(chunk.Text);

        AnsibleYamlExtractor.Extract(response.ToString()).Kind.ShouldNotBe(GeneratedYamlKind.Invalid);
    }

    [Fact]
    public void A_rule_with_no_convention_role_still_gets_a_usable_prompt()
    {
        var rule = ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"))
            .Findings.First(f => f.Rule.FixText.Length > 0).Rule;

        var prompt = RemediationPromptAssembler.Assemble(new RemediationRequest
        {
            Rule = rule,
            TargetOs = "Red Hat Enterprise Linux 8",
        });

        prompt.User.ShouldContain("No convention role is configured", Case.Insensitive);
        prompt.User.ShouldContain(rule.FixText.Split('\n')[0]);
        prompt.User.ShouldNotContain("House conventions");
    }
}
