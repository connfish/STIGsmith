using System.Reflection;
using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;
using Stigsmith.Generation.Conventions;
using Stigsmith.Generation.Prompting;
using Stigsmith.Rules;
using Stigsmith.Tests.Support;
using Xunit;

namespace Stigsmith.Tests.Generation;

/// <summary>
/// Constraint 3, enforced by test: no host-identifying field reaches a language model.
/// </summary>
/// <remarks>
/// The structural half of the guarantee is that <see cref="RemediationRequest"/> takes a
/// <see cref="RuleContent"/>, which has no host fields on it, so there is no hostname or address in scope to
/// pass. This is the other half, and it is the one that survives a future refactor: prompts are assembled
/// from every finding in every fixture, and every host value from those checklists is searched for in the
/// result. The fixtures carry deliberately distinctive host values — `ALPHA-CANARY-STRING` and friends — for
/// exactly this purpose.
/// </remarks>
public class PromptHygieneTests(ITestOutputHelper output)
{
    private static string[] FixtureFiles() =>
        [.. Directory.EnumerateFiles(TestEnvironment.FixturePath(), "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".ckl") || f.EndsWith(".cklb") || f.EndsWith(".xml"))
            .OrderBy(f => f, StringComparer.Ordinal)];

    private static RoleIndex ExampleRole() => new AnsibleRoleIndexer().Index(new ConventionRoleOptions
    {
        Path = TestEnvironment.ExampleRolePath,
    });

    private static RemediationRequest Request(RuleContent rule, RoleIndex role)
    {
        var classification = RuleClassifier.Classify(rule);
        return new RemediationRequest
        {
            Rule = rule,
            TargetOs = "Red Hat Enterprise Linux 8",
            Examples = role.Retrieve(rule),
            Conventions = role.Conventions,
            RequireCheckMode = classification.IsHighRisk,
            RiskDomains = [.. classification.HighRiskDomains],
        };
    }

    /// <summary>
    /// The headline assertion. Every finding in every fixture, with a real convention role attached, and not
    /// one host value in any assembled prompt.
    /// </summary>
    [Fact]
    public void No_assembled_prompt_contains_any_host_identifying_value()
    {
        var role = ExampleRole();
        var promptsChecked = 0;
        var valuesChecked = 0;
        var leaks = new List<string>();

        foreach (var file in FixtureFiles())
        {
            var checklist = ChecklistIo.ReadFile(file);
            var hostValues = checklist.Host.IdentifyingValues().ToArray();
            valuesChecked += hostValues.Length;

            foreach (var finding in checklist.Findings)
            {
                var prompt = RemediationPromptAssembler.Assemble(Request(finding.Rule, role)).FullText;
                promptsChecked++;

                foreach (var value in hostValues)
                {
                    if (prompt.Contains(value, StringComparison.OrdinalIgnoreCase))
                        leaks.Add($"{Path.GetFileName(file)} / {finding.Rule.RuleVersion}: '{value}'");
                }
            }
        }

        output.WriteLine($"{promptsChecked} prompts assembled; {valuesChecked} host values searched for.");

        promptsChecked.ShouldBeGreaterThan(300, "the sweep must actually cover the fixtures");
        valuesChecked.ShouldBeGreaterThan(0, "the fixtures must have populated host fields to search for");
        leaks.ShouldBeEmpty("host-identifying values found in assembled prompts:\n" + string.Join("\n", leaks));
    }

    /// <summary>
    /// The canary check, stated separately so a failure names the problem directly. The fixture host comments
    /// contain strings that appear nowhere else in the repository, so any leak of the host record shows up
    /// here even if hostnames and addresses were somehow scrubbed.
    /// </summary>
    [Fact]
    public void No_prompt_contains_a_fixture_canary_string()
    {
        var role = ExampleRole();
        string[] canaries = ["CANARY-STRING", "ALPHA-CANARY", "BRAVO-CANARY", "CHARLIE-CANARY", "DELTA-CANARY"];

        foreach (var file in FixtureFiles())
        {
            foreach (var finding in ChecklistIo.ReadFile(file).Findings)
            {
                var prompt = RemediationPromptAssembler.Assemble(Request(finding.Rule, role)).FullText;
                foreach (var canary in canaries)
                    prompt.ShouldNotContain(canary, Case.Insensitive,
                        $"{Path.GetFileName(file)} / {finding.Rule.RuleVersion} leaked a canary");
            }
        }
    }

    /// <summary>
    /// The finding's own <c>FindingDetails</c> and <c>Comments</c> are scan output, frequently quoting
    /// hostnames and command results from the live system. They are not rule content and must not be sent,
    /// even though they are the most tempting extra context available.
    /// </summary>
    [Fact]
    public void Finding_details_and_comments_are_not_sent()
    {
        var checklist = ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"));
        var role = ExampleRole();

        foreach (var finding in checklist.Findings.Where(f => f.FindingDetails.Length > 20))
        {
            var prompt = RemediationPromptAssembler.Assemble(Request(finding.Rule, role)).FullText;

            prompt.ShouldNotContain(finding.FindingDetails);
            if (finding.Comments.Length > 10) prompt.ShouldNotContain(finding.Comments);
        }
    }

    /// <summary>
    /// The structural guarantee, asserted directly: nothing reachable from a <see cref="RemediationRequest"/>
    /// is a host field. This is what makes the test above hold for code that has not been written yet.
    /// </summary>
    [Fact]
    public void Nothing_on_the_request_type_can_carry_host_metadata()
    {
        var reachable = typeof(RemediationRequest)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.PropertyType)
            .ToArray();

        reachable.ShouldNotContain(typeof(HostMetadata));
        reachable.ShouldNotContain(typeof(Checklist));
        reachable.ShouldNotContain(typeof(Finding));

        // And the rule type it does carry has no host-shaped member.
        string[] forbidden = ["host", "ipaddress", "fqdn", "mac", "targetkey", "asset", "target"];
        typeof(RuleContent).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .ShouldNotContain(n => forbidden.Any(f => n.Contains(f, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// The prompt must still contain what constraint 3 permits, or the hygiene guarantee would be satisfied
    /// trivially by sending nothing useful.
    /// </summary>
    [Fact]
    public void The_prompt_does_contain_the_rule_content_the_model_needs()
    {
        var checklist = ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"));
        var rule = checklist.Findings.Single(f => f.Rule.RuleVersion == "RHEL-08-010550").Rule;

        var prompt = RemediationPromptAssembler.Assemble(Request(rule, ExampleRole()));

        prompt.User.ShouldContain("SV-230296r1130296_rule");
        prompt.User.ShouldContain("RHEL-08-010550");
        prompt.User.ShouldContain("CAT II");
        prompt.User.ShouldContain("direct logons to the root account");
        prompt.User.ShouldContain("PermitRootLogin no");
        prompt.User.ShouldContain("Red Hat Enterprise Linux 8");
        output.WriteLine(prompt.FullText);
    }
}
