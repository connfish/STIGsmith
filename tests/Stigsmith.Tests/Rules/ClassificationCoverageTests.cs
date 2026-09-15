using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;
using Stigsmith.Rules;
using Stigsmith.Tests.Support;
using Xunit;

namespace Stigsmith.Tests.Rules;

/// <summary>
/// Classification over the full synthetic RHEL 8 checklist, graded against the answer key authored with
/// the rule catalog, plus the coverage numbers the milestone asks for.
/// </summary>
public class ClassificationCoverageTests(ITestOutputHelper output)
{
    private static Checklist Checklist() =>
        ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"));

    [Fact]
    public void Reports_coverage_numbers_for_the_full_checklist()
    {
        var coverage = ClassificationCoverage.From(Checklist());

        output.WriteLine(coverage.Summary());
        foreach (var (domain, count) in coverage.ByDomain.OrderByDescending(kv => kv.Value))
            output.WriteLine($"  {domain.ToToken(),-16} {count,3}");

        coverage.Total.ShouldBe(72);
        (coverage.Automatable + coverage.Manual + coverage.NeedsReview).ShouldBe(coverage.Total);
        (coverage.OpenAutomatable + coverage.OpenManual + coverage.OpenNeedsReview).ShouldBe(coverage.OpenTotal);
        coverage.OpenTotal.ShouldBeLessThan(coverage.Total);

        // The numbers as measured. Pinned so a change in the heuristics is a visible, reviewable diff
        // rather than a silent drift in what the tool claims it can do.
        coverage.Automatable.ShouldBe(47);
        coverage.Manual.ShouldBe(9);
        coverage.NeedsReview.ShouldBe(16);
        coverage.AutomatableHighRisk.ShouldBe(22);
        coverage.Summary().ShouldContain("47 automatable, 9 manual, 16 needs-review");
    }

    [Fact]
    public void Agrees_with_the_answer_key_on_every_rule()
    {
        var expectations = ClassificationExpectations.Load().ByRuleId;

        var disagreements = Checklist().Findings
            .Select(f => (Expected: expectations[f.Rule.RuleId], Actual: RuleClassifier.Classify(f.Rule)))
            .Where(p => p.Actual.Automatability != p.Expected.Expected)
            .Select(p => $"{p.Expected.VulnId} {p.Expected.RuleVersion}: "
                       + $"expected {p.Expected.ExpectedAutomatability}, got {p.Actual.Automatability.ToToken()} "
                       + $"({p.Actual.Reason})")
            .ToArray();

        disagreements.ShouldBeEmpty(
            $"{disagreements.Length} rules disagree with the answer key:\n" + string.Join("\n", disagreements));
    }

    /// <summary>
    /// The dangerous direction. Classifying an automatable rule as needs-review costs an operator some
    /// time; classifying a policy rule as automatable sends a documentation requirement to a language
    /// model and produces confident nonsense for an ISSO to catch.
    /// </summary>
    [Fact]
    public void No_policy_rule_is_ever_classified_automatable()
    {
        var expectations = ClassificationExpectations.Load().ByRuleId;

        var wrong = Checklist().Findings
            .Where(f => expectations[f.Rule.RuleId].Expected == Automatability.Manual)
            .Select(f => (f, Classification: RuleClassifier.Classify(f.Rule)))
            .Where(p => p.Classification.Automatability == Automatability.Automatable)
            .Select(p => p.f.Rule.RuleVersion)
            .ToArray();

        wrong.ShouldBeEmpty($"policy rules classified automatable: {string.Join(", ", wrong)}");
    }

    /// <summary>
    /// High-risk recall must be total. A missed flag means a rule that can lock an operator out of the
    /// host gets generated without opt-in and applied without a check-mode path. Over-flagging costs one
    /// extra opt-in and is the direction to err in.
    /// </summary>
    [Fact]
    public void Every_high_risk_rule_is_flagged()
    {
        var expectations = ClassificationExpectations.Load().ByRuleId;

        var missed = Checklist().Findings
            .Select(f => (Expected: expectations[f.Rule.RuleId], Actual: RuleClassifier.Classify(f.Rule)))
            .Where(p => p.Expected.ExpectedHighRisk && !p.Actual.IsHighRisk)
            .Select(p => $"{p.Expected.VulnId} {p.Expected.RuleVersion} "
                       + $"(expected {string.Join('/', p.Expected.Domains)}, detected {p.Actual.DomainTokens})")
            .ToArray();

        missed.ShouldBeEmpty("high-risk rules not flagged:\n" + string.Join("\n", missed));
    }

    [Fact]
    public void High_risk_flagging_is_not_indiscriminate()
    {
        var expectations = ClassificationExpectations.Load().ByRuleId;
        var findings = Checklist().Findings.ToArray();

        var falsePositives = findings
            .Select(f => (Expected: expectations[f.Rule.RuleId], Actual: RuleClassifier.Classify(f.Rule)))
            .Count(p => !p.Expected.ExpectedHighRisk && p.Actual.IsHighRisk);

        output.WriteLine($"high-risk false positives: {falsePositives} of {findings.Length}");

        // A flag that fires on everything is a flag nobody reads. Held at zero on this fixture; the
        // assertion allows a small margin so a new rule shape does not fail the build for being
        // conservative in the safe direction.
        falsePositives.ShouldBeLessThanOrEqualTo(3);
    }

    [Fact]
    public void Classification_is_deterministic()
    {
        var rules = Checklist().Findings.Select(f => f.Rule).ToArray();

        var first = RuleClassifier.ClassifyAll(rules);
        var second = RuleClassifier.ClassifyAll(rules);

        first.Select(c => (c.RuleId, c.Automatability, c.DomainTokens))
            .ShouldBe(second.Select(c => (c.RuleId, c.Automatability, c.DomainTokens)));
    }

    [Fact]
    public void Coverage_runs_over_every_fixture_without_throwing()
    {
        var files = Directory.EnumerateFiles(TestEnvironment.FixturePath(), "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".ckl") || f.EndsWith(".cklb") || f.EndsWith(".xml"))
            .ToArray();

        files.ShouldNotBeEmpty();
        foreach (var file in files)
        {
            var coverage = ClassificationCoverage.From(ChecklistIo.ReadFile(file));
            output.WriteLine($"{Path.GetFileName(file),-34} {coverage.Summary()}");
            coverage.Total.ShouldBeGreaterThan(0);
        }
    }

    /// <summary>
    /// A results-only XCCDF import has no fixtext, so nothing is automatable. The classifier must say
    /// that rather than guess, because "import the benchmark too" is the actionable answer.
    /// </summary>
    [Fact]
    public void Rules_imported_without_fix_text_are_not_claimed_automatable()
    {
        const string xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="tr1">
          <title>Results only</title>
          <target>host-echo.example.test</target>
          <rule-result idref="xccdf_mil.disa.stig_rule_SV-230296r1_rule" severity="medium">
            <result>fail</result>
          </rule-result>
        </TestResult>
        """;

        var coverage = ClassificationCoverage.From(ChecklistIo.Read(xml));

        coverage.Automatable.ShouldBe(0);
        coverage.NeedsReview.ShouldBe(1);
    }
}
