using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;
using Stigsmith.Generation.Conventions;
using Stigsmith.Tests.Support;
using Xunit;

namespace Stigsmith.Tests.Generation;

/// <summary>
/// Relevance tests for convention retrieval against the synthetic example role.
/// </summary>
/// <remarks>
/// The known pairs below are chosen so the answer does not depend on the ranking function's details. Each
/// query is a rule the example role does <em>not</em> implement, paired with the family of tasks a person
/// would reach for when writing it — an sshd rule should retrieve the role's sshd tasks, a sysctl rule its
/// sysctl tasks. That is what makes generated output match house conventions rather than being generic,
/// so it is asserted rather than eyeballed.
/// </remarks>
public class ConventionRetrievalTests(ITestOutputHelper output)
{
    private static readonly RoleIndex Index = new AnsibleRoleIndexer().Index(new ConventionRoleOptions
    {
        Path = TestEnvironment.ExampleRolePath,
    });

    private static readonly Lazy<Dictionary<string, RuleContent>> RulesByVersion = new(() =>
        ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"))
            .Findings
            .ToDictionary(f => f.Rule.RuleVersion, f => f.Rule, StringComparer.OrdinalIgnoreCase));

    private static RuleContent Rule(string version) => RulesByVersion.Value[version];

    private static string[] RetrievedVersions(RuleContent rule, int count = 3) =>
        [.. Index.Retrieve(rule, count).SelectMany(r => r.Task.StigVersionIds)];

    /// <summary>
    /// A rule the role already implements retrieves that implementation first, whatever the lexical score
    /// says. If the role has already solved this rule, that solution is the answer and the model's job is
    /// to match it rather than invent something.
    /// </summary>
    [Fact]
    public void A_rule_the_role_already_implements_returns_that_task_first()
    {
        var results = Index.Retrieve(Rule("RHEL-08-010550"));

        results.ShouldNotBeEmpty();
        results[0].Kind.ShouldBe(MatchKind.SameRule);
        results[0].Task.StigVersionIds.ShouldContain("RHEL-08-010550");
        results[0].Reason.ShouldContain("already implements");
    }

    [Fact]
    public void Same_rule_matching_works_across_id_spellings()
    {
        // Same rule, addressed only by its V-number rather than its version id.
        var byVulnOnly = new RuleContent
        {
            RuleId = "SV-230296r1130296_rule",
            GroupId = "V-230296",
            Title = "Root logon over SSH",
            FixText = "Set PermitRootLogin no.",
        };

        Index.Retrieve(byVulnOnly)[0].Kind.ShouldBe(MatchKind.SameRule);
    }

    /// <summary>
    /// The core relevance claim, on rules the role does not implement. Each expectation is a family
    /// judgement, not a ranking detail: the neighbours must come from the same subsystem.
    /// </summary>
    [Theory]
    // An SSH rule the role has no task for -> the role's sshd tasks.
    [InlineData("RHEL-08-010290", new[] { "RHEL-08-010550", "RHEL-08-010500", "RHEL-08-010200" })]
    // A sysctl network rule -> the role's sysctl tasks.
    [InlineData("RHEL-08-040209", new[] { "RHEL-08-040286", "RHEL-08-010372" })]
    // Removing a package -> the role's package tasks.
    [InlineData("RHEL-08-040001", new[] { "RHEL-08-040000", "RHEL-08-040100", "RHEL-08-010171" })]
    // A pwquality setting -> the role's pwquality/faillock tasks.
    [InlineData("RHEL-08-020170", new[] { "RHEL-08-020300", "RHEL-08-020010" })]
    // An audit rule -> the role's audit tasks.
    [InlineData("RHEL-08-030310", new[] { "RHEL-08-030170", "RHEL-08-030620" })]
    public void Retrieves_neighbours_from_the_same_subsystem(string queryVersion, string[] expectedFamily)
    {
        var rule = Rule(queryVersion);
        var retrieved = Index.Retrieve(rule);

        output.WriteLine($"{queryVersion}  {rule.Title}");
        foreach (var result in retrieved)
            output.WriteLine($"  {result.Score,8:F3}  {result.Task.Reference,-20} {result.Task.Name}");

        retrieved.ShouldNotBeEmpty();
        // Not the exact ordering -- that would be testing BM25's tie-breaks. At least one neighbour must
        // come from the right family, and the top hit must be one of them.
        var versions = retrieved.SelectMany(r => r.Task.StigVersionIds).ToArray();
        versions.ShouldContain(v => expectedFamily.Contains(v));
        retrieved[0].Task.StigVersionIds.ShouldContain(v => expectedFamily.Contains(v),
            $"top hit for {queryVersion} was {retrieved[0].Task.Reference} ({retrieved[0].Task.Name})");
    }

    /// <summary>
    /// The negative half of relevance: a retriever that returned the same three tasks for every rule would
    /// pass the positive cases above by accident, so the result sets have to differ and the best hit has to
    /// come from the right subsystem each time.
    /// </summary>
    /// <remarks>
    /// Asserted on the top hit and on set difference, deliberately not on every position. On a 21-task role
    /// the second and third neighbours do drift into other subsystems — an SSH rule's third hit is a
    /// package task — because after the one or two genuinely related tasks there is nothing else close, and
    /// BM25 then ranks on incidental shared vocabulary (`/etc/`, `root`, `mode`). That is the known
    /// limitation of lexical retrieval and the thing embeddings would improve; pretending otherwise in a
    /// test would just mean tuning constants until this fixture passed. See DECISIONS.md.
    /// </remarks>
    [Fact]
    public void Retrieval_discriminates_between_subsystems()
    {
        var ssh = RetrievedVersions(Rule("RHEL-08-010290"));
        var packages = RetrievedVersions(Rule("RHEL-08-040001"));
        var sysctl = RetrievedVersions(Rule("RHEL-08-040209"));

        // Best hit is from the right family in each case.
        ssh[0].ShouldBe("RHEL-08-010550");
        packages[0].ShouldBe("RHEL-08-040000");
        sysctl[0].ShouldBe("RHEL-08-040286");

        // And the three result sets are genuinely different rather than one fixed list.
        ssh.ShouldNotBe(packages);
        ssh.ShouldNotBe(sysctl);
        packages.ShouldNotBe(sysctl);
        ssh.Intersect(sysctl).ShouldBeEmpty();
    }

    [Fact]
    public void Retrieval_prefers_the_module_the_fix_implies()
    {
        // A fix that sets a kernel parameter should surface the role's sysctl tasks, not its lineinfile ones.
        var top = Index.Retrieve(Rule("RHEL-08-040209"))[0];

        top.Task.Module.ShouldBe("ansible.posix.sysctl");
    }

    [Fact]
    public void Retrieval_respects_the_requested_count()
    {
        Index.Retrieve(Rule("RHEL-08-010290"), count: 1).Count.ShouldBe(1);
        Index.Retrieve(Rule("RHEL-08-010290"), count: 5).Count.ShouldBe(5);
        Index.Retrieve(Rule("RHEL-08-010290"), count: 0).ShouldBeEmpty();
    }

    [Fact]
    public void Retrieval_never_returns_the_same_task_twice()
    {
        var results = Index.Retrieve(Rule("RHEL-08-010550"), count: 8);

        results.Select(r => r.Task.Reference).Distinct().Count().ShouldBe(results.Count);
    }

    [Fact]
    public void Retrieval_is_deterministic()
    {
        var rule = Rule("RHEL-08-010290");

        var first = Index.Retrieve(rule, 5).Select(r => r.Task.Reference).ToArray();
        var second = Index.Retrieve(rule, 5).Select(r => r.Task.Reference).ToArray();

        second.ShouldBe(first);
    }

    [Fact]
    public void An_unavailable_index_retrieves_nothing_rather_than_throwing()
    {
        var empty = RoleIndex.Empty("no role configured");

        empty.Retrieve(Rule("RHEL-08-010550")).ShouldBeEmpty();
        empty.IsEmpty.ShouldBeTrue();
    }

    /// <summary>
    /// Scores are reported so a bad retrieval can be diagnosed rather than guessed at, and so the
    /// relevance claims above can be reviewed by reading the output.
    /// </summary>
    [Fact]
    public void Reports_the_full_ranking_for_every_automatable_open_finding()
    {
        var checklist = ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl"));

        var withNeighbours = 0;
        foreach (var finding in checklist.Findings.Where(f => f.Status == FindingStatus.Open))
        {
            var retrieved = Index.Retrieve(finding.Rule);
            if (retrieved.Count > 0) withNeighbours++;

            output.WriteLine($"{finding.Rule.RuleVersion,-18} -> "
                + string.Join(", ", retrieved.Select(r =>
                    $"{r.Task.Reference}({(double.IsInfinity(r.Score) ? "same-rule" : r.Score.ToString("F1"))})")));
        }

        // Every open finding gets at least one neighbour from a 21-task role. That is expected at this
        // corpus size, and is pinned so a scoring change that starts returning nothing is visible.
        withNeighbours.ShouldBe(checklist.Findings.Count(f => f.Status == FindingStatus.Open));
    }
}
