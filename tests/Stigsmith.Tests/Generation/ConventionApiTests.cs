using System.Net;
using System.Net.Http.Json;
using Stigsmith.Api.Endpoints;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests.Generation;

/// <summary>
/// The convention endpoints against a running API. Skipped where no container runtime exists.
/// </summary>
public class ConventionApiTests(ApiFixture api) : IClassFixture<ApiFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Reports_the_indexed_role_and_its_conventions()
    {
        ApiFixture.SkipIfUnavailable();

        var report = await api.Client.GetFromJsonAsync<ConventionReport>("/api/conventions", Ct);

        report.ShouldNotBeNull();
        report.UnavailableReason.ShouldBeNull();
        report.TaskCount.ShouldBe(21);
        report.VariablePrefix.ShouldBe("stigsmith_rhel8_");
        report.RuleToggleTemplate.ShouldBe("stigsmith_rhel8_rule_<vuln number>");
        report.UsesFullyQualifiedModules.ShouldBeTrue();
        report.HandlerNames.ShouldContain("restart sshd");
        report.SkippedFiles.ShouldBeEmpty();
        report.Description.ShouldContain("Do not invent a handler name");
    }

    /// <summary>
    /// Shows an operator exactly which existing tasks the model will imitate for a given finding, before
    /// they trust anything generated from them.
    /// </summary>
    [Fact]
    public async Task Returns_the_few_shot_examples_for_a_finding()
    {
        ApiFixture.SkipIfUnavailable();

        var imported = await api.ImportFixture("ckl", "rhel8-host-alpha.ckl");
        var result = (await imported.Content.ReadFromJsonAsync<ImportResult>(Ct))!;
        var detail = await api.Client.GetFromJsonAsync<ChecklistDetail>($"/api/checklists/{result.Id}", Ct);

        // RHEL-08-010290 (SSH MACs) is not implemented by the example role, so this exercises similarity
        // retrieval rather than the same-rule shortcut.
        var finding = detail!.Findings.Single(f => f.RuleVersion == "RHEL-08-010290");

        var examples = await api.Client.GetFromJsonAsync<ExamplesResponse>(
            $"/api/conventions/examples/{finding.Id}", Ct);

        examples.ShouldNotBeNull();
        examples.RuleVersion.ShouldBe("RHEL-08-010290");
        examples.Examples.Count.ShouldBe(3);
        examples.Examples[0].Reference.ShouldBe("tasks/cat2.yml:31");
        examples.Examples[0].MatchKind.ShouldBe("Similar");
        examples.Examples[0].Yaml.ShouldContain("ansible.builtin.lineinfile");
        examples.ConventionDescription.ShouldContain("stigsmith_rhel8_");
    }

    [Fact]
    public async Task A_rule_the_role_implements_returns_it_as_a_same_rule_example()
    {
        ApiFixture.SkipIfUnavailable();

        var imported = await api.ImportFixture("cklb", "rhel8-host-bravo.cklb");
        var result = (await imported.Content.ReadFromJsonAsync<ImportResult>(Ct))!;
        var detail = await api.Client.GetFromJsonAsync<ChecklistDetail>($"/api/checklists/{result.Id}", Ct);
        var finding = detail!.Findings.Single(f => f.RuleVersion == "RHEL-08-010550");

        var examples = await api.Client.GetFromJsonAsync<ExamplesResponse>(
            $"/api/conventions/examples/{finding.Id}?count=1", Ct);

        examples!.Examples.Count.ShouldBe(1);
        examples.Examples[0].MatchKind.ShouldBe("SameRule");
        examples.Examples[0].Score.ShouldBeNull();
        examples.Examples[0].Yaml.ShouldContain("PermitRootLogin no");
    }

    [Fact]
    public async Task Returns_404_for_an_unknown_finding()
    {
        ApiFixture.SkipIfUnavailable();

        var response = await api.Client.GetAsync($"/api/conventions/examples/{Guid.CreateVersion7()}", Ct);

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }
}
