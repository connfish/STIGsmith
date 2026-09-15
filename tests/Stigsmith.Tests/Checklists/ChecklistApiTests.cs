using System.Net;
using System.Net.Http.Json;
using Stigsmith.Api.Endpoints;
using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests.Checklists;

/// <summary>
/// Import and export through the real endpoints against real PostgreSQL. Skipped where no container
/// runtime exists; see <see cref="ApiFixture"/>.
/// </summary>
public class ChecklistApiTests(ApiFixture api) : IClassFixture<ApiFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Imports_a_ckl_and_reports_status_counts()
    {
        ApiFixture.SkipIfUnavailable();

        var response = await api.ImportFixture("ckl", "rhel8-host-alpha.ckl");

        response.StatusCode.ShouldBe(HttpStatusCode.Created);
        var result = await response.Content.ReadFromJsonAsync<ImportResult>(Ct);
        result.ShouldNotBeNull();
        result.SourceFormat.ShouldBe(ChecklistFormat.Ckl);
        result.HostName.ShouldBe("host-alpha.example.test");
        result.StigId.ShouldBe("RHEL_8_STIG");
        result.FindingCount.ShouldBe(72);
        result.Open.ShouldBeGreaterThan(30);
        (result.Open + result.NotAFinding + result.NotApplicable + result.NotReviewed).ShouldBe(72);
    }

    [Fact]
    public async Task Imports_a_cklb_an_xccdf_and_an_arf()
    {
        ApiFixture.SkipIfUnavailable();

        var cklb = await api.ImportFixture("cklb", "rhel8-host-bravo.cklb");
        var xccdf = await api.ImportFixture("xccdf", "rhel8-host-charlie-xccdf.xml");
        var arf = await api.ImportFixture("xccdf", "rhel8-host-delta-arf.xml");

        (await cklb.Content.ReadFromJsonAsync<ImportResult>(Ct))!.SourceFormat.ShouldBe(ChecklistFormat.Cklb);
        (await xccdf.Content.ReadFromJsonAsync<ImportResult>(Ct))!.SourceFormat.ShouldBe(ChecklistFormat.Xccdf);
        (await arf.Content.ReadFromJsonAsync<ImportResult>(Ct))!.SourceFormat.ShouldBe(ChecklistFormat.Arf);
    }

    [Fact]
    public async Task Imports_a_multi_host_set_as_separate_checklists()
    {
        ApiFixture.SkipIfUnavailable();

        foreach (var file in Directory.GetFiles(TestEnvironment.FixturePath("multihost")).OrderBy(f => f))
            (await api.ImportFixture("multihost", Path.GetFileName(file))).StatusCode.ShouldBe(HttpStatusCode.Created);

        var list = await api.Client.GetFromJsonAsync<List<ChecklistSummary>>("/api/checklists", Ct);

        list.ShouldNotBeNull();
        var hosts = list.Select(c => c.HostName).ToHashSet();
        hosts.ShouldContain("host-alpha.example.test");
        hosts.ShouldContain("host-charlie.example.test");
        hosts.ShouldContain("host-delta.example.test");
    }

    [Fact]
    public async Task Rejects_a_file_that_is_not_a_checklist()
    {
        ApiFixture.SkipIfUnavailable();

        using var content = new MultipartFormDataContent
        {
            { new StringContent("hostname,status\nfoo,open\n"), "file", "scan.csv" },
        };

        var response = await api.Client.PostAsync("/api/checklists/import", content, Ct);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(Ct)).ShouldContain("Could not identify the file");
    }

    /// <summary>
    /// Import, export, and the exported bytes must be the imported bytes. This is the claim the README
    /// makes about not trapping an operator's data, tested through the endpoints an operator uses.
    /// </summary>
    [Fact]
    public async Task Export_returns_the_imported_document_unchanged()
    {
        ApiFixture.SkipIfUnavailable();

        var imported = await api.ImportFixture("ckl", "edge-cases.ckl");
        var result = (await imported.Content.ReadFromJsonAsync<ImportResult>(Ct))!;

        var exported = await api.Client.GetAsync($"/api/checklists/{result.Id}/export", Ct);

        exported.StatusCode.ShouldBe(HttpStatusCode.OK);
        var body = await exported.Content.ReadAsStringAsync(Ct);
        body.ShouldBe(TestEnvironment.ReadFixture("ckl", "edge-cases.ckl"));
        exported.Content.Headers.ContentDisposition!.FileName.ShouldNotBeNull().ShouldContain("edge-cases");
    }

    [Fact]
    public async Task Exports_a_ckl_as_cklb_on_request()
    {
        ApiFixture.SkipIfUnavailable();

        var imported = await api.ImportFixture("ckl", "edge-cases.ckl");
        var result = (await imported.Content.ReadFromJsonAsync<ImportResult>(Ct))!;

        var exported = await api.Client.GetAsync($"/api/checklists/{result.Id}/export?format=Cklb", Ct);

        exported.StatusCode.ShouldBe(HttpStatusCode.OK);
        exported.Content.Headers.ContentType!.MediaType.ShouldBe("application/json");
        var reread = ChecklistIo.Read(await exported.Content.ReadAsStringAsync(Ct));
        reread.SourceFormat.ShouldBe(ChecklistFormat.Cklb);
        reread.Host.HostName.ShouldBe("host-edge.example.test");
    }

    /// <summary>Scanner output is a results document, so a scan-derived checklist exports as .ckl.</summary>
    [Fact]
    public async Task Xccdf_import_exports_as_ckl_by_default()
    {
        ApiFixture.SkipIfUnavailable();

        var imported = await api.ImportFixture("xccdf", "rhel8-host-charlie-xccdf.xml");
        var result = (await imported.Content.ReadFromJsonAsync<ImportResult>(Ct))!;

        var exported = await api.Client.GetAsync($"/api/checklists/{result.Id}/export", Ct);

        exported.Content.Headers.ContentType!.MediaType.ShouldBe("application/xml");
        ChecklistIo.Detect(await exported.Content.ReadAsStringAsync(Ct)).ShouldBe(ChecklistFormat.Ckl);
    }

    [Fact]
    public async Task Returns_findings_for_one_checklist()
    {
        ApiFixture.SkipIfUnavailable();

        var imported = await api.ImportFixture("ckl", "rhel8-host-alpha.ckl");
        var result = (await imported.Content.ReadFromJsonAsync<ImportResult>(Ct))!;

        var detail = await api.Client.GetFromJsonAsync<ChecklistDetail>($"/api/checklists/{result.Id}", Ct);

        detail.ShouldNotBeNull();
        detail.Host.HostName.ShouldBe("host-alpha.example.test");
        detail.Findings.Count.ShouldBe(72);
        detail.Findings.ShouldContain(f => f.RuleVersion == "RHEL-08-010550");
    }

    [Fact]
    public async Task Import_reports_coverage_and_persists_classification()
    {
        ApiFixture.SkipIfUnavailable();

        var imported = await api.ImportFixture("ckl", "rhel8-host-alpha.ckl");
        var result = (await imported.Content.ReadFromJsonAsync<ImportResult>(Ct))!;

        result.CoverageSummary.ShouldContain("47 automatable, 9 manual, 16 needs-review");

        var coverage = await api.Client.GetFromJsonAsync<CoverageReport>(
            $"/api/checklists/{result.Id}/coverage", Ct);

        coverage.ShouldNotBeNull();
        coverage.Total.ShouldBe(72);
        coverage.Automatable.ShouldBe(47);
        coverage.Manual.ShouldBe(9);
        coverage.NeedsReview.ShouldBe(16);
        coverage.AutomatableHighRisk.ShouldBe(22);
        coverage.ByRiskDomain.ShouldContainKey("sshd");

        // Classification is persisted per finding, not recomputed per request.
        var detail = await api.Client.GetFromJsonAsync<ChecklistDetail>($"/api/checklists/{result.Id}", Ct);
        var sshRule = detail!.Findings.Single(f => f.RuleVersion == "RHEL-08-010550");
        sshRule.Automatability.ShouldBe(Stigsmith.Rules.Automatability.Automatable);
        sshRule.IsHighRisk.ShouldBeTrue();
        sshRule.RiskCategories.ShouldContain("sshd");
    }

    [Fact]
    public async Task Returns_404_for_coverage_of_an_unknown_checklist()
    {
        ApiFixture.SkipIfUnavailable();

        var response = await api.Client.GetAsync($"/api/checklists/{Guid.CreateVersion7()}/coverage", Ct);

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Returns_404_for_an_unknown_checklist()
    {
        ApiFixture.SkipIfUnavailable();

        var response = await api.Client.GetAsync($"/api/checklists/{Guid.CreateVersion7()}", Ct);

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }
}
