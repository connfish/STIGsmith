using System.Net;
using System.Net.Http.Json;
using Stigsmith.Api.Endpoints;
using Stigsmith.Tests.Support;
using Stigsmith.Validation;
using Xunit;

namespace Stigsmith.Tests.Validation;

/// <summary>
/// The validation endpoints, worker, evidence persistence, and report against a real PostgreSQL, with a scripted model
/// and a scripted container behind them. Skipped where no container runtime exists.
/// </summary>
public class ValidationApiTests(ApiFixture api, ITestOutputHelper output) : IClassFixture<ApiFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Imports a checklist, generates for a few rules, and waits for the generations to finish.</summary>
    private async Task<(Guid ChecklistId, List<QueuedGeneration> Generations)> GenerateFor(params string[] ruleVersions)
    {
        var imported = await api.ImportFixture("ckl", "rhel8-host-alpha.ckl");
        var checklistId = (await imported.Content.ReadFromJsonAsync<ImportResult>(Ct))!.Id;

        var queued = (await (await api.Client.PostAsJsonAsync(
            $"/api/checklists/{checklistId}/generate",
            new GenerateRequest(RuleVersions: ruleVersions, OptInRiskDomains: ["sshd", "pam", "firewall", "network", "authentication", "selinux"]), Ct))
            .Content.ReadFromJsonAsync<QueueResult>(Ct))!;

        foreach (var item in queued.QueuedItems)
            await WaitFor<GenerationDetail>($"/api/generations/{item.GenerationId}",
                d => d.RawResponse.Length > 0 || d.Error is { Length: > 0 });

        return (checklistId, queued.QueuedItems);
    }

    [Fact]
    public async Task Reports_sandbox_status()
    {
        ApiFixture.SkipIfUnavailable();

        var status = await api.Client.GetFromJsonAsync<SandboxStatus>("/api/validations/status", Ct);

        status.ShouldNotBeNull();
        status.ContainerImage.ShouldBe("scripted/validation:test");
        status.Available.ShouldBeTrue();
    }

    [Fact]
    public async Task Validates_a_generation_and_stores_the_full_evidence()
    {
        ApiFixture.SkipIfUnavailable();
        api.Sandbox.Reset();
        var (_, generations) = await GenerateFor("RHEL-08-040000");

        var generationId = generations.Single().GenerationId;
        var queued = await api.Client.PostAsJsonAsync($"/api/generations/{generationId}/validate", new { }, Ct);

        queued.StatusCode.ShouldBe(HttpStatusCode.OK);
        var runId = (await queued.Content.ReadFromJsonAsync<ValidationQueueResult>(Ct))!.QueuedItems.Single().ValidationRunId;

        var run = await WaitFor<ValidationRunDetail>(
            $"/api/validations/{runId}", r => r.CompletedAt is not null);

        output.WriteLine($"{run.RuleVersion}: {run.Outcome}, {run.ScanStatusBefore} -> {run.ScanStatusAfter}");

        run.Outcome.ShouldBe(ValidationOutcome.Passed);
        run.RuleVersion.ShouldBe("RHEL-08-040000");
        run.ContainerImage.ShouldBe("scripted/validation:test");

        // The evidence an ISSO reads, all of it persisted.
        run.LintOutput.ShouldNotBeNullOrWhiteSpace();
        run.SyntaxCheckOutput.ShouldNotBeNullOrWhiteSpace();
        run.ApplyOutput.ShouldContain("PLAY RECAP");
        run.ScanStatusBefore.ShouldBe("fail");
        run.ScanStatusAfter.ShouldBe("pass");
        run.IdempotencyOutput.ShouldContain("changed=0");
        run.IdempotencyChangedCount.ShouldBe(0);
        run.EvidenceJson.ShouldContain("\"Outcome\": \"Passed\"");
        run.EvidenceJson.ShouldContain("hosts: localhost");
    }

    [Fact]
    public async Task Refuses_to_validate_a_generation_with_no_usable_yaml()
    {
        ApiFixture.SkipIfUnavailable();
        api.Sandbox.Reset();

        // The scripted model returns a cannot-automate answer for one response shape in four, so generating for four
        // rules reliably produces one with no YAML.
        var (_, generations) = await GenerateFor(
            "RHEL-08-040000", "RHEL-08-010171", "RHEL-08-010561", "RHEL-08-040001");

        var withoutYaml = new List<Guid>();
        foreach (var item in generations)
        {
            var detail = await api.Client.GetFromJsonAsync<GenerationDetail>($"/api/generations/{item.GenerationId}", Ct);
            if (detail!.Yaml.Length == 0) withoutYaml.Add(item.GenerationId);
        }

        withoutYaml.ShouldNotBeEmpty("the scripted model should have produced at least one cannot-automate answer");

        var response = await api.Client.PostAsJsonAsync($"/api/generations/{withoutYaml[0]}/validate", new { }, Ct);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(Ct)).ShouldContain("no usable YAML");
    }

    /// <summary>
    /// A rule whose remediation cannot be repaired must land in needs-human-review, with both attempts stored so a
    /// reviewer can see what was tried and what the tool said about it.
    /// </summary>
    [Fact]
    public async Task A_rule_that_fails_twice_lands_in_needs_human_review_with_both_attempts_stored()
    {
        ApiFixture.SkipIfUnavailable();
        api.Sandbox.Reset();
        api.Sandbox.LintFails = true;
        try
        {
            var (_, generations) = await GenerateFor("RHEL-08-040000");
            var generationId = generations.Single().GenerationId;

            var queued = (await (await api.Client.PostAsJsonAsync(
                $"/api/generations/{generationId}/validate", new { }, Ct))
                .Content.ReadFromJsonAsync<ValidationQueueResult>(Ct))!;

            await WaitFor<ValidationRunDetail>(
                $"/api/validations/{queued.QueuedItems.Single().ValidationRunId}", r => r.CompletedAt is not null);

            var runs = await api.Client.GetFromJsonAsync<List<ValidationRunDetail>>(
                $"/api/generations/{generationId}/validations", Ct);

            runs.ShouldNotBeNull();
            runs.Count.ShouldBe(2, "the first attempt and the repair attempt are both evidence");
            runs[0].RepairAttempt.ShouldBe(0);
            runs[1].RepairAttempt.ShouldBe(1);
            runs[^1].Outcome.ShouldBe(ValidationOutcome.NeedsHumanReview);
            runs[^1].FailedStage.ShouldBe("Lint");
            runs[^1].LintOutput.ShouldContain("couldn't resolve module");
        }
        finally
        {
            api.Sandbox.Reset();
        }
    }

    [Fact]
    public async Task A_non_idempotent_remediation_is_reported_as_such()
    {
        ApiFixture.SkipIfUnavailable();
        api.Sandbox.Reset();
        api.Sandbox.NotIdempotent = true;
        try
        {
            var (_, generations) = await GenerateFor("RHEL-08-040000");
            var queued = (await (await api.Client.PostAsJsonAsync(
                $"/api/generations/{generations.Single().GenerationId}/validate", new { }, Ct))
                .Content.ReadFromJsonAsync<ValidationQueueResult>(Ct))!;

            var run = await WaitFor<ValidationRunDetail>(
                $"/api/validations/{queued.QueuedItems.Single().ValidationRunId}", r => r.CompletedAt is not null);

            // It flipped the finding, and still fails: both facts are recorded.
            run.ScanStatusAfter.ShouldBe("pass");
            run.IdempotencyChangedCount.ShouldBe(1);
            run.Outcome.ShouldNotBe(ValidationOutcome.Passed);
        }
        finally
        {
            api.Sandbox.Reset();
        }
    }

    /// <summary>The report the milestone asks for: pass/fail per rule, with evidence behind each row.</summary>
    [Fact]
    public async Task Produces_a_pass_fail_report_for_a_checklist()
    {
        ApiFixture.SkipIfUnavailable();
        api.Sandbox.Reset();

        var (checklistId, _) = await GenerateFor(
            "RHEL-08-040000", "RHEL-08-010171", "RHEL-08-010550", "RHEL-08-020300",
            "RHEL-08-040100", "RHEL-08-010561", "RHEL-08-030170", "RHEL-08-040001");

        var queued = (await (await api.Client.PostAsJsonAsync(
            $"/api/checklists/{checklistId}/validate", new { }, Ct))
            .Content.ReadFromJsonAsync<ValidationQueueResult>(Ct))!;

        output.WriteLine($"{queued.Queued} queued, {queued.Skipped} skipped");
        foreach (var skip in queued.SkippedItems) output.WriteLine($"  skipped {skip.RuleVersion}: {skip.Reason}");

        queued.Queued.ShouldBeGreaterThan(0);
        foreach (var item in queued.QueuedItems)
            await WaitFor<ValidationRunDetail>($"/api/validations/{item.ValidationRunId}", r => r.CompletedAt is not null);

        var report = await api.Client.GetFromJsonAsync<ValidationReportResponse>(
            $"/api/checklists/{checklistId}/validation-report", Ct);

        report.ShouldNotBeNull();
        output.WriteLine(report.Summary);
        foreach (var row in report.Rows)
            output.WriteLine($"  {row.RuleVersion,-18} {row.Outcome,-18} {row.ScanStatusBefore}->{row.ScanStatusAfter}");

        report.Total.ShouldBe(queued.Queued);
        report.Passed.ShouldBe(queued.Queued);
        (report.Passed + report.NeedsHumanReview + report.Failed + report.Skipped).ShouldBe(report.Total);
        report.Summary.ShouldContain("passed");
        report.Rows.ShouldAllBe(r => r.Summary.Length > 0);
        // Skipped generations are absent from the report rather than counted as failures: nothing was validated.
        report.Rows.Select(r => r.RuleVersion)
            .ShouldNotContain(v => queued.SkippedItems.Any(s => s.RuleVersion == v));
    }

    [Fact]
    public async Task Returns_404_for_unknown_ids()
    {
        ApiFixture.SkipIfUnavailable();

        (await api.Client.PostAsJsonAsync($"/api/generations/{Guid.CreateVersion7()}/validate", new { }, Ct))
            .StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await api.Client.GetAsync($"/api/validations/{Guid.CreateVersion7()}", Ct))
            .StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await api.Client.GetAsync($"/api/checklists/{Guid.CreateVersion7()}/validation-report", Ct))
            .StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    /// <summary>
    /// Without a container runtime the API must refuse and say what to do, not queue work that will quietly report
    /// everything as skipped.
    /// </summary>
    [Fact]
    public async Task Refuses_to_queue_validation_without_a_container_runtime()
    {
        ApiFixture.SkipIfUnavailable();
        api.Sandbox.Reset();
        var (checklistId, _) = await GenerateFor("RHEL-08-040000");

        api.Sandbox.Available = false;
        try
        {
            var response = await api.Client.PostAsJsonAsync($"/api/checklists/{checklistId}/validate", new { }, Ct);

            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            var body = await response.Content.ReadAsStringAsync(Ct);
            body.ShouldContain("No container runtime is available");
            body.ShouldContain("docker build");
        }
        finally
        {
            api.Sandbox.Reset();
        }
    }

    private async Task<T> WaitFor<T>(string url, Func<T, bool> done, int seconds = 30)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < deadline)
        {
            var response = await api.Client.GetAsync(url, Ct);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                var value = await response.Content.ReadFromJsonAsync<T>(Ct);
                if (value is not null && done(value)) return value;
            }
            await Task.Delay(100, Ct);
        }
        throw new TimeoutException($"{url} did not reach the expected state within {seconds} seconds.");
    }
}
