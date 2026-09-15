using System.Net;
using System.Net.Http.Json;
using Stigsmith.Api.Endpoints;
using Stigsmith.Tests.Support;
using Xunit;

namespace Stigsmith.Tests.Generation;

/// <summary>
/// The generation endpoints against a real PostgreSQL, with a scripted model behind them. Skipped where no
/// container runtime exists.
/// </summary>
public class GenerationApiTests(ApiFixture api, ITestOutputHelper output) : IClassFixture<ApiFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task<Guid> ImportAlpha()
    {
        var imported = await api.ImportFixture("ckl", "rhel8-host-alpha.ckl");
        return (await imported.Content.ReadFromJsonAsync<ImportResult>(Ct))!.Id;
    }

    [Fact]
    public async Task Reports_provider_status()
    {
        ApiFixture.SkipIfUnavailable();

        var status = await api.Client.GetFromJsonAsync<ProviderStatus>("/api/generations/status", Ct);

        status.ShouldNotBeNull();
        status.Provider.ShouldBe("scripted");
        status.Available.ShouldBeTrue();
        status.QueueDepth.ShouldBeGreaterThanOrEqualTo(0);
    }

    /// <summary>
    /// The queue result is where an operator learns what the tool will and will not do for them. Silently
    /// queueing 29 of 45 findings with no explanation would look like dropped work.
    /// </summary>
    [Fact]
    public async Task Queues_automatable_rules_and_explains_every_skip()
    {
        ApiFixture.SkipIfUnavailable();
        var checklistId = await ImportAlpha();

        var response = await api.Client.PostAsJsonAsync(
            $"/api/checklists/{checklistId}/generate", new GenerateRequest(), Ct);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var result = (await response.Content.ReadFromJsonAsync<QueueResult>(Ct))!;

        output.WriteLine($"{result.Candidates} candidates: {result.Queued} queued, {result.Skipped} skipped.");

        result.Candidates.ShouldBe(45);
        (result.Queued + result.Skipped).ShouldBe(result.Candidates);
        result.TargetOs.ShouldBe("Red Hat Enterprise Linux 8");

        // With no opt-in, high-risk rules are held back and every skip names a reason.
        result.SkippedItems.ShouldAllBe(s => s.Reason.Length > 0);
        result.SkippedItems.ShouldContain(s => s.Verdict == "BlockedPendingOptIn");
        result.SkippedItems.ShouldContain(s => s.Verdict == "NotAutomatable");
        result.SkippedItems.First(s => s.Verdict == "BlockedPendingOptIn").Reason.ShouldContain("Opt in to");
        result.QueuedItems.ShouldAllBe(q => q.RequiresCheckMode == false);
    }

    [Fact]
    public async Task Opting_in_to_a_domain_releases_its_high_risk_rules_with_check_mode_required()
    {
        ApiFixture.SkipIfUnavailable();
        var checklistId = await ImportAlpha();

        var withoutOptIn = (await (await api.Client.PostAsJsonAsync(
            $"/api/checklists/{checklistId}/generate",
            new GenerateRequest(RuleVersions: ["RHEL-08-010550"]), Ct))
            .Content.ReadFromJsonAsync<QueueResult>(Ct))!;

        withoutOptIn.Queued.ShouldBe(0);
        withoutOptIn.SkippedItems.Single().Reason.ShouldContain("sshd");

        var withOptIn = (await (await api.Client.PostAsJsonAsync(
            $"/api/checklists/{checklistId}/generate",
            new GenerateRequest(RuleVersions: ["RHEL-08-010550"], OptInRiskDomains: ["sshd"]), Ct))
            .Content.ReadFromJsonAsync<QueueResult>(Ct))!;

        withOptIn.Queued.ShouldBe(1);
        // Consenting to generation is not consenting to apply blind.
        withOptIn.QueuedItems.Single().RequiresCheckMode.ShouldBeTrue();
    }

    [Fact]
    public async Task Opting_in_to_one_domain_does_not_release_another()
    {
        ApiFixture.SkipIfUnavailable();
        var checklistId = await ImportAlpha();

        var result = (await (await api.Client.PostAsJsonAsync(
            $"/api/checklists/{checklistId}/generate",
            // 010550 is sshd; 040286 (rp_filter) is network. Both are open in the alpha fixture.
            new GenerateRequest(RuleVersions: ["RHEL-08-010550", "RHEL-08-040286"], OptInRiskDomains: ["sshd"]), Ct))
            .Content.ReadFromJsonAsync<QueueResult>(Ct))!;

        result.QueuedItems.Select(q => q.RuleVersion).ShouldBe(["RHEL-08-010550"]);
        result.SkippedItems.Single().RuleVersion.ShouldBe("RHEL-08-040286");
        result.SkippedItems.Single().Reason.ShouldContain("network");
    }

    [Fact]
    public async Task Rejects_an_unknown_risk_domain()
    {
        ApiFixture.SkipIfUnavailable();
        var checklistId = await ImportAlpha();

        var response = await api.Client.PostAsJsonAsync(
            $"/api/checklists/{checklistId}/generate", new GenerateRequest(OptInRiskDomains: ["sshd", "nonsense"]), Ct);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(Ct)).ShouldContain("not a risk domain");
    }

    /// <summary>
    /// The audit record. An ISSO asking "what exactly did the model see?" gets the whole prompt back, which is
    /// also how the constraint 3 guarantee stays checkable in production rather than only at test time.
    /// </summary>
    [Fact]
    public async Task Persists_the_full_prompt_model_and_parameters()
    {
        ApiFixture.SkipIfUnavailable();
        var checklistId = await ImportAlpha();

        var queued = (await (await api.Client.PostAsJsonAsync(
            $"/api/checklists/{checklistId}/generate",
            new GenerateRequest(RuleVersions: ["RHEL-08-040000"]), Ct))
            .Content.ReadFromJsonAsync<QueueResult>(Ct))!;

        queued.Queued.ShouldBe(1);
        var generationId = queued.QueuedItems.Single().GenerationId;

        var detail = await WaitForGeneration(generationId);

        detail.Provider.ShouldBe("scripted");
        detail.Model.ShouldBe("scripted-test-model");
        detail.TargetOs.ShouldBe("Red Hat Enterprise Linux 8");
        detail.SystemPrompt.ShouldContain("translation task, not a design task");
        detail.UserPrompt.ShouldContain("RHEL-08-040000");
        detail.UserPrompt.ShouldContain("telnet-server");
        detail.PromptSha256.Length.ShouldBe(64);
        detail.ParametersJson.ShouldContain("Temperature");
        detail.RetrievedExamples.ShouldNotBeEmpty();
        detail.RawResponse.ShouldNotBeNullOrWhiteSpace();

        // And no host identifier anywhere in the persisted prompt.
        foreach (var canary in new[] { "host-alpha.example.test", "192.0.2.10", "ALPHA-CANARY-STRING" })
            (detail.SystemPrompt + detail.UserPrompt).ShouldNotContain(canary, Case.Insensitive);
    }

    [Fact]
    public async Task Lists_generations_for_a_finding()
    {
        ApiFixture.SkipIfUnavailable();
        var checklistId = await ImportAlpha();

        var queued = (await (await api.Client.PostAsJsonAsync(
            $"/api/checklists/{checklistId}/generate",
            // A low-risk automatable rule, so it queues without an opt-in.
            new GenerateRequest(RuleVersions: ["RHEL-08-040000"]), Ct))
            .Content.ReadFromJsonAsync<QueueResult>(Ct))!;

        var item = queued.QueuedItems.Single();
        await WaitForGeneration(item.GenerationId);

        var list = await api.Client.GetFromJsonAsync<List<GenerationSummary>>(
            $"/api/findings/{item.FindingId}/generations", Ct);

        list.ShouldNotBeNull();
        list.ShouldContain(g => g.Id == item.GenerationId);
        list[0].Provider.ShouldBe("scripted");
    }

    [Fact]
    public async Task Returns_404_for_an_unknown_checklist_or_generation()
    {
        ApiFixture.SkipIfUnavailable();

        (await api.Client.PostAsJsonAsync(
            $"/api/checklists/{Guid.CreateVersion7()}/generate", new GenerateRequest(), Ct))
            .StatusCode.ShouldBe(HttpStatusCode.NotFound);

        (await api.Client.GetAsync($"/api/generations/{Guid.CreateVersion7()}", Ct))
            .StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Refuses_to_queue_when_the_provider_is_unavailable()
    {
        ApiFixture.SkipIfUnavailable();
        var checklistId = await ImportAlpha();

        api.Provider.Available = false;
        try
        {
            var response = await api.Client.PostAsJsonAsync(
                $"/api/checklists/{checklistId}/generate", new GenerateRequest(), Ct);

            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
            (await response.Content.ReadAsStringAsync(Ct)).ShouldContain("could not be reached");
        }
        finally
        {
            api.Provider.Available = true;
        }
    }

    /// <summary>
    /// Generation runs on a background worker, so the record appears shortly after queueing rather than
    /// immediately. Polls rather than sleeping a fixed interval, so the test is neither flaky nor slow.
    /// </summary>
    private async Task<GenerationDetail> WaitForGeneration(Guid generationId)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            var response = await api.Client.GetAsync($"/api/generations/{generationId}", Ct);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                var detail = (await response.Content.ReadFromJsonAsync<GenerationDetail>(Ct))!;
                if (detail.RawResponse.Length > 0 || detail.Error is { Length: > 0 }) return detail;
            }
            await Task.Delay(100, Ct);
        }
        throw new TimeoutException($"Generation {generationId} did not complete within 30 seconds.");
    }
}
