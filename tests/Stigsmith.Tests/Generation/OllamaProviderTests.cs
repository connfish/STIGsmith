using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Stigsmith.Generation.Providers;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests.Generation;

public class OllamaProviderTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static (OllamaRemediationProvider Provider, StubHttpMessageHandler Handler) Build(
        StubHttpMessageHandler handler, string model = "qwen2.5-coder:7b")
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("http://localhost:11434") };
        var options = Options.Create(new OllamaOptions { Model = model });
        return (new OllamaRemediationProvider(http, options, NullLogger<OllamaRemediationProvider>.Instance), handler);
    }

    private static RemediationPrompt Prompt => new("system rules here", "user rule content here");

    [Fact]
    public async Task Streams_chunks_as_they_arrive_and_reports_token_counts()
    {
        var (provider, _) = Build(StubHttpMessageHandler.Streaming(
            """{"message":{"content":"- name: "},"done":false}""",
            """{"message":{"content":"Root SSH\n"},"done":false}""",
            """{"message":{"content":""},"done":true,"prompt_eval_count":1234,"eval_count":56}"""));

        var chunks = new List<GenerationChunk>();
        await foreach (var chunk in provider.StreamAsync(Prompt, new GenerationParameters(), Ct))
            chunks.Add(chunk);

        chunks.Count.ShouldBe(3);
        string.Concat(chunks.Select(c => c.Text)).ShouldBe("- name: Root SSH\n");
        chunks[^1].IsFinal.ShouldBeTrue();
        chunks[^1].PromptTokens.ShouldBe(1234);
        chunks[^1].CompletionTokens.ShouldBe(56);
    }

    /// <summary>
    /// Temperature 0 and a fixed seed are what make two runs over the same rule produce the same Ansible. If
    /// these stopped being sent, reproducibility would fail silently and every diff would look like a change.
    /// </summary>
    [Fact]
    public async Task Sends_the_model_prompt_and_sampling_parameters()
    {
        var (provider, handler) = Build(StubHttpMessageHandler.Streaming("""{"message":{"content":"x"},"done":true}"""));

        await foreach (var _ in provider.StreamAsync(Prompt, new GenerationParameters(Temperature: 0, Seed: 7), Ct)) { }

        var body = JsonNode.Parse(handler.LastBody)!;
        handler.Requests[^1].Path.ShouldBe("/api/chat");
        body["model"]!.GetValue<string>().ShouldBe("qwen2.5-coder:7b");
        body["stream"]!.GetValue<bool>().ShouldBeTrue();
        body["messages"]![0]!["role"]!.GetValue<string>().ShouldBe("system");
        body["messages"]![0]!["content"]!.GetValue<string>().ShouldBe("system rules here");
        body["messages"]![1]!["role"]!.GetValue<string>().ShouldBe("user");
        body["messages"]![1]!["content"]!.GetValue<string>().ShouldBe("user rule content here");
        body["options"]!["temperature"]!.GetValue<double>().ShouldBe(0);
        body["options"]!["seed"]!.GetValue<int>().ShouldBe(7);
        body["options"]!["num_predict"]!.GetValue<int>().ShouldBe(2048);
    }

    [Fact]
    public async Task Surfaces_an_error_reported_inside_the_stream()
    {
        var (provider, _) = Build(StubHttpMessageHandler.Streaming(
            """{"message":{"content":"- name: partial"},"done":false}""",
            """{"error":"model requires more system memory than is available"}"""));

        var error = await Should.ThrowAsync<RemediationProviderException>(async () =>
        {
            await foreach (var _ in provider.StreamAsync(Prompt, new GenerationParameters(), Ct)) { }
        });

        error.Message.ShouldContain("more system memory");
    }

    [Fact]
    public async Task Surfaces_an_http_failure_with_the_body()
    {
        var (provider, _) = Build(StubHttpMessageHandler.Status(
            HttpStatusCode.NotFound, """{"error":"model 'nope' not found"}"""));

        var error = await Should.ThrowAsync<RemediationProviderException>(async () =>
        {
            await foreach (var _ in provider.StreamAsync(Prompt, new GenerationParameters(), Ct)) { }
        });

        error.Message.ShouldContain("404");
        error.Message.ShouldContain("not found");
    }

    /// <summary>
    /// One malformed line should not discard a generation: the content already received is still usable, and
    /// the alternative is throwing away a whole response over a transport hiccup.
    /// </summary>
    [Fact]
    public async Task Skips_an_unparseable_line_rather_than_failing()
    {
        var (provider, _) = Build(StubHttpMessageHandler.Streaming(
            """{"message":{"content":"- name: a"},"done":false}""",
            "{ this is not json",
            """{"message":{"content":"\n"},"done":true}"""));

        var text = new List<string>();
        await foreach (var chunk in provider.StreamAsync(Prompt, new GenerationParameters(), Ct))
            text.Add(chunk.Text);

        string.Concat(text).ShouldBe("- name: a\n");
    }

    [Fact]
    public async Task Reports_available_when_the_configured_model_is_installed()
    {
        var (provider, _) = Build(new StubHttpMessageHandler((request, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"models":[{"name":"qwen2.5-coder:7b"},{"name":"llama3.2:3b"}]}"""),
                RequestMessage = request,
            }));

        (await provider.IsAvailableAsync(Ct)).ShouldBeTrue();
    }

    /// <summary>
    /// Reachable but missing the model is a distinct, actionable failure — the operator needs `ollama pull`,
    /// not a network diagnosis — so it must not report as available.
    /// </summary>
    [Fact]
    public async Task Reports_unavailable_when_the_configured_model_is_not_installed()
    {
        var (provider, _) = Build(new StubHttpMessageHandler((request, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"models":[{"name":"llama3.2:3b"}]}"""),
                RequestMessage = request,
            }));

        (await provider.IsAvailableAsync(Ct)).ShouldBeFalse();
    }

    [Fact]
    public async Task Reports_unavailable_when_ollama_cannot_be_reached()
    {
        var (provider, _) = Build(new StubHttpMessageHandler((_, _) => throw new HttpRequestException("refused")));

        (await provider.IsAvailableAsync(Ct)).ShouldBeFalse();
    }

    [Fact]
    public async Task Reports_unavailable_when_no_model_is_installed_at_all()
    {
        var (provider, _) = Build(new StubHttpMessageHandler((request, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"models":[]}"""),
                RequestMessage = request,
            }));

        (await provider.IsAvailableAsync(Ct)).ShouldBeFalse();
    }

    /// <summary>A stream that stops without a done frame is a dropped connection, not a short answer.</summary>
    [Fact]
    public async Task A_stream_that_ends_without_a_done_frame_is_an_error()
    {
        var (provider, _) = Build(StubHttpMessageHandler.Streaming(
            """{"message":{"content":"- name: partial"},"done":false}"""));

        var error = await Should.ThrowAsync<RemediationProviderException>(async () =>
        {
            await foreach (var _ in provider.StreamAsync(Prompt, new GenerationParameters(), Ct)) { }
        });

        error.Message.ShouldContain("incomplete");
    }

    [Fact]
    public void Identifies_itself_for_the_audit_record()
    {
        var (provider, _) = Build(StubHttpMessageHandler.Streaming(), model: "codellama:13b");

        provider.Name.ShouldBe("ollama");
        provider.Model.ShouldBe("codellama:13b");
    }

    /// <summary>
    /// The one test that talks to a real model. Skipped without a reachable Ollama, which is the case on the
    /// machine this was built on — see DECISIONS.md. It is the only coverage of an actual generation, so
    /// treat end-to-end generation as unverified until this has run somewhere.
    /// </summary>
    [Fact]
    public async Task Generates_against_a_live_ollama()
    {
        Assert.SkipUnless(TestEnvironment.HasOllama, $"No Ollama reachable at {TestEnvironment.OllamaBaseUrl}.");

        var http = new HttpClient { BaseAddress = new Uri(TestEnvironment.OllamaBaseUrl) };
        var provider = new OllamaRemediationProvider(
            http, Options.Create(new OllamaOptions()), NullLogger<OllamaRemediationProvider>.Instance);

        Assert.SkipUnless(await provider.IsAvailableAsync(Ct), "Ollama is reachable but the model is not installed.");

        var prompt = new RemediationPrompt(
            "Reply with exactly the word OK and nothing else.", "Say OK.");

        var text = new List<string>();
        await foreach (var chunk in provider.StreamAsync(prompt, new GenerationParameters(MaxOutputTokens: 16), Ct))
            text.Add(chunk.Text);

        string.Concat(text).ShouldNotBeNullOrWhiteSpace();
    }
}
