using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Stigsmith.Generation.Providers;

/// <summary>
/// Generates remediation using a model served by Ollama on the operator's own hardware.
/// </summary>
/// <remarks>
/// Talks to <c>/api/chat</c> with <c>stream: true</c>, which returns newline-delimited JSON rather than SSE.
/// Read line by line off the response stream so chunks can be relayed to the client as they arrive — a
/// 2000-token generation takes tens of seconds on modest hardware, and an operator watching a blank screen
/// assumes the tool is broken.
/// </remarks>
public sealed class OllamaRemediationProvider(
    HttpClient http,
    IOptions<OllamaOptions> options,
    ILogger<OllamaRemediationProvider> logger) : IRemediationProvider
{
    public string Name => "ollama";

    public string Model => options.Value.Model;

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // /api/tags lists installed models and needs no model loaded, so it is a cheap liveness probe.
            using var response = await http.GetAsync("/api/tags", cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Ollama at {BaseUrl} returned {Status} from /api/tags.",
                    http.BaseAddress, (int)response.StatusCode);
                return false;
            }

            var body = await response.Content.ReadFromJsonAsync<JsonNode>(cancellationToken);
            var installed = (body?["models"] as JsonArray)?
                .Select(m => m?["name"]?.GetValue<string>() ?? "")
                .Where(n => n.Length > 0)
                .ToArray() ?? [];

            // Reachable but without the configured model is a distinct, actionable failure: the operator needs
            // to run `ollama pull`, not debug their network.
            if (!installed.Any(m => ModelMatches(m, options.Value.Model)))
            {
                logger.LogWarning(
                    "Ollama at {BaseUrl} is reachable but model {Model} is not installed. Installed: {Installed}. "
                    + "Run: ollama pull {Model}",
                    http.BaseAddress, options.Value.Model, string.Join(", ", installed), options.Value.Model);
                return false;
            }

            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            logger.LogWarning(ex, "Ollama at {BaseUrl} is not reachable.", http.BaseAddress);
            return false;
        }
    }

    /// <summary>Ollama reports "qwen2.5-coder:7b"; a config value of "qwen2.5-coder" should still match it.</summary>
    private static bool ModelMatches(string installed, string configured) =>
        installed.Equals(configured, StringComparison.OrdinalIgnoreCase)
        || installed.StartsWith(configured + ":", StringComparison.OrdinalIgnoreCase);

    public async IAsyncEnumerable<GenerationChunk> StreamAsync(
        RemediationPrompt prompt,
        GenerationParameters parameters,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var payload = new JsonObject
        {
            ["model"] = options.Value.Model,
            ["stream"] = true,
            ["messages"] = new JsonArray(
                new JsonObject { ["role"] = "system", ["content"] = prompt.System },
                new JsonObject { ["role"] = "user", ["content"] = prompt.User }),
            ["options"] = new JsonObject
            {
                ["temperature"] = parameters.Temperature,
                ["top_p"] = parameters.TopP,
                ["seed"] = parameters.Seed,
                ["num_predict"] = parameters.MaxOutputTokens,
            },
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/chat")
        {
            Content = new StringContent(payload.ToJsonString(), Encoding.UTF8, "application/json"),
        };

        using var response = await http.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new RemediationProviderException(
                $"Ollama returned {(int)response.StatusCode} {response.ReasonPhrase}: {Truncate(body, 500)}");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var reader = new StreamReader(stream, Encoding.UTF8);

        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            if (line.Length == 0) continue;

            JsonNode? node;
            try
            {
                node = JsonNode.Parse(line);
            }
            catch (JsonException ex)
            {
                // A malformed line mid-stream is worth knowing about but not worth discarding the generation
                // for; the content already received is still usable.
                logger.LogWarning(ex, "Skipped an unparseable line in the Ollama stream.");
                continue;
            }

            if (node?["error"]?.GetValue<string>() is { Length: > 0 } error)
                throw new RemediationProviderException($"Ollama reported an error: {error}");

            var text = node?["message"]?["content"]?.GetValue<string>() ?? "";

            if (node?["done"]?.GetValue<bool>() == true)
            {
                yield return new GenerationChunk(
                    text,
                    IsFinal: true,
                    PromptTokens: node["prompt_eval_count"]?.GetValue<int>() ?? 0,
                    CompletionTokens: node["eval_count"]?.GetValue<int>() ?? 0);
                yield break;
            }

            if (text.Length > 0) yield return new GenerationChunk(text);
        }

        // Ollama always closes a stream with a done frame. Getting here means the connection dropped mid-generation,
        // and a truncated answer must not be recorded as a complete one.
        throw new RemediationProviderException(
            "The Ollama stream ended before the model reported it was done; the response is incomplete.");
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...";
}

/// <summary>The provider could not produce a response. Distinct from the model producing a bad one.</summary>
public sealed class RemediationProviderException(string message, Exception? inner = null)
    : Exception(message, inner);
