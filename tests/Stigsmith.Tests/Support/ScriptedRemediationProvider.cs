using Stigsmith.Generation.Providers;

namespace Stigsmith.Tests.Support;

/// <summary>
/// A provider that returns canned responses instead of calling a model.
/// </summary>
/// <remarks>
/// <para>
/// This exists to test the pipeline, not the model. It produces the four response <em>shapes</em> real models
/// actually produce — bare YAML, a fenced block, YAML wrapped in prose, and a "cannot automate" answer — so the
/// queue, worker, extractor, persistence, and streaming path are all driven by realistic input. Which shape a rule
/// gets is a function of the rule (its STIG version number modulo four: 0 bare, 1 fenced, 2 prose, 3 cannot
/// automate), never of call order, so a test that names a rule knows what it will get regardless of what ran
/// before it against the same fixture.
/// </para>
/// <para>
/// It says nothing about whether a real model produces good Ansible. That is only answerable by running one, and
/// on the machine this was built on no Ollama was available. See DECISIONS.md and PROGRESS.md.
/// </para>
/// </remarks>
public sealed class ScriptedRemediationProvider : IRemediationProvider
{
    private int _calls;

    public string Name => "scripted";

    public string Model => "scripted-test-model";

    public bool Available { get; set; } = true;

    /// <summary>Every prompt this provider was asked to complete, so a test can inspect what was sent.</summary>
    public List<RemediationPrompt> Prompts { get; } = [];

    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default) => Task.FromResult(Available);

    public async IAsyncEnumerable<GenerationChunk> StreamAsync(
        RemediationPrompt prompt,
        GenerationParameters parameters,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        Prompts.Add(prompt);
        var response = ResponseFor(prompt, Interlocked.Increment(ref _calls) - 1);

        // Chunked mid-word, as a real token stream arrives, so the worker's accumulation is actually exercised.
        for (var i = 0; i < response.Length; i += 24)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return new GenerationChunk(response[i..Math.Min(i + 24, response.Length)]);
            await Task.Yield();
        }

        yield return new GenerationChunk("", IsFinal: true, PromptTokens: 1200, CompletionTokens: response.Length / 4);
    }

    /// <summary>
    /// Derives a plausible task from the rule in the prompt, then packages it in one of the four shapes, chosen by
    /// the rule's own number so the choice is stable across runs and test orderings.
    /// </summary>
    private static string ResponseFor(RemediationPrompt prompt, int call)
    {
        var version = ExtractLine(prompt.User, "STIG version: ") ?? "UNKNOWN-00-000000";
        var vuln = ExtractLine(prompt.User, "Rule ID: ") is { } ruleId
            ? new string([.. ruleId.Where(char.IsDigit)])[..Math.Min(6, ruleId.Count(char.IsDigit))]
            : "000000";

        var tasks = $"""
            - name: "{version} | PATCH | Applied by Stigsmith"
              ansible.builtin.lineinfile:
                path: /etc/stigsmith/{version}.conf
                regexp: '^setting'
                line: setting = compliant
                create: true
                owner: root
                group: root
                mode: "0644"
              when:
                - stigsmith_rhel8_rule_{vuln}
              tags:
                - {version}
                - V-{vuln}
            """;

        var shape = int.TryParse(version[(version.LastIndexOf('-') + 1)..], out var number) ? number % 4 : call % 4;
        return shape switch
        {
            0 => tasks,
            1 => $"```yaml\n{tasks}\n```",
            2 => $"Here are the tasks for {version}:\n\n{tasks}\n\nLet me know if you need anything else.",
            _ => $"# cannot-automate: the fix for {version} requires a value only the site can supply",
        };
    }

    private static string? ExtractLine(string text, string prefix)
    {
        foreach (var line in text.Split('\n'))
            if (line.StartsWith(prefix, StringComparison.Ordinal))
                return line[prefix.Length..].Trim();
        return null;
    }
}
