using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Stigsmith.Generation.Providers;

/// <summary>
/// The exact text sent to a model, split into its system and user halves.
/// </summary>
/// <remarks>
/// A record rather than two loose strings so the pair can be hashed and persisted as one unit. The hash is
/// what makes an audit answerable: "this generation came from exactly this prompt" is checkable after the
/// fact, which is also how the constraint 3 guarantee stays verifiable outside test time.
/// </remarks>
public sealed record RemediationPrompt(string System, string User)
{
    /// <summary>Everything the model sees. What the hygiene test inspects, and what an operator is shown.</summary>
    public string FullText => System + "\n\n" + User;

    /// <summary>SHA-256 of the full prompt, stored with every generation.</summary>
    public string Sha256Hex => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(FullText)));
}

/// <summary>
/// Sampling parameters, persisted with each generation so a run can be reproduced.
/// </summary>
/// <remarks>
/// Temperature defaults to 0 and the seed is fixed. This is translation, not authoring: two runs over the
/// same rule should produce the same Ansible, and an operator comparing today's output with last month's
/// should be seeing a real difference rather than sampling noise.
/// </remarks>
public sealed record GenerationParameters(
    double Temperature = 0.0,
    double TopP = 0.9,
    int Seed = 0,
    int MaxOutputTokens = 2048)
{
    public string ToJson() => JsonSerializer.Serialize(this);
}

/// <summary>One piece of a streaming response.</summary>
public sealed record GenerationChunk(
    string Text,
    bool IsFinal = false,
    int PromptTokens = 0,
    int CompletionTokens = 0);

/// <summary>
/// A model that can translate a STIG fix into Ansible.
/// </summary>
/// <remarks>
/// Behind an interface so a cloud model can be swapped in where policy allows, but Ollama is the default
/// and is not a fallback (constraint 4). Target environments are frequently air-gapped, and a tool that
/// requires a cloud API is a tool nobody in this space can adopt.
/// </remarks>
public interface IRemediationProvider
{
    /// <summary>Stable identifier persisted with each generation, e.g. "ollama".</summary>
    string Name { get; }

    /// <summary>The model actually used, e.g. "qwen2.5-coder:7b". Persisted for reproducibility.</summary>
    string Model { get; }

    /// <summary>
    /// Whether the provider can be reached. Checked before queuing work, so an unreachable model server is
    /// reported once as such rather than surfacing as a separate failed generation for every rule.
    /// </summary>
    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);

    /// <summary>Streams the response. Chunks are relayed to the client as they arrive.</summary>
    IAsyncEnumerable<GenerationChunk> StreamAsync(
        RemediationPrompt prompt,
        GenerationParameters parameters,
        CancellationToken cancellationToken = default);
}
