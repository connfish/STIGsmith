namespace Stigsmith.Generation.Providers;

/// <summary>
/// Ollama connection settings. The default provider (constraint 4), not a fallback.
/// </summary>
public sealed class OllamaOptions
{
    public const string SectionName = "Stigsmith:Generation:Ollama";

    public string BaseUrl { get; set; } = "http://localhost:11434";

    /// <summary>
    /// A code-oriented model by default. Translating prose into YAML is a code task, and a general chat model
    /// spends its output budget explaining itself.
    /// </summary>
    public string Model { get; set; } = "qwen2.5-coder:7b";

    /// <summary>
    /// Generous, because a first request to a cold Ollama includes loading the model into memory, which on
    /// modest hardware takes longer than any sane HTTP default.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(10);
}
