using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Stigsmith.Generation.Prompting;

/// <summary>What a model's raw response turned out to contain.</summary>
public enum GeneratedYamlKind
{
    /// <summary>A parseable list of Ansible tasks.</summary>
    Tasks,

    /// <summary>The model reported that the fix cannot be expressed as idempotent Ansible. A valid answer.</summary>
    CannotAutomate,

    /// <summary>Not YAML, or YAML that is not a task list.</summary>
    Invalid,
}

/// <summary>The result of pulling usable YAML out of a model response.</summary>
public sealed record GeneratedYaml
{
    public required GeneratedYamlKind Kind { get; init; }

    /// <summary>The extracted YAML, or empty when nothing usable was found.</summary>
    public string Yaml { get; init; } = "";

    /// <summary>Why it is invalid, or the model's stated reason it cannot be automated.</summary>
    public string Message { get; init; } = "";

    /// <summary>Task names found, for reporting what was generated without re-parsing.</summary>
    public IReadOnlyList<string> TaskNames { get; init; } = [];

    public bool IsUsable => Kind == GeneratedYamlKind.Tasks;
}

/// <summary>
/// Extracts and validates the Ansible in a model response.
/// </summary>
/// <remarks>
/// <para>
/// The prompt asks for bare YAML with no fence, and models comply most of the time. This handles the rest: a
/// ```yaml fence, a leading sentence of explanation, a trailing "Let me know if...". Being tolerant here is
/// not sloppiness — the alternative is discarding an otherwise correct generation over a formatting habit and
/// then re-running the model to get the same content with different packaging.
/// </para>
/// <para>
/// What it does <b>not</b> do is repair the YAML. If the structure is wrong, the generation is invalid and
/// says why; M6's validation loop feeds that message back for one repair attempt. Silently fixing up a
/// model's output would hide exactly the signal the loop needs.
/// </para>
/// </remarks>
public static class AnsibleYamlExtractor
{
    public static GeneratedYaml Extract(string response)
    {
        if (string.IsNullOrWhiteSpace(response))
            return new GeneratedYaml { Kind = GeneratedYamlKind.Invalid, Message = "The model returned nothing." };

        var text = Unfence(response.ReplaceLineEndings("\n")).Trim();

        if (FindCannotAutomate(text) is { } reason)
            return new GeneratedYaml
            {
                Kind = GeneratedYamlKind.CannotAutomate,
                Yaml = text,
                Message = reason,
            };

        var yaml = TrimToYaml(text);
        if (yaml.Length == 0)
            return new GeneratedYaml
            {
                Kind = GeneratedYamlKind.Invalid,
                Message = "No YAML found in the response.",
            };

        try
        {
            var stream = new YamlStream();
            stream.Load(new StringReader(yaml));

            if (stream.Documents.FirstOrDefault()?.RootNode is not YamlSequenceNode sequence)
                return new GeneratedYaml
                {
                    Kind = GeneratedYamlKind.Invalid,
                    Yaml = yaml,
                    Message = "The YAML parsed but is not a list of tasks at the top level.",
                };

            if (sequence.Children.Count == 0)
                return new GeneratedYaml
                {
                    Kind = GeneratedYamlKind.Invalid,
                    Yaml = yaml,
                    Message = "The YAML is an empty list, so it applies no fix.",
                };

            var entries = sequence.Children.OfType<YamlMappingNode>().ToArray();
            if (entries.Length != sequence.Children.Count)
                return new GeneratedYaml
                {
                    Kind = GeneratedYamlKind.Invalid,
                    Yaml = yaml,
                    Message = "The list contains an entry that is not a task mapping.",
                };

            return new GeneratedYaml
            {
                Kind = GeneratedYamlKind.Tasks,
                Yaml = yaml,
                TaskNames = [.. entries
                    .Select(e => e.Children.TryGetValue(new YamlScalarNode("name"), out var n)
                        ? (n as YamlScalarNode)?.Value ?? ""
                        : "")
                    .Where(n => n.Length > 0)],
            };
        }
        catch (YamlException ex)
        {
            return new GeneratedYaml
            {
                Kind = GeneratedYamlKind.Invalid,
                Yaml = yaml,
                Message = $"The response is not valid YAML: {ex.Message}",
            };
        }
    }

    /// <summary>Returns the first fenced block's contents, or the input unchanged when there is no fence.</summary>
    private static string Unfence(string text)
    {
        var open = text.IndexOf("```", StringComparison.Ordinal);
        if (open < 0) return text;

        // Skip the rest of the opening fence line, which usually carries a language hint.
        var contentStart = text.IndexOf('\n', open);
        if (contentStart < 0) return text;
        contentStart++;

        var close = text.IndexOf("```", contentStart, StringComparison.Ordinal);
        return close < 0 ? text[contentStart..] : text[contentStart..close];
    }

    /// <summary>
    /// Finds the model's "cannot automate" line anywhere in the response, since a model that adds a sentence
    /// of preamble still means it.
    /// </summary>
    private static string? FindCannotAutomate(string text)
    {
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith(RemediationPromptAssembler.CannotAutomateMarker, StringComparison.OrdinalIgnoreCase))
                continue;

            var reason = trimmed[RemediationPromptAssembler.CannotAutomateMarker.Length..].Trim();
            return reason.Length > 0 ? reason : "The model gave no reason.";
        }
        return null;
    }

    /// <summary>
    /// Drops leading prose and trailing commentary, keeping the block from the first YAML-ish line to the last.
    /// A document marker or a list item is what a task list starts with; a sentence is not.
    /// </summary>
    private static string TrimToYaml(string text)
    {
        var lines = text.Split('\n');

        var first = Array.FindIndex(lines, IsYamlStart);
        if (first < 0) return "";

        var last = lines.Length - 1;
        while (last > first && !IsYamlBody(lines[last])) last--;

        return string.Join('\n', lines[first..(last + 1)]).Trim();
    }

    /// <summary>
    /// Where the YAML plausibly begins. Accepts a flow collection and a top-level key, not just a list item,
    /// so a model that returned a whole playbook or an empty collection is reported as the wrong <em>shape</em>
    /// rather than as "no YAML found" — which would be a baffling message to read next to obvious YAML.
    /// </summary>
    private static bool IsYamlStart(string line)
    {
        var trimmed = line.TrimStart();
        return trimmed.StartsWith("---", StringComparison.Ordinal)
            || trimmed.StartsWith("- ", StringComparison.Ordinal)
            || trimmed.StartsWith('[')
            || trimmed.StartsWith('{')
            || LooksLikeTopLevelKey(trimmed);
    }

    /// <summary>
    /// A line that could belong to a YAML task: a list item, an indented key, or a comment. Explicitly not a
    /// sentence, which is how a trailing "Let me know if you need anything else" gets dropped.
    /// </summary>
    private static bool IsYamlBody(string line)
    {
        if (line.Length == 0) return false;
        if (char.IsWhiteSpace(line[0])) return true;

        var trimmed = line.TrimStart();
        if (trimmed.StartsWith("- ", StringComparison.Ordinal) || trimmed.StartsWith('#')) return true;
        if (trimmed.StartsWith(']') || trimmed.StartsWith('}')) return true;
        return LooksLikeTopLevelKey(trimmed);
    }

    /// <summary>
    /// A top-level "key: value". A sentence containing a colon is not one, so the part before the colon has to
    /// look like an identifier — that is how "Here are the tasks that apply the fix:" is not mistaken for YAML.
    /// </summary>
    private static bool LooksLikeTopLevelKey(string trimmed)
    {
        var colon = trimmed.IndexOf(':');
        if (colon <= 0) return false;
        return trimmed[..colon].All(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.');
    }
}
