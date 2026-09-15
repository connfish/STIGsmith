using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Stigsmith.Checklists.Model;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Stigsmith.Generation.Conventions;

/// <summary>
/// Reads an operator's Ansible role and extracts one <see cref="RoleTask"/> per task.
/// </summary>
/// <remarks>
/// <para>
/// Parsed with YamlDotNet's representation model rather than deserialized into types. Two reasons: an
/// Ansible task is an open map whose interesting key is the module name, which no fixed C# type can
/// anticipate; and every node carries source marks, which is how each task's raw text is sliced out of
/// the file so the few-shot example keeps the role's own formatting.
/// </para>
/// <para>
/// Indexing is best-effort by design. A role that fails to parse is a role Stigsmith should still be
/// partly useful against, so a malformed file is logged and skipped rather than aborting the index — an
/// operator whose role has one Jinja-templated task file should not lose convention retrieval entirely.
/// </para>
/// </remarks>
public sealed partial class AnsibleRoleIndexer(ILogger<AnsibleRoleIndexer>? logger = null)
{
    /// <summary>
    /// Task-level keywords, so whatever key is left over is the module. Taken from Ansible's task keyword
    /// list; a keyword missing from here would show up as a spurious module name, which is why
    /// <see cref="ChooseModule"/> prefers a key containing a dot when there is more than one candidate.
    /// </summary>
    private static readonly HashSet<string> TaskKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "name", "when", "tags", "notify", "become", "become_user", "become_method", "become_flags",
        "register", "changed_when", "failed_when", "ignore_errors", "ignore_unreachable", "loop",
        "loop_control", "with_items", "with_dict", "with_fileglob", "with_first_found", "with_nested",
        "with_subelements", "with_together", "until", "retries", "delay", "delegate_to", "delegate_facts",
        "run_once", "check_mode", "diff", "no_log", "args", "vars", "environment", "listen", "throttle",
        "any_errors_fatal", "block", "rescue", "always", "collections", "module_defaults", "port",
        "remote_user", "timeout", "connection", "debugger", "async", "poll", "local_action", "action",
    };

    /// <summary>Jinja variable references: <c>{{ stigsmith_rhel8_password_minlen }}</c>.</summary>
    [GeneratedRegex(@"\{\{[-\s]*([A-Za-z_][A-Za-z0-9_]*)")]
    private static partial Regex JinjaVariable();

    /// <summary>A bare identifier, for <c>when</c> expressions whose variables are not inside braces.</summary>
    [GeneratedRegex(@"\b([a-z_][a-z0-9_]{3,})\b")]
    private static partial Regex BareIdentifier();

    /// <summary>A V- or SV- rule identifier as it appears in a task name or tag.</summary>
    [GeneratedRegex(@"\b(S?V-\d{4,7})\b", RegexOptions.IgnoreCase)]
    private static partial Regex RuleIdToken();

    /// <summary>A STIG version id such as RHEL-08-010550 or WN22-SO-000030.</summary>
    [GeneratedRegex(@"\b([A-Z]{2,10}-\d{2}-\d{6})\b", RegexOptions.IgnoreCase)]
    private static partial Regex StigVersionToken();

    /// <summary>
    /// Words that look like variables in a <c>when</c> expression but are Jinja or Ansible vocabulary.
    /// Without this, every guard contributes "defined", "bool", and "true" to the variable list.
    /// </summary>
    private static readonly HashSet<string> JinjaVocabulary = new(StringComparer.OrdinalIgnoreCase)
    {
        "defined", "undefined", "none", "true", "false", "bool", "int", "string", "list", "dict",
        "length", "version", "search", "match", "select", "reject", "default", "lower", "upper",
        "and", "or", "not", "in", "is", "if", "else", "changed", "succeeded", "failed", "skipped",
    };

    public RoleIndex Index(ConventionRoleOptions options)
    {
        if (!options.IsConfigured)
            return RoleIndex.Empty("No convention role path is configured.");

        var root = Path.GetFullPath(options.Path!);
        if (!Directory.Exists(root))
            return RoleIndex.Empty($"The configured convention role path does not exist: {root}");

        var files = options.TaskDirectories
            .Distinct(StringComparer.Ordinal)
            .Select(d => Path.Combine(root, d))
            .Where(Directory.Exists)
            .SelectMany(d => Directory.EnumerateFiles(d, "*.y*ml", SearchOption.AllDirectories))
            .Where(f => f.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
                     || f.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToArray();

        if (files.Length == 0)
            return RoleIndex.Empty(
                $"No task files found under {root} in: {string.Join(", ", options.TaskDirectories)}");

        var tasks = new List<RoleTask>();
        var skipped = new List<string>();

        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(root, file);
            try
            {
                tasks.AddRange(ParseFile(File.ReadAllText(file), relative));
            }
            catch (Exception ex) when (ex is YamlException or IOException or UnauthorizedAccessException)
            {
                // Best-effort: one unparseable file must not cost the operator the whole index.
                skipped.Add($"{relative}: {ex.Message}");
                logger?.LogWarning(ex,
                    "Skipped unparseable task file {File} while indexing role conventions.", relative);
            }
        }

        logger?.LogInformation(
            "Indexed {TaskCount} tasks from {FileCount} files under {Root}{Skipped}.",
            tasks.Count, files.Length, root,
            skipped.Count > 0 ? $" ({skipped.Count} file(s) skipped)" : "");

        return new RoleIndex
        {
            RolePath = root,
            Tasks = tasks,
            SkippedFiles = skipped,
            Conventions = RoleConventions.Infer(tasks),
            VarsFiles = ReadVarsFiles(root, skipped),
        };
    }

    /// <summary>
    /// The role's variable files, verbatim, with their top-level keys. Not parsed into values: ansible-playbook reads
    /// them itself in the sandbox, which is the only reader that gets every YAML subtlety right.
    /// </summary>
    private List<RoleVarsFile> ReadVarsFiles(string root, List<string> skipped)
    {
        var files = new List<RoleVarsFile>();
        foreach (var directory in new[] { "defaults", "vars" })
        {
            var path = Path.Combine(root, directory);
            if (!Directory.Exists(path)) continue;
            foreach (var file in Directory.EnumerateFiles(path, "*.y*ml", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                var relative = Path.GetRelativePath(root, file);
                try
                {
                    var content = File.ReadAllText(file);
                    var stream = new YamlStream();
                    stream.Load(new StringReader(content));
                    var names = stream.Documents
                        .Select(d => d.RootNode)
                        .OfType<YamlMappingNode>()
                        .SelectMany(m => m.Children.Keys.OfType<YamlScalarNode>())
                        .Select(k => k.Value ?? "")
                        .Where(k => k.Length > 0)
                        .ToHashSet(StringComparer.Ordinal);
                    files.Add(new RoleVarsFile(relative, content, names));
                }
                catch (Exception ex) when (ex is YamlException or IOException or UnauthorizedAccessException)
                {
                    skipped.Add($"{relative}: {ex.Message}");
                    logger?.LogWarning(ex, "Skipped unreadable variable file {File} while indexing role conventions.", relative);
                }
            }
        }
        return files;
    }

    /// <summary>Parses one task file's worth of YAML. Public so a single file can be indexed or inspected.</summary>
    public static IEnumerable<RoleTask> ParseFile(string yaml, string relativePath)
    {
        var stream = new YamlStream();
        stream.Load(new StringReader(yaml));

        var lines = yaml.ReplaceLineEndings("\n").Split('\n');

        foreach (var document in stream.Documents)
        {
            if (document.RootNode is not YamlSequenceNode sequence) continue;

            var entries = sequence.Children.OfType<YamlMappingNode>().ToArray();
            for (var i = 0; i < entries.Length; i++)
            {
                // The task's text runs from its own first line to the line before the next task's, or to
                // the end of the file for the last one. Derived from start marks rather than from each
                // node's End mark, which YamlDotNet does not populate usefully for block mappings.
                var firstLine = (int)entries[i].Start.Line;
                var lastLine = i + 1 < entries.Length ? (int)entries[i + 1].Start.Line - 1 : lines.Length;

                var task = ParseTask(entries[i], SliceLines(lines, firstLine, lastLine), relativePath);
                // import_tasks / include_tasks entries are plumbing, not examples of how the role
                // configures anything, so they are indexed as nothing.
                if (task is not null) yield return task;
            }
        }
    }

    /// <summary>
    /// Joins a 1-based inclusive line range, keeping the leading "- " marker and the role's indentation so
    /// the result is a complete task an operator (or a model) can copy.
    /// </summary>
    private static string SliceLines(string[] lines, int firstLine, int lastLine)
    {
        var from = Math.Clamp(firstLine - 1, 0, Math.Max(0, lines.Length - 1));
        var to = Math.Clamp(lastLine - 1, from, lines.Length - 1);
        return string.Join('\n', lines[from..(to + 1)]).TrimEnd();
    }

    private static RoleTask? ParseTask(YamlMappingNode node, string raw, string relativePath)
    {
        var keys = node.Children.Keys.OfType<YamlScalarNode>()
            .Select(k => k.Value ?? "")
            .Where(k => k.Length > 0)
            .ToArray();

        var module = ChooseModule(keys);
        if (module is null) return null;
        if (module.Contains("import_tasks", StringComparison.Ordinal)
            || module.Contains("include_tasks", StringComparison.Ordinal)
            || module.Contains("import_role", StringComparison.Ordinal)
            || module.Contains("include_role", StringComparison.Ordinal))
            return null;

        var name = Scalar(node, "name") ?? $"(unnamed {module} task)";
        var tags = StringList(node, "tags");
        var notify = StringList(node, "notify");
        var whenGuards = StringList(node, "when");

        var ruleIdSource = name + "\n" + string.Join('\n', tags);
        var versionIds = StigVersionToken().Matches(ruleIdSource)
            .Select(m => m.Groups[1].Value.ToUpperInvariant())
            .ToHashSet(StringComparer.Ordinal);
        var ruleIds = RuleIdToken().Matches(ruleIdSource)
            .Select(m => m.Groups[1].Value.ToUpperInvariant())
            .Concat(versionIds)
            .Distinct()
            .ToArray();

        return new RoleTask
        {
            Name = name,
            Module = module,
            Variables = ExtractVariables(raw, whenGuards),
            NotifiedHandlers = notify,
            WhenGuards = whenGuards,
            Tags = tags,
            RuleIds = ruleIds,
            NumericRuleIds = ruleIds.Select(RuleIdentifiers.Numeric).Where(n => n.Length > 0)
                .ToHashSet(StringComparer.Ordinal),
            StigVersionIds = versionIds,
            SourceFile = relativePath,
            SourceLine = (int)node.Start.Line,
            RawYaml = raw,
        };
    }

    /// <summary>
    /// The module is the key that is not a task keyword. Where several qualify, a fully qualified name
    /// (one containing a dot) wins: a role using <c>ansible.builtin.copy</c> alongside a keyword this
    /// indexer has not heard of should still be read correctly.
    /// </summary>
    private static string? ChooseModule(string[] keys)
    {
        var candidates = keys.Where(k => !TaskKeywords.Contains(k)).ToArray();
        if (candidates.Length == 0) return null;
        return candidates.FirstOrDefault(k => k.Contains('.', StringComparison.Ordinal)) ?? candidates[0];
    }

    private static string? Scalar(YamlMappingNode node, string key) =>
        node.Children.TryGetValue(new YamlScalarNode(key), out var value) && value is YamlScalarNode scalar
            ? scalar.Value
            : null;

    /// <summary>
    /// Reads a key that Ansible accepts as either a scalar or a sequence — <c>when</c>, <c>notify</c>, and
    /// <c>tags</c> are all written both ways in the wild.
    /// </summary>
    private static IReadOnlyList<string> StringList(YamlMappingNode node, string key)
    {
        if (!node.Children.TryGetValue(new YamlScalarNode(key), out var value)) return [];
        return value switch
        {
            YamlScalarNode scalar when scalar.Value is { Length: > 0 } s => [s],
            YamlSequenceNode sequence => [.. sequence.Children.OfType<YamlScalarNode>()
                .Select(c => c.Value ?? "")
                .Where(s => s.Length > 0)],
            _ => [],
        };
    }

    private static IReadOnlyList<string> ExtractVariables(string rawYaml, IReadOnlyList<string> whenGuards)
    {
        var ordered = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void Add(string name)
        {
            if (JinjaVocabulary.Contains(name)) return;
            if (seen.Add(name)) ordered.Add(name);
        }

        foreach (Match match in JinjaVariable().Matches(rawYaml))
            Add(match.Groups[1].Value);

        // A `when` guard is a bare expression, not a templated string, so its variables are not inside
        // braces and the Jinja pattern above misses them.
        foreach (var guard in whenGuards)
            foreach (Match match in BareIdentifier().Matches(guard))
                Add(match.Groups[1].Value);

        return ordered;
    }
}
