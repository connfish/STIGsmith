namespace Stigsmith.Generation.Conventions;

/// <summary>
/// The house style inferred from an indexed role: variable prefix, handler names, tag scheme, module
/// spelling. Stated explicitly in the prompt alongside the few-shot examples.
/// </summary>
/// <remarks>
/// Examples alone leave the model to infer the pattern, and it infers wrong on the things that are only
/// visible across many tasks — that every variable starts with one prefix, that tags always include the
/// STIG version id, that modules are always fully qualified. Naming them costs a few lines of prompt and
/// removes the guesswork.
/// </remarks>
public sealed record RoleConventions
{
    public static readonly RoleConventions None = new();

    /// <summary>The longest prefix shared by most variable names, e.g. <c>stigsmith_rhel8_</c>.</summary>
    public string? VariablePrefix { get; init; }

    /// <summary>Handler names the role defines, verbatim, so generated tasks notify names that exist.</summary>
    public IReadOnlyList<string> HandlerNames { get; init; } = [];

    /// <summary>Modules the role uses, most-used first — the vocabulary to prefer.</summary>
    public IReadOnlyList<string> CommonModules { get; init; } = [];

    /// <summary>True when every module is written fully qualified (<c>ansible.builtin.lineinfile</c>).</summary>
    public bool UsesFullyQualifiedModules { get; init; }

    /// <summary>Tags that are not rule identifiers, e.g. <c>CAT2</c>, <c>medium</c>, <c>sshd</c>.</summary>
    public IReadOnlyList<string> CommonTags { get; init; } = [];

    /// <summary>True when tasks are tagged with their STIG version id, which is what makes retrieval exact.</summary>
    public bool TagsIncludeStigVersionId { get; init; }

    /// <summary>True when tasks are tagged with their V- number.</summary>
    public bool TagsIncludeVulnId { get; init; }

    /// <summary>The per-rule toggle pattern, e.g. <c>stigsmith_rhel8_rule_230296</c>, with the number replaced.</summary>
    public string? RuleToggleTemplate { get; init; }

    /// <summary>Share of tasks carrying a <c>when</c> guard. Near 1.0 means every generated task needs one.</summary>
    public double GuardedTaskShare { get; init; }

    public static RoleConventions Infer(IReadOnlyCollection<RoleTask> tasks)
    {
        if (tasks.Count == 0) return None;

        var variables = tasks.SelectMany(t => t.Variables).ToArray();
        var allTags = tasks.SelectMany(t => t.Tags).ToArray();

        return new RoleConventions
        {
            VariablePrefix = CommonPrefix(variables),
            HandlerNames = [.. tasks.SelectMany(t => t.NotifiedHandlers).Distinct().Order()],
            CommonModules = [.. tasks.GroupBy(t => t.Module)
                .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal)
                .Select(g => g.Key)],
            UsesFullyQualifiedModules = tasks.All(t => t.Module.Contains('.', StringComparison.Ordinal)),
            CommonTags = [.. allTags
                .Where(t => !LooksLikeRuleId(t))
                .GroupBy(t => t, StringComparer.Ordinal)
                .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal)
                .Select(g => g.Key)
                .Take(12)],
            TagsIncludeStigVersionId = tasks.Count(t => t.StigVersionIds.Count > 0) * 2 > tasks.Count,
            TagsIncludeVulnId = tasks.Count(t => t.NumericRuleIds.Count > 0) * 2 > tasks.Count,
            RuleToggleTemplate = InferRuleToggle(tasks),
            GuardedTaskShare = (double)tasks.Count(t => t.WhenGuards.Count > 0) / tasks.Count,
        };
    }

    private static bool LooksLikeRuleId(string tag) =>
        tag.StartsWith("V-", StringComparison.OrdinalIgnoreCase)
        || tag.StartsWith("SV-", StringComparison.OrdinalIgnoreCase)
        || (tag.Count(c => c == '-') >= 2 && tag.Any(char.IsDigit));

    /// <summary>
    /// Share of a role's variables that must carry a prefix before it counts as the house namespace.
    /// </summary>
    /// <remarks>
    /// High on purpose. A majority threshold finds the wrong answer on a role like the example one, where
    /// 16 of 23 variables are per-rule toggles: the majority prefix is <c>stigsmith_rhel8_rule_</c>, which
    /// is a subset convention, not the namespace. At 0.8 only <c>stigsmith_rhel8_</c> qualifies, and the
    /// toggle pattern is reported separately by <see cref="InferRuleToggle"/> — which is the pair of facts
    /// a prompt actually needs. The slack below 1.0 tolerates a handful of loop variables and
    /// <c>register</c> names that never carry the prefix.
    /// </remarks>
    private const double PrefixShareThreshold = 0.8;

    /// <summary>
    /// The longest prefix ending at an underscore that nearly all of the role's variables share.
    /// </summary>
    /// <remarks>
    /// Anchoring to an underscore matters: the raw longest common prefix of
    /// <c>stigsmith_rhel8_rule_230296</c> and <c>stigsmith_rhel8_rule_230244</c> is
    /// <c>stigsmith_rhel8_rule_2302</c>, which is not a convention and would be nonsense in a prompt. Every
    /// candidate is considered as a seed rather than just the first: a role with a short loop variable such
    /// as <c>audit_tool</c> alongside a long house prefix would otherwise cap the search at that variable's
    /// length and report <c>stigsmith_</c>.
    /// </remarks>
    private static string? CommonPrefix(IReadOnlyCollection<string> names)
    {
        var candidates = names.Distinct(StringComparer.Ordinal).ToArray();
        if (candidates.Length < 2) return null;

        var required = candidates.Length * PrefixShareThreshold;
        var best = "";

        foreach (var seed in candidates)
        {
            for (var length = 2; length <= seed.Length; length++)
            {
                if (seed[length - 1] != '_') continue;
                if (length <= best.Length) continue;

                var prefix = seed[..length];
                if (candidates.Count(n => n.StartsWith(prefix, StringComparison.Ordinal)) >= required)
                    best = prefix;
            }
        }

        return best.Length > 1 ? best : null;
    }

    /// <summary>
    /// Finds the per-rule toggle by looking for a guard variable whose trailing digits match one of the
    /// task's own rule numbers, then generalising it to a template.
    /// </summary>
    private static string? InferRuleToggle(IReadOnlyCollection<RoleTask> tasks)
    {
        foreach (var task in tasks.Where(t => t.NumericRuleIds.Count > 0))
        {
            foreach (var guard in task.WhenGuards)
            {
                var trimmed = guard.Trim();
                foreach (var numeric in task.NumericRuleIds)
                {
                    if (!trimmed.EndsWith(numeric, StringComparison.Ordinal)) continue;
                    return trimmed[..^numeric.Length] + "<vuln number>";
                }
            }
        }
        return null;
    }

    /// <summary>The prompt-ready description. Empty when nothing was inferred, so it can be omitted cleanly.</summary>
    public string Describe()
    {
        var lines = new List<string>();
        if (VariablePrefix is { Length: > 0 })
            lines.Add($"- Variables are prefixed `{VariablePrefix}`.");
        if (RuleToggleTemplate is { Length: > 0 })
            lines.Add($"- Each task is guarded by a per-rule toggle named `{RuleToggleTemplate}`.");
        if (UsesFullyQualifiedModules)
            lines.Add("- Modules are always fully qualified (for example `ansible.builtin.lineinfile`).");
        if (CommonModules.Count > 0)
            lines.Add($"- Modules used by this role, most common first: {string.Join(", ", CommonModules.Take(8))}.");
        if (HandlerNames.Count > 0)
            lines.Add($"- Handlers that exist, to notify verbatim: {string.Join(", ", HandlerNames.Select(h => $"`{h}`"))}. Do not invent a handler name.");
        if (TagsIncludeStigVersionId || TagsIncludeVulnId)
        {
            var parts = new List<string>();
            if (TagsIncludeStigVersionId) parts.Add("the STIG version id");
            if (TagsIncludeVulnId) parts.Add("the V- number");
            lines.Add($"- Every task is tagged with {string.Join(" and ", parts)}.");
        }
        if (CommonTags.Count > 0)
            lines.Add($"- Other tags in use: {string.Join(", ", CommonTags)}.");
        if (GuardedTaskShare >= 0.9)
            lines.Add("- Every task in this role carries a `when` guard.");

        return string.Join('\n', lines);
    }
}
