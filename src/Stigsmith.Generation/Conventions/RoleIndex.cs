using System.Text.RegularExpressions;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Generation.Conventions;

/// <summary>Why a task was retrieved, so an operator can tell a real match from a lexical coincidence.</summary>
public enum MatchKind
{
    /// <summary>The task is tagged or named with this exact rule. The strongest possible signal.</summary>
    SameRule,

    /// <summary>Lexically similar to the rule's title and fix text.</summary>
    Similar,
}

public sealed record RetrievedTask(RoleTask Task, double Score, MatchKind Kind, string Reason);

/// <summary>
/// One of the role's own variable files, verbatim. The validation sandbox hands these to ansible-playbook as they
/// are, so the values generated tasks reference (<c>{{ stigsmith_rhel8_sshd_config_path }}</c>) are the operator's
/// real ones rather than placeholders. <see cref="Names"/> is the file's top-level keys, so the placeholder file can
/// leave those out.
/// </summary>
public sealed record RoleVarsFile(string RelativePath, string Content, IReadOnlySet<string> Names);

/// <summary>
/// An indexed role: its tasks, its inferred conventions, and lexical retrieval over them.
/// </summary>
/// <remarks>
/// <para>
/// Retrieval is <b>BM25 over task text</b>, not embeddings. Decided this way because:
/// </para>
/// <list type="bullet">
/// <item>The strongest signal is an exact identifier match — roles label tasks with the STIG version id
/// or V- number — and exact matching is what lexical search is best at and what embeddings blur.</item>
/// <item>It needs no model at index time. Constraint 4's target environments are air-gapped, and an index
/// that cannot be built until a model is warm is an index that fails at the worst moment.</item>
/// <item>It is explainable. "Retrieved because the task name shares `sshd_config` and `lineinfile`" is
/// something an operator can check; a cosine distance is not.</item>
/// <item>The corpus is a role, so hundreds of tasks. Nothing here needs approximate nearest neighbours.</item>
/// </list>
/// <para>
/// The trade is real: BM25 will miss a task that solves the same problem in different words —
/// "harden the SSH daemon" against a rule phrased "must not permit direct logons". Embeddings via the
/// local model are the upgrade path if measurement shows that mattering; the retrieval interface does not
/// change, only the scorer.
/// </para>
/// </remarks>
public sealed partial class RoleIndex
{
    // Okapi BM25 defaults. Not tuned: tuning them against a 16-task synthetic role would be fitting
    // noise, and the ranking is dominated by exact identifier matches anyway.
    private const double K1 = 1.2;
    private const double B = 0.75;

    private Dictionary<string, List<Posting>>? _postings;
    private double _averageLength;

    public string RolePath { get; init; } = "";
    public IReadOnlyList<RoleTask> Tasks { get; init; } = [];
    public IReadOnlyList<string> SkippedFiles { get; init; } = [];
    public RoleConventions Conventions { get; init; } = RoleConventions.None;

    /// <summary><c>defaults/</c> then <c>vars/</c>, in Ansible's precedence order.</summary>
    public IReadOnlyList<RoleVarsFile> VarsFiles { get; init; } = [];

    /// <summary>Every handler the role defines or notifies, so the sandbox can stub them by name.</summary>
    public IReadOnlyList<string> HandlerNames => [.. Tasks
        .Where(t => t.SourceFile.StartsWith("handlers", StringComparison.Ordinal))
        .Select(t => t.Name)
        .Concat(Conventions.HandlerNames)
        .Distinct(StringComparer.Ordinal)
        .Order(StringComparer.Ordinal)];

    /// <summary>Why the index is empty, when it is. Surfaced to the operator rather than failing silently.</summary>
    public string? UnavailableReason { get; init; }

    public bool IsEmpty => Tasks.Count == 0;

    public static RoleIndex Empty(string reason) => new() { UnavailableReason = reason };

    [GeneratedRegex(@"[A-Za-z0-9_.\-]+")]
    private static partial Regex TokenPattern();

    /// <summary>
    /// English and Ansible filler that appears in nearly every task and rule, so it separates nothing.
    /// Kept short: an over-aggressive stop list throws away signal, and BM25's IDF already discounts
    /// common terms.
    /// </summary>
    private static readonly HashSet<string> StopWords = new(StringComparer.Ordinal)
    {
        "the", "and", "must", "with", "for", "that", "this", "not", "are", "from", "its", "have",
        "following", "command", "file", "line", "set", "configure", "verify", "value", "system",
        "operating", "patch", "rhel",
    };

    /// <summary>
    /// Retrieves the closest existing tasks to use as few-shot examples.
    /// </summary>
    /// <remarks>
    /// A task addressing the same rule is always returned first, whatever BM25 thinks: if the role already
    /// implements this rule, that implementation is the answer, and the model's job becomes matching it
    /// rather than inventing something. Remaining slots are filled by lexical similarity.
    /// </remarks>
    public IReadOnlyList<RetrievedTask> Retrieve(RuleContent rule, int count = 3)
    {
        if (IsEmpty || count <= 0) return [];

        var results = new List<RetrievedTask>();
        var taken = new HashSet<string>(StringComparer.Ordinal);

        foreach (var task in Tasks.Where(t => t.Addresses(rule)))
        {
            if (!taken.Add(task.Reference)) continue;
            results.Add(new RetrievedTask(task, double.PositiveInfinity, MatchKind.SameRule,
                $"This role already implements {rule.RuleVersion} in {task.Reference}."));
            if (results.Count == count) return results;
        }

        foreach (var (task, score) in ScoreAll(QueryTokens(rule)))
        {
            if (score <= 0) break;
            if (!taken.Add(task.Reference)) continue;
            results.Add(new RetrievedTask(task, score, MatchKind.Similar,
                $"Similar to {task.Reference} (uses {task.Module})."));
            if (results.Count == count) break;
        }

        return results;
    }

    /// <summary>All tasks scored against a rule, best first. Exposed for the relevance tests and for debugging a bad retrieval.</summary>
    public IReadOnlyList<(RoleTask Task, double Score)> ScoreAll(RuleContent rule) => ScoreAll(QueryTokens(rule));

    private IReadOnlyList<(RoleTask Task, double Score)> ScoreAll(IReadOnlyList<string> queryTokens)
    {
        EnsurePostings();

        var scores = new double[Tasks.Count];
        foreach (var term in queryTokens)
        {
            if (!_postings!.TryGetValue(term, out var postings)) continue;

            // Standard Okapi IDF, floored at zero so a term present in most tasks cannot push scores
            // negative and rank an unrelated task above a related one.
            var idf = Math.Max(0, Math.Log(1 + (Tasks.Count - postings.Count + 0.5) / (postings.Count + 0.5)));
            if (idf == 0) continue;

            foreach (var posting in postings)
            {
                var tf = posting.Frequency;
                var norm = 1 - B + B * (posting.Length / _averageLength);
                scores[posting.TaskIndex] += idf * (tf * (K1 + 1)) / (tf + K1 * norm);
            }
        }

        return [.. scores
            .Select((score, i) => (Task: Tasks[i], Score: score))
            .OrderByDescending(p => p.Score)
            .ThenBy(p => p.Task.Reference, StringComparer.Ordinal)];
    }

    private void EnsurePostings()
    {
        if (_postings is not null) return;

        var postings = new Dictionary<string, List<Posting>>(StringComparer.Ordinal);
        var totalLength = 0;

        for (var i = 0; i < Tasks.Count; i++)
        {
            var tokens = Tokenize(DocumentText(Tasks[i]));
            totalLength += tokens.Count;

            foreach (var group in tokens.GroupBy(t => t, StringComparer.Ordinal))
            {
                if (!postings.TryGetValue(group.Key, out var list))
                    postings[group.Key] = list = [];
                list.Add(new Posting(i, group.Count(), tokens.Count));
            }
        }

        _averageLength = Tasks.Count == 0 ? 1 : Math.Max(1.0, (double)totalLength / Tasks.Count);
        _postings = postings;
    }

    /// <summary>
    /// What gets indexed per task. The module name is repeated because it is the single most useful
    /// discriminator — a rule whose fix sets a sysctl should retrieve the role's sysctl tasks — and one
    /// mention of it competes with a dozen words of task name.
    /// </summary>
    private static string DocumentText(RoleTask task) => string.Join('\n',
        task.Name, task.Name,
        task.Module, task.Module, task.Module,
        string.Join(' ', task.Tags),
        string.Join(' ', task.Variables),
        string.Join(' ', task.NotifiedHandlers),
        task.RawYaml);

    /// <summary>
    /// The query side. Title and fix text describe what has to change; the identifiers let an
    /// exactly-labelled task win on lexical score too, not only through the same-rule path.
    /// </summary>
    private static IReadOnlyList<string> QueryTokens(RuleContent rule) => Tokenize(string.Join('\n',
        rule.Title, rule.Title,
        rule.RuleVersion,
        rule.GroupId,
        rule.FixText));

    private static List<string> Tokenize(string text)
    {
        var tokens = new List<string>();
        foreach (Match match in TokenPattern().Matches(text.ToLowerInvariant()))
        {
            var token = match.Value.Trim('.', '-', '_');
            if (token.Length < 2 || StopWords.Contains(token)) continue;
            tokens.Add(token);

            // A dotted or hyphenated token also contributes its parts, so `ansible.builtin.lineinfile`
            // matches a query saying only `lineinfile`, and `net.ipv4.conf.all.rp_filter` matches
            // `rp_filter`. Without this, FQCN-style roles score near zero against plain fix text.
            if (token.IndexOfAny(['.', '-']) < 0) continue;
            foreach (var part in token.Split(['.', '-'], StringSplitOptions.RemoveEmptyEntries))
                if (part.Length >= 2 && !StopWords.Contains(part))
                    tokens.Add(part);
        }
        return tokens;
    }

    private readonly record struct Posting(int TaskIndex, int Frequency, int Length);
}
