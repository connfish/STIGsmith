using System.Text;
using Stigsmith.Checklists.Model;
using Stigsmith.Generation.Conventions;
using Stigsmith.Generation.Providers;
using Stigsmith.Rules;

namespace Stigsmith.Generation.Prompting;

/// <summary>Everything the model is allowed to see about a generation request.</summary>
/// <remarks>
/// <para>
/// This type is the enforcement point for constraint 3. It accepts a <see cref="RuleContent"/>, which has no
/// host fields on it at all, so there is no hostname, IP, MAC, FQDN, or target comment available to pass —
/// not as a matter of discipline but because the value does not exist in scope. The other half of the
/// guarantee is <c>PromptHygieneTests</c>, which builds prompts from checklists whose host fields carry
/// deliberately distinctive values and asserts none of them appear.
/// </para>
/// <para>
/// One boundary worth being explicit about: the few-shot examples are tasks from the operator's own Ansible
/// role, and if that role hardcodes an inventory hostname, that text does reach the model. That is the
/// operator's own source code, which they chose to point Stigsmith at, and it is not scan data — constraint 3
/// is about the host identifiers and finding detail that arrive with a checklist and are frequently CUI. The
/// distinction is real and is stated in the README rather than papered over.
/// </para>
/// </remarks>
public sealed record RemediationRequest
{
    public required RuleContent Rule { get; init; }

    /// <summary>The OS family the playbook targets, e.g. "Red Hat Enterprise Linux 8".</summary>
    public required string TargetOs { get; init; }

    /// <summary>Existing tasks to imitate. Empty when no convention role is configured.</summary>
    public IReadOnlyList<RetrievedTask> Examples { get; init; } = [];

    public RoleConventions Conventions { get; init; } = RoleConventions.None;

    /// <summary>
    /// True for a high-risk rule. The generated tasks must then work under <c>--check</c>, because the
    /// operator will dry-run them before letting them near a host they could be locked out of.
    /// </summary>
    public bool RequireCheckMode { get; init; }

    public IReadOnlyCollection<RiskDomain> RiskDomains { get; init; } = [];
}

/// <summary>
/// Builds the prompt that turns DISA's prose into Ansible.
/// </summary>
/// <remarks>
/// The prompt's whole job is to keep the model in translation mode. Left to itself, a model asked to "harden
/// SSH" writes a dozen tasks it thinks are good ideas; asked to express one specific documented fix, it
/// writes that fix. Hence the repeated insistence on doing exactly what the fix text says and nothing
/// adjacent, and hence the explicit escape hatch: a model that cannot express the fix idempotently should
/// say so rather than invent something that merely lints.
/// </remarks>
public static class RemediationPromptAssembler
{
    public const string CannotAutomateMarker = "# cannot-automate:";

    private const string SystemPrompt = $"""
        You translate a DISA STIG rule's prescribed fix into Ansible tasks.

        This is a translation task, not a design task. The rule already contains DISA's prescribed fix. Your
        job is to express exactly that fix as idempotent Ansible, changing nothing about what the fix does
        and adding nothing it does not ask for.

        Requirements:
        - Output YAML only: a list of one or more Ansible tasks. No prose, no explanation, no code fence.
        - Do exactly what the fix text says. Do not add related hardening. Do not fix adjacent settings.
          Do not reorder or "improve" the fix.
        - Every task must be idempotent. Running the tasks a second time must report no change.
        - Prefer a real module over `command` or `shell`. Where a command is unavoidable, set `changed_when`
          so the task reports change honestly.
        - Use only modules that exist in ansible.builtin, ansible.posix or community.general. Never invent a
          module.
        - Follow the house conventions given below exactly: variable prefix, tag scheme, module spelling,
          and handler names.
        - Notify only handlers listed as existing. Never invent a handler name.
        - Do not reference any host by name or address. The tasks run against whatever inventory the
          operator targets.
        - If the fix cannot be expressed as idempotent Ansible, output exactly one line starting
          `{CannotAutomateMarker}` followed by the reason, and nothing else. That is a correct answer, and a
          far better one than a task that does the wrong thing.
        """;

    public static RemediationPrompt Assemble(RemediationRequest request)
    {
        var user = new StringBuilder();

        user.AppendLine("## Target");
        user.AppendLine($"Operating system: {request.TargetOs}");
        if (request.RequireCheckMode)
        {
            var domains = request.RiskDomains.Count > 0
                ? string.Join(", ", request.RiskDomains.Select(d => d.ToToken()))
                : "high-risk";
            user.AppendLine(
                $"This rule is high-risk ({domains}): a mistake can lock an operator out of the host. The tasks "
                + "must run correctly under `ansible-playbook --check` without failing, so the operator can "
                + "dry-run them first.");
        }
        user.AppendLine();

        user.AppendLine("## Rule");
        user.AppendLine($"Rule ID: {request.Rule.RuleId}");
        if (request.Rule.RuleVersion is { Length: > 0 })
            user.AppendLine($"STIG version: {request.Rule.RuleVersion}");
        user.AppendLine($"Severity: {request.Rule.Severity.ToCategory()} ({request.Rule.Severity.ToToken()})");
        user.AppendLine($"Title: {request.Rule.Title}");
        user.AppendLine();

        user.AppendLine("### Fix text to translate");
        user.AppendLine(Trim(request.Rule.FixText));
        user.AppendLine();

        if (request.Rule.CheckContent is { Length: > 0 })
        {
            user.AppendLine("### How this will be verified");
            user.AppendLine(
                "This is the procedure that will be re-run after your tasks are applied. Your tasks must make "
                + "this check pass.");
            user.AppendLine();
            user.AppendLine(Trim(request.Rule.CheckContent));
            user.AppendLine();
        }

        var conventions = request.Conventions.Describe();
        if (conventions.Length > 0)
        {
            user.AppendLine("## House conventions");
            user.AppendLine("Match these exactly. They are what make the output fit the operator's existing role.");
            user.AppendLine();
            user.AppendLine(conventions);
            user.AppendLine();
        }

        user.AppendLine("## Existing tasks from this role");
        if (request.Examples.Count > 0)
        {
            user.AppendLine(
                "Imitate the style of these. They are real tasks from the role this output will join, so match "
                + "their structure, naming, and formatting.");
            user.AppendLine();

            foreach (var example in request.Examples)
            {
                var label = example.Kind == MatchKind.SameRule
                    ? "already implements this rule"
                    : $"similar, uses {example.Task.Module}";
                user.AppendLine($"### {example.Task.Reference} ({label})");
                user.AppendLine("```yaml");
                user.AppendLine(example.Task.RawYaml);
                user.AppendLine("```");
                user.AppendLine();
            }
        }
        else
        {
            user.AppendLine(
                "None available — no convention role is configured. Write plain, idiomatic Ansible using fully "
                + "qualified module names.");
            user.AppendLine();
        }

        user.AppendLine("## Output");
        user.Append("YAML only: the Ansible tasks that apply the fix above. No fence, no commentary.");

        return new RemediationPrompt(SystemPrompt, user.ToString());
    }

    /// <summary>
    /// Builds the one repair prompt, given the tool output that rejected the previous attempt.
    /// </summary>
    /// <remarks>
    /// The error goes in verbatim and uncommented. A summarised error loses the line number and the rule id that
    /// ansible-lint actually complained about, which is the only part that tells the model what to change. The
    /// previous attempt goes in too, so this is an edit rather than a fresh guess — a regenerated-from-scratch
    /// answer tends to make a different mistake instead of fixing this one.
    /// </remarks>
    public static RemediationPrompt AssembleRepair(
        RemediationRequest request, string previousYaml, string failedStage, string errorOutput)
    {
        var original = Assemble(request);

        var user = new StringBuilder(original.User);
        user.AppendLine();
        user.AppendLine();
        user.AppendLine("## Your previous attempt failed");
        user.AppendLine($"It was rejected at the {failedStage} stage. This is what you produced:");
        user.AppendLine();
        user.AppendLine("```yaml");
        user.AppendLine(previousYaml.Trim());
        user.AppendLine("```");
        user.AppendLine();
        user.AppendLine("This is the tool output, verbatim:");
        user.AppendLine();
        user.AppendLine("```");
        user.AppendLine(Truncate(errorOutput.Trim(), 4000));
        user.AppendLine("```");
        user.AppendLine();
        user.AppendLine("## Output");
        user.Append(
            "Fix the specific problem the output names and return the corrected tasks. Change as little as possible: "
            + "edit the previous attempt rather than starting again. YAML only, no fence, no commentary. If the fix "
            + $"genuinely cannot be expressed as idempotent Ansible, say so with `{CannotAutomateMarker}` instead.");

        return new RemediationPrompt(original.System, user.ToString());
    }

    /// <summary>
    /// Keeps the head and tail of long tool output. An ansible failure puts the useful line at the end and the task
    /// context at the start, so cutting only the tail would throw away the error itself.
    /// </summary>
    private static string Truncate(string text, int max)
    {
        if (text.Length <= max) return text;
        var half = max / 2;
        return text[..half] + "\n\n... (output truncated) ...\n\n" + text[^half..];
    }

    /// <summary>
    /// Normalizes line endings and collapses runs of blank lines. DISA text arrives with inconsistent
    /// spacing, and three blank lines between paragraphs is prompt budget spent on nothing.
    /// </summary>
    private static string Trim(string text)
    {
        var result = new List<string>();
        var blank = false;

        foreach (var raw in text.ReplaceLineEndings("\n").Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.Length == 0)
            {
                if (!blank && result.Count > 0) result.Add("");
                blank = true;
                continue;
            }
            blank = false;
            result.Add(line);
        }

        while (result.Count > 0 && result[^1].Length == 0) result.RemoveAt(result.Count - 1);
        return string.Join('\n', result);
    }
}
