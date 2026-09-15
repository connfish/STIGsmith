using Stigsmith.Checklists.Model;

namespace Stigsmith.Generation.Conventions;

/// <summary>
/// One task from the operator's existing Ansible role, with the metadata that makes it useful as a
/// few-shot example.
/// </summary>
/// <remarks>
/// <see cref="RawYaml"/> is the task exactly as written in the role, sliced out of the source file
/// rather than re-serialized. That matters: what makes retrieval worth doing is that the example carries
/// the house formatting — quoting style, key order, how <c>when</c> is written — and a round trip through
/// a YAML emitter would normalize all of it away and teach the model Stigsmith's conventions instead of
/// the operator's.
/// </remarks>
public sealed record RoleTask
{
    /// <summary>The task's <c>name</c>, or a placeholder when it has none.</summary>
    public required string Name { get; init; }

    /// <summary>The module invoked, fully qualified if the role writes it that way: <c>ansible.builtin.lineinfile</c>.</summary>
    public required string Module { get; init; }

    /// <summary>Variables the task references, in first-seen order: <c>stigsmith_rhel8_faillock_deny</c>.</summary>
    public IReadOnlyList<string> Variables { get; init; } = [];

    /// <summary>Handlers this task notifies, verbatim, so generated tasks notify the same names.</summary>
    public IReadOnlyList<string> NotifiedHandlers { get; init; } = [];

    /// <summary>The task's <c>when</c> conditions, as written.</summary>
    public IReadOnlyList<string> WhenGuards { get; init; } = [];

    public IReadOnlyList<string> Tags { get; init; } = [];

    /// <summary>
    /// STIG rule identifiers this task addresses, derived from its name and tags. Empty when the role
    /// does not label tasks by rule, which is common and is why retrieval cannot rely on it alone.
    /// </summary>
    public IReadOnlyList<string> RuleIds { get; init; } = [];

    /// <summary>The V-number digits of <see cref="RuleIds"/>, for matching across id spellings.</summary>
    public IReadOnlySet<string> NumericRuleIds { get; init; } = new HashSet<string>();

    /// <summary>STIG version ids this task addresses, e.g. <c>RHEL-08-010550</c>.</summary>
    public IReadOnlySet<string> StigVersionIds { get; init; } = new HashSet<string>();

    /// <summary>Path relative to the role root, for citing the example back to the operator.</summary>
    public required string SourceFile { get; init; }

    /// <summary>1-based line of the task's first key in <see cref="SourceFile"/>.</summary>
    public required int SourceLine { get; init; }

    /// <summary>The task verbatim, as it appears in the role.</summary>
    public required string RawYaml { get; init; }

    public string Reference => $"{SourceFile}:{SourceLine}";

    /// <summary>True when this task addresses the given rule, in any of its id spellings.</summary>
    public bool Addresses(RuleContent rule)
    {
        if (rule.RuleVersion is { Length: > 0 } version && StigVersionIds.Contains(version.ToUpperInvariant()))
            return true;
        return rule.NumericId is { Length: > 0 } numeric && NumericRuleIds.Contains(numeric);
    }
}
