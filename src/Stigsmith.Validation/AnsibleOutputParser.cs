using System.Text.RegularExpressions;

namespace Stigsmith.Validation;

/// <summary>Counts from an Ansible run's PLAY RECAP.</summary>
public sealed record PlayRecap(int Ok, int Changed, int Unreachable, int Failed, int Skipped, int Rescued, int Ignored)
{
    public bool Clean => Failed == 0 && Unreachable == 0;

    /// <summary>The idempotency requirement: a second apply must change nothing.</summary>
    public bool Idempotent => Clean && Changed == 0;

    public static PlayRecap None => new(0, 0, 0, 0, 0, 0, 0);
}

/// <summary>
/// Reads Ansible's own output rather than trusting its exit code.
/// </summary>
/// <remarks>
/// The exit code alone is not enough for this loop. <c>ansible-playbook</c> exits 0 for a run where every task was
/// skipped, which looks like success and applied nothing — and a skipped task is the most likely way generated
/// remediation silently does nothing, because a <c>when</c> guard referencing an undefined variable skips rather
/// than fails. So the recap is parsed and the loop asserts on it.
/// </remarks>
public static partial class AnsibleOutputParser
{
    /// <summary>
    /// The PLAY RECAP line: <c>localhost : ok=3 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0</c>.
    /// </summary>
    [GeneratedRegex(
        @"ok=(?<ok>\d+)\s+changed=(?<changed>\d+)\s+unreachable=(?<unreachable>\d+)\s+failed=(?<failed>\d+)"
        + @"(?:\s+skipped=(?<skipped>\d+))?(?:\s+rescued=(?<rescued>\d+))?(?:\s+ignored=(?<ignored>\d+))?")]
    private static partial Regex RecapPattern();

    /// <summary>ansible-lint's own summary count, e.g. "Failed: 2 failure(s), 1 warning(s)".</summary>
    [GeneratedRegex(@"Failed:\s*(?<failures>\d+)\s+failure", RegexOptions.IgnoreCase)]
    private static partial Regex LintFailurePattern();

    public static PlayRecap ParseRecap(string output)
    {
        var match = RecapPattern().Match(output ?? "");
        if (!match.Success) return PlayRecap.None;

        int Group(string name) =>
            match.Groups[name].Success && int.TryParse(match.Groups[name].Value, out var v) ? v : 0;

        return new PlayRecap(
            Group("ok"), Group("changed"), Group("unreachable"), Group("failed"),
            Group("skipped"), Group("rescued"), Group("ignored"));
    }

    /// <summary>
    /// Whether a lint run should be treated as a failure.
    /// </summary>
    /// <remarks>
    /// Non-zero exit is the signal, but ansible-lint also exits non-zero for warnings-only runs in some
    /// configurations, and blocking on a warning would reject correct remediation over a naming preference. So a
    /// non-zero exit whose summary explicitly says "0 failure(s)" is treated as a pass, and the full output is kept
    /// as evidence either way.
    /// </remarks>
    public static bool LintPassed(ExecResult result)
    {
        if (result.Succeeded) return true;

        var match = LintFailurePattern().Match(result.Combined);
        return match.Success && match.Groups["failures"].Value == "0";
    }

    /// <summary>
    /// Whether the run actually did something. A run where every task was skipped exits 0 and applied nothing,
    /// which must not count as a successful apply.
    /// </summary>
    public static bool AppliedSomething(PlayRecap recap) => recap.Clean && recap.Ok > 0;
}
