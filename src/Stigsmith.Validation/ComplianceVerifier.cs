using System.Text.RegularExpressions;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Validation;

/// <summary>What a verification attempt concluded about one rule.</summary>
public sealed record VerificationResult(
    ComplianceVerifierKind Kind,
    string Status,
    string Command,
    ExecResult Output)
{
    /// <summary>The only status that lets a remediation be called validated.</summary>
    public bool Passed => Status.Equals("pass", StringComparison.OrdinalIgnoreCase);

    public static VerificationResult NotVerified(string why) =>
        new(ComplianceVerifierKind.None, "unknown", "", new ExecResult(-1, "", why));
}

/// <summary>
/// Re-checks whether a rule passes, inside the sandbox, after remediation has been applied.
/// </summary>
/// <remarks>
/// <para>
/// Step 3 of the loop, and the one that makes the rest mean anything: lint and a clean apply only prove the YAML
/// ran, not that it fixed the finding.
/// </para>
/// <para>
/// Two strategies, and which one ran is recorded, because they are not worth the same:
/// </para>
/// <list type="number">
/// <item><b>oscap</b> — a real SCAP scan of that one rule against an installed datastream. The primary path, and
/// the one the milestone asks for.</item>
/// <item><b>check content</b> — DISA's own verification command, extracted from the rule's <c>check content</c> and
/// run as a shell test. Used when oscap has no definition for the rule, which covers both synthetic fixtures and
/// the many real STIG rules whose manual benchmark carries a command but no OVAL.</item>
/// </list>
/// <para>
/// An ISSO reading the evidence needs to know which produced the verdict, so <see cref="VerificationResult.Kind"/>
/// is part of the record rather than an implementation detail.
/// </para>
/// </remarks>
public sealed partial class ComplianceVerifier(ValidationOptions options)
{
    /// <summary>
    /// A command line in DISA check content. They are written as <c>$ sudo grep -i permitrootlogin /etc/…</c> or with
    /// a bare <c>#</c> prompt.
    /// </summary>
    [GeneratedRegex(@"^[ \t]*[$#][ \t]+(?<command>\S.*)$", RegexOptions.Multiline)]
    private static partial Regex PromptedCommand();

    public async Task<VerificationResult> VerifyAsync(
        IValidationSession session, RuleContent rule, CancellationToken cancellationToken = default)
    {
        if (options.PreferOscap)
        {
            var oscap = await TryOscapAsync(session, rule, cancellationToken);
            if (oscap is not null) return oscap;
        }

        return await VerifyByCheckContentAsync(session, rule, cancellationToken);
    }

    /// <summary>
    /// Runs <c>oscap xccdf eval</c> for this one rule. Returns null when oscap or the datastream is unavailable, or
    /// when the datastream has no definition for the rule — all of which mean "use the other strategy", not "the
    /// rule failed".
    /// </summary>
    private async Task<VerificationResult?> TryOscapAsync(
        IValidationSession session, RuleContent rule, CancellationToken cancellationToken)
    {
        var probe = await session.ExecAsync(
            $"command -v oscap >/dev/null 2>&1 && test -f {options.ScapDatastreamPath} && echo ready",
            cancellationToken);
        if (!probe.Stdout.Contains("ready", StringComparison.Ordinal)) return null;

        // The rule id in an SSG datastream is the XCCDF-wrapped form.
        var ruleId = $"xccdf_mil.disa.stig_rule_{rule.RuleId}";
        var command =
            $"oscap xccdf eval --profile {options.ScapProfile} --rule {ruleId} "
            + $"--results /tmp/stigsmith-results.xml {options.ScapDatastreamPath} 2>&1 || true";

        var result = await session.ExecAsync(command, cancellationToken);
        var status = ParseOscapStatus(result.Combined);

        // "notchecked" or "notselected" means oscap had nothing to say about this rule, so fall through rather than
        // recording a verdict oscap did not give.
        if (status is null or "notchecked" or "notselected") return null;

        return new VerificationResult(ComplianceVerifierKind.Oscap, status, command, result);
    }

    /// <summary>
    /// Runs the command DISA's check content prescribes, and treats a zero exit as pass.
    /// </summary>
    /// <remarks>
    /// Deliberately conservative. Only a read-only prompted command is run, <c>sudo</c> is stripped (the container
    /// runs as root and a minimal image has no sudo), and check content with no runnable command yields "unknown"
    /// rather than a guess. A wrong pass here would be worse than no verification, because it would be evidence of
    /// something that did not happen.
    /// </remarks>
    private async Task<VerificationResult> VerifyByCheckContentAsync(
        IValidationSession session, RuleContent rule, CancellationToken cancellationToken)
    {
        var command = ExtractCheckCommand(rule.CheckContent);
        if (command is null)
            return VerificationResult.NotVerified(
                "The rule's check content contains no runnable read-only command, and oscap had no definition for "
                + "it. This remediation cannot be automatically verified.");

        var result = await session.ExecAsync(command, cancellationToken);
        return new VerificationResult(
            ComplianceVerifierKind.CheckContent,
            result.Succeeded ? "pass" : "fail",
            command,
            result);
    }

    /// <summary>Pulls the first runnable read-only command out of DISA check content, or null when there is none.</summary>
    public static string? ExtractCheckCommand(string? checkContent)
    {
        if (string.IsNullOrWhiteSpace(checkContent)) return null;

        foreach (Match match in PromptedCommand().Matches(checkContent))
        {
            var command = match.Groups["command"].Value.Trim();

            if (command.StartsWith("sudo ", StringComparison.Ordinal)) command = command[5..].TrimStart();
            if (command.Length == 0) continue;

            // Refuse anything that would change the system. A verification step that remediates would make the
            // re-scan pass by its own action, which is the most dangerous possible bug in this loop.
            if (LooksMutating(command)) continue;

            return command;
        }

        return null;
    }

    /// <summary>
    /// Whether this <em>invocation</em> would modify the system.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Check content is overwhelmingly read-only, but some rules quote the fix command alongside the check. Running
    /// that here would let the verifier remediate the finding itself and then report a pass — the most dangerous
    /// possible bug in this loop — so anything mutating is refused and the rule reports as unverifiable instead.
    /// </para>
    /// <para>
    /// Judged per invocation rather than per binary. An earlier version listed bare binary names, which refused
    /// <c>fips-mode-setup --check</c> and <c>firewall-cmd --list-all</c> — both read-only — and so reported "cannot
    /// verify" for rules that are perfectly verifiable. Only the binaries that mutate however they are called are
    /// matched by name; the rest are matched by the sub-command or flag that does the mutating.
    /// </para>
    /// </remarks>
    private static bool LooksMutating(string command)
    {
        var lower = command.ToLowerInvariant();

        // Any redirection writes a file, whatever the command is. This is also why `echo` and `printf` need no entry.
        if (lower.Contains('>')) return true;

        // Binaries with no read-only mode worth the risk.
        string[] alwaysMutating =
        [
            "chmod", "chown", "chgrp", "chcon", "restorecon", "semanage", "setsebool",
            "useradd", "usermod", "userdel", "groupadd", "chage", "authconfig",
            "touch", "mkdir", "truncate", "tee ", "install ", "sed -i", "rpm -i", "rpm -e", "rpm -U",
        ];
        if (alwaysMutating.Any(m => lower.Contains(m, StringComparison.Ordinal))) return true;

        if (lower.StartsWith("rm", StringComparison.Ordinal)
            || lower.StartsWith("mv", StringComparison.Ordinal)
            || lower.StartsWith("cp", StringComparison.Ordinal)) return true;

        // Binaries that read or write depending on the sub-command. Matched on the mutating form only, so the
        // read-only forms -- fips-mode-setup --check, firewall-cmd --list-all, grubby --info, nmcli device status --
        // stay usable as verification commands.
        string[] mutatingInvocations =
        [
            "yum install", "yum remove", "yum update", "yum upgrade",
            "dnf install", "dnf remove", "dnf update", "dnf upgrade",
            "systemctl enable", "systemctl disable", "systemctl start", "systemctl stop",
            "systemctl restart", "systemctl reload", "systemctl mask", "systemctl unmask", "systemctl set-",
            "sysctl -w", "sysctl --write", "sysctl --system", "sysctl -p",
            "fips-mode-setup --enable", "fips-mode-setup --disable",
            "firewall-cmd --add", "firewall-cmd --remove", "firewall-cmd --set-", "firewall-cmd --reload",
            "firewall-cmd --permanent --add", "firewall-cmd --permanent --set-",
            "authselect select", "authselect apply-changes", "authselect enable-feature",
            "dconf update", "dconf write",
            "augenrules --load", "auditctl -w", "auditctl -a",
            "grubby --update-kernel", "grubby --remove-args", "grubby --set-default",
            "grub2-mkconfig", "grub2-setpassword", "grub2-editenv - set",
            "nmcli radio", "nmcli connection modify", "nmcli connection up", "nmcli connection down",
            "nmcli device connect", "nmcli device disconnect",
            "postconf -e", "fapolicyd-cli --update", "passwd -l", "passwd -u", "passwd --lock",
            "update-crypto-policies --set", "aide --init", "aide --update",
            "ansible-playbook", "pip install", "pip3 install",
        ];
        return mutatingInvocations.Any(m => lower.Contains(m, StringComparison.Ordinal));
    }

    /// <summary>Reads the per-rule verdict oscap prints, e.g. "Result\tfail" or "Result: pass".</summary>
    public static string? ParseOscapStatus(string output)
    {
        string[] statuses =
            ["pass", "fail", "notapplicable", "notchecked", "notselected", "error", "unknown", "fixed"];

        foreach (var line in (output ?? "").ReplaceLineEndings("\n").Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("Result", StringComparison.OrdinalIgnoreCase)) continue;

            var value = trimmed["Result".Length..].TrimStart(':', '\t', ' ').Trim().ToLowerInvariant();
            if (statuses.Contains(value)) return value;
        }

        return null;
    }
}
