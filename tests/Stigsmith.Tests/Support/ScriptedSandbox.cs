using Stigsmith.Checklists;
using Stigsmith.Validation;

namespace Stigsmith.Tests.Support;

/// <summary>
/// A sandbox that models a coherent little world instead of a real container.
/// </summary>
/// <remarks>
/// <para>
/// The validation loop's decisions — which stage failed, whether to repair, when to give up and ask a human, what
/// evidence to keep — are the part worth testing exhaustively, and they can be tested on a machine with no container
/// runtime. So this fake is not a stub returning canned strings: it tracks whether remediation has been applied, so
/// the verifier legitimately fails before and passes after, and the second apply legitimately reports no change.
/// A fake that always said "pass" would test nothing.
/// </para>
/// <para>
/// It says nothing about whether the real Docker path works. That has not been run — see DECISIONS.md.
/// </para>
/// </remarks>
public sealed class ScriptedSandbox : IValidationSandbox
{
    /// <summary>Tasks YAML containing this marker behaves as broken remediation.</summary>
    public const string BrokenMarker = "STIGSMITH_BROKEN";

    /// <summary>
    /// What a compliant host answers to each fixture rule's check, read from the check content itself, so the
    /// scripted world agrees with the verifier about what "pass" looks like: the shown output after remediation, a
    /// commented default line before it (which exits zero and must not count), and nothing at all for a check whose
    /// result would be the finding.
    /// </summary>
    private static readonly Lazy<Dictionary<string, CheckSpec>> FixtureChecks = new(() =>
        ChecklistIo.ReadFile(TestEnvironment.FixturePath("ckl", "rhel8-host-alpha.ckl")).Findings
            .Select(f => (f.Rule.RuleVersion, Spec: ComplianceVerifier.ExtractCheck(f.Rule.CheckContent)))
            .Where(p => p.Spec is not null && p.RuleVersion.Length > 0)
            .ToDictionary(p => p.RuleVersion, p => p.Spec!, StringComparer.OrdinalIgnoreCase));

    public string Image => "scripted/validation:test";

    public bool Available { get; set; } = true;

    /// <summary>ansible-lint rejects the playbook.</summary>
    public bool LintFails { get; set; }

    /// <summary>--syntax-check rejects the playbook.</summary>
    public bool SyntaxFails { get; set; }

    /// <summary>The apply reports a failed task.</summary>
    public bool ApplyFails { get; set; }

    /// <summary>The apply never returns, so only the per-rule timeout can end it.</summary>
    public bool ApplyHangs { get; set; }

    /// <summary>The second apply dies before printing a recap, as ansible does for a missing handler.</summary>
    public bool SecondApplyCrashes { get; set; }

    /// <summary>The apply succeeds but every task is skipped, so nothing is remediated.</summary>
    public bool ApplyChangesNothing { get; set; }

    /// <summary>The apply succeeds but the finding still fails afterwards — the fix does not fix it.</summary>
    public bool RescanNeverPasses { get; set; }

    /// <summary>Every apply reports a change, so the playbook is not idempotent.</summary>
    public bool NotIdempotent { get; set; }

    /// <summary>The playbook fails under --check, so a high-risk rule cannot be dry-run.</summary>
    public bool CheckModeFails { get; set; }

    /// <summary>Set when the check content command should be treated as unrunnable, as for a policy rule.</summary>
    public bool NoVerifierAvailable { get; set; }

    /// <summary>oscap and a datastream that knows the rule are present, so verification is a real SCAP scan.</summary>
    public bool OscapKnowsTheRule { get; set; }

    public List<string> Commands { get; } = [];

    /// <summary>Every file written into the container, by path, so a test can check what the play was given.</summary>
    public Dictionary<string, string> Files { get; } = [];

    public int SessionsStarted { get; private set; }

    public int SessionsDisposed { get; private set; }

    /// <summary>
    /// Restores every knob to its default. The API tests share one fixture, so a test that steers a failure has to hand
    /// the sandbox back in a clean state or it silently changes the next test's world.
    /// </summary>
    public void Reset()
    {
        Available = true;
        LintFails = false;
        SyntaxFails = false;
        ApplyFails = false;
        ApplyHangs = false;
        SecondApplyCrashes = false;
        ApplyChangesNothing = false;
        RescanNeverPasses = false;
        NotIdempotent = false;
        CheckModeFails = false;
        NoVerifierAvailable = false;
        OscapKnowsTheRule = false;
        Commands.Clear();
        Files.Clear();
    }

    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default) => Task.FromResult(Available);

    public Task<IValidationSession> StartAsync(CancellationToken cancellationToken = default)
    {
        SessionsStarted++;
        return Task.FromResult<IValidationSession>(new Session(this));
    }

    private sealed class Session(ScriptedSandbox owner) : IValidationSession
    {
        private bool _applied;
        private string _tasks = "";
        private string? _ruleVersion;

        public string ContainerId => "scripted-container";

        public Task WriteFileAsync(string path, string content, CancellationToken cancellationToken = default)
        {
            owner.Files[path] = content;
            if (path.EndsWith("playbook.yml", StringComparison.Ordinal))
            {
                _tasks = content;
                _ruleVersion = content.Split('\n').FirstOrDefault(l => l.StartsWith("# Rule: ", StringComparison.Ordinal))?["# Rule: ".Length..].Trim();
            }
            return Task.CompletedTask;
        }

        public Task<ExecResult> ExecAsync(string command, CancellationToken cancellationToken = default)
        {
            owner.Commands.Add(command);
            var broken = _tasks.Contains(BrokenMarker, StringComparison.Ordinal);

            if (command.Contains("mkdir", StringComparison.Ordinal))
                return Ok("");

            if (command.Contains("ansible-lint", StringComparison.Ordinal))
                return owner.LintFails || broken
                    ? Fail(2, "syntax-check[unknown-module]: couldn't resolve module/action 'nonsense'\nFailed: 1 failure(s), 0 warning(s)")
                    : Ok("Passed: 0 failure(s), 0 warning(s)");

            if (command.Contains("--syntax-check", StringComparison.Ordinal))
                return owner.SyntaxFails
                    ? Fail(4, "ERROR! conflicting action statements: ansible.builtin.lineinfile, ansible.builtin.copy")
                    : Ok("playbook: playbook.yml");

            // The verifier's probe for oscap. Reporting it absent sends the loop down the check-content path, which is
            // what a machine without the SCAP datastream would really do.
            if (command.Contains("command -v oscap", StringComparison.Ordinal))
                return Ok(owner.OscapKnowsTheRule ? "ready" : "");

            // The DISA id to SSG rule id lookup, then the scan itself, in the shapes the real tools produce.
            if (command.StartsWith("xmllint --xpath", StringComparison.Ordinal))
                return Ok("xccdf_org.ssgproject.content_rule_scripted_rule\n");
            if (command.StartsWith("oscap xccdf eval", StringComparison.Ordinal))
                return Ok($"Title\tScripted rule\nRule\txccdf_org.ssgproject.content_rule_scripted_rule\nResult\t{(_applied ? "pass" : "fail")}\n");

            // Matched on ansible-playbook as well as the flag: a verification command can legitimately carry
            // --check of its own (fips-mode-setup --check), and routing that here would have the fake report a
            // playbook dry-run for what is really a read-only status query.
            if (command.Contains("ansible-playbook", StringComparison.Ordinal)
                && command.Contains("--check", StringComparison.Ordinal))
                return owner.CheckModeFails
                    ? Fail(2, Recap(ok: 0, changed: 0, failed: 1))
                    : Ok(Recap(ok: 1, changed: 1, failed: 0));

            if (command.Contains("ansible-playbook", StringComparison.Ordinal))
            {
                if (owner.ApplyHangs)
                    return Hang(cancellationToken);

                if (owner.ApplyFails)
                    return Fail(2, Recap(ok: 0, changed: 0, failed: 1));

                if (owner.ApplyChangesNothing)
                    // Exit 0 with everything skipped: the most dangerous shape, because it looks like success.
                    return Ok(Recap(ok: 0, changed: 0, failed: 0, skipped: 1));

                var firstApply = !_applied;
                if (!firstApply && owner.SecondApplyCrashes)
                    return Fail(4, "ERROR! The requested handler 'restart sshd' was not found in either the main handlers list nor in the listening handlers list");
                _applied = true;
                var changed = firstApply || owner.NotIdempotent ? 1 : 0;
                return Ok(Recap(ok: 1, changed: changed, failed: 0));
            }

            // Anything else is the verifier running DISA's check command.
            if (owner.NoVerifierAvailable) return Fail(127, "sh: command not found");
            var compliant = _applied && !owner.RescanNeverPasses;
            if (_ruleVersion is not null && FixtureChecks.Value.TryGetValue(_ruleVersion, out var check))
                return check.Polarity switch
                {
                    // Before remediation the stock file has the setting commented out: exit zero, no compliance.
                    CheckPolarity.ExpectedOutput => Ok(compliant ? string.Join('\n', check.ExpectedLines) : "# " + check.ExpectedLines[0]),
                    CheckPolarity.Negative => Ok(compliant ? "" : "telnet-server.x86_64  0.17-76.el8  @baseos"),
                    _ => compliant ? Ok("compliant") : Fail(1, ""),
                };
            return compliant ? Ok("PermitRootLogin no") : Fail(1, "");
        }

        public ValueTask DisposeAsync()
        {
            owner.SessionsDisposed++;
            return ValueTask.CompletedTask;
        }

        private static Task<ExecResult> Ok(string stdout) => Task.FromResult(new ExecResult(0, stdout, ""));

        private static async Task<ExecResult> Hang(CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }

        private static Task<ExecResult> Fail(int code, string output) =>
            Task.FromResult(new ExecResult(code, output, ""));

        private static string Recap(int ok, int changed, int failed, int skipped = 0) =>
            $"PLAY RECAP *********************************************************************\n"
            + $"localhost                  : ok={ok}    changed={changed}    unreachable=0    failed={failed}    "
            + $"skipped={skipped}    rescued=0    ignored=0";
    }
}
