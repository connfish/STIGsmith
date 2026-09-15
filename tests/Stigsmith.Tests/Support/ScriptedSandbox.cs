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

    public string Image => "scripted/validation:test";

    public bool Available { get; set; } = true;

    /// <summary>ansible-lint rejects the playbook.</summary>
    public bool LintFails { get; set; }

    /// <summary>--syntax-check rejects the playbook.</summary>
    public bool SyntaxFails { get; set; }

    /// <summary>The apply reports a failed task.</summary>
    public bool ApplyFails { get; set; }

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

    public List<string> Commands { get; } = [];

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
        ApplyChangesNothing = false;
        RescanNeverPasses = false;
        NotIdempotent = false;
        CheckModeFails = false;
        NoVerifierAvailable = false;
        Commands.Clear();
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

        public string ContainerId => "scripted-container";

        public Task WriteFileAsync(string path, string content, CancellationToken cancellationToken = default)
        {
            if (path.EndsWith("playbook.yml", StringComparison.Ordinal)) _tasks = content;
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
                return Ok("");

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
                if (owner.ApplyFails)
                    return Fail(2, Recap(ok: 0, changed: 0, failed: 1));

                if (owner.ApplyChangesNothing)
                    // Exit 0 with everything skipped: the most dangerous shape, because it looks like success.
                    return Ok(Recap(ok: 0, changed: 0, failed: 0, skipped: 1));

                var firstApply = !_applied;
                _applied = true;
                var changed = firstApply || owner.NotIdempotent ? 1 : 0;
                return Ok(Recap(ok: 1, changed: changed, failed: 0));
            }

            // Anything else is the verifier running DISA's check command.
            if (owner.NoVerifierAvailable) return Fail(127, "sh: command not found");
            return _applied && !owner.RescanNeverPasses
                ? Ok("PermitRootLogin no")
                : Fail(1, "");
        }

        public ValueTask DisposeAsync()
        {
            owner.SessionsDisposed++;
            return ValueTask.CompletedTask;
        }

        private static Task<ExecResult> Ok(string stdout) => Task.FromResult(new ExecResult(0, stdout, ""));

        private static Task<ExecResult> Fail(int code, string output) =>
            Task.FromResult(new ExecResult(code, output, ""));

        private static string Recap(int ok, int changed, int failed, int skipped = 0) =>
            $"PLAY RECAP *********************************************************************\n"
            + $"localhost                  : ok={ok}    changed={changed}    unreachable=0    failed={failed}    "
            + $"skipped={skipped}    rescued=0    ignored=0";
    }
}
