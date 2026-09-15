using Microsoft.Extensions.Logging.Abstractions;
using Stigsmith.Checklists.Model;
using Stigsmith.Tests.Support;
using Stigsmith.Validation;
using Stigsmith.Validation.Docker;
using Xunit;

namespace Stigsmith.Tests.Validation;

/// <summary>
/// The real Docker path, end to end in a real container.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are the only tests that exercise <see cref="DockerValidationSandbox"/> at all, and they have never run:
/// the machine this was built on has no container runtime.</b> Treat that code as unrun until this suite has passed
/// somewhere. It is the single largest caveat in the repository and it is repeated in PROGRESS.md.
/// </para>
/// <para>
/// The first two tests need only a container runtime and use the fallback image, so they verify the sandbox
/// plumbing — start, write a file, exec, capture both streams, remove the container. The full-loop test additionally
/// needs the validation image built (<c>docker build -t stigsmith/validation:el8 docker/validation</c>) and skips
/// with an explanation when it is absent, because without ansible inside the container the loop can only report a
/// lint failure.
/// </para>
/// </remarks>
public class DockerSandboxTests(ITestOutputHelper output)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void SkipWithoutDocker() =>
        Assert.SkipUnless(TestEnvironment.HasDocker, "No container runtime is available.");

    private static ValidationOptions Options() => new()
    {
        // The fallback is a plain image, enough to prove the sandbox plumbing works.
        Image = "stigsmith/validation:el8",
        FallbackImage = "almalinux:8",
        PerRuleTimeout = TimeSpan.FromMinutes(5),
    };

    private static DockerValidationSandbox Sandbox(ValidationOptions? options = null) =>
        new(options ?? Options(), NullLogger<DockerValidationSandbox>.Instance);

    [Fact]
    public async Task Starts_a_container_runs_a_command_and_removes_it()
    {
        SkipWithoutDocker();
        using var sandbox = Sandbox();
        Assert.SkipUnless(await sandbox.IsAvailableAsync(Ct), "Docker is installed but the daemon is not reachable.");

        string containerId;
        await using (var session = await sandbox.StartAsync(Ct))
        {
            containerId = session.ContainerId;
            containerId.ShouldNotBeNullOrWhiteSpace();

            var echo = await session.ExecAsync("echo hello-from-sandbox", Ct);
            echo.ExitCode.ShouldBe(0);
            echo.Stdout.ShouldContain("hello-from-sandbox");

            // A non-zero exit is data, not an exception: the loop reads exit codes as stage results.
            var failing = await session.ExecAsync("exit 3", Ct);
            failing.ExitCode.ShouldBe(3);

            // Both streams are captured, because tool errors arrive on stderr.
            var stderr = await session.ExecAsync("echo oops 1>&2", Ct);
            stderr.Combined.ShouldContain("oops");
        }

        output.WriteLine($"container {containerId[..12]} started and removed");
    }

    [Fact]
    public async Task Writes_a_file_into_the_container()
    {
        SkipWithoutDocker();
        using var sandbox = Sandbox();
        Assert.SkipUnless(await sandbox.IsAvailableAsync(Ct), "Docker is installed but the daemon is not reachable.");

        await using var session = await sandbox.StartAsync(Ct);

        const string content = "- name: a task\n  ansible.builtin.debug:\n    msg: hello\n";
        await session.WriteFileAsync("/tmp/stigsmith/nested/playbook.yml", content, Ct);

        var read = await session.ExecAsync("cat /tmp/stigsmith/nested/playbook.yml", Ct);
        read.ExitCode.ShouldBe(0);
        read.Stdout.ShouldContain("ansible.builtin.debug");
        read.Stdout.Trim().ShouldBe(content.Trim());
    }

    /// <summary>
    /// The whole loop against a real container: lint, syntax check, apply, re-scan, prove idempotent. The rule is a
    /// simple file-content change, chosen because it is the shape a container can genuinely validate — a kernel or
    /// systemd rule cannot apply in an unprivileged container and would fail for reasons that say nothing about the
    /// generated Ansible.
    /// </summary>
    [Fact]
    public async Task Validates_a_real_remediation_in_a_real_container()
    {
        SkipWithoutDocker();
        var options = Options();
        using var sandbox = Sandbox(options);
        Assert.SkipUnless(await sandbox.IsAvailableAsync(Ct), "Docker is installed but the daemon is not reachable.");

        await using (var probe = await sandbox.StartAsync(Ct))
        {
            var ansible = await probe.ExecAsync("command -v ansible-playbook && command -v ansible-lint", Ct);
            Assert.SkipUnless(ansible.ExitCode == 0,
                "The validation image is not built. Run: docker build -t stigsmith/validation:el8 docker/validation");
        }

        var rule = new RuleContent
        {
            RuleId = "SV-999100r1_rule",
            GroupId = "V-999100",
            RuleVersion = "TEST-08-000100",
            Title = "The banner file must contain the approved text.",
            Severity = Severity.Medium,
            FixText = "Set the contents of \"/etc/issue\" to the approved banner text.",
            // Read-only, and true only after remediation has run.
            CheckContent = "Verify the banner text:\n\n$ sudo grep -q 'APPROVED BANNER' /etc/issue\n",
        };

        var validator = new RemediationValidator(
            sandbox, new ComplianceVerifier(options), options, NullLogger<RemediationValidator>.Instance);

        var attempts = await validator.ValidateAsync(
            new ValidationRequest
            {
                Rule = rule,
                TasksYaml = """
                    - name: "TEST-08-000100 | PATCH | Approved banner text"
                      ansible.builtin.copy:
                        dest: /etc/issue
                        content: |
                          APPROVED BANNER
                        owner: root
                        group: root
                        mode: "0644"
                      when:
                        - stigsmith_rhel8_rule_999100
                    """,
                ReferencedVariables = ["stigsmith_rhel8_rule_999100"],
            },
            cancellationToken: Ct);

        var evidence = attempts[^1];
        output.WriteLine(evidence.Summary);
        foreach (var stage in evidence.Stages)
            output.WriteLine($"  {stage.Stage,-14} passed={stage.Passed} exit={stage.ExitCode} ({stage.Duration.TotalSeconds:F1}s)");

        evidence.Outcome.ShouldBe(ValidationOutcome.Passed, evidence.Summary);
        evidence.ScanStatusBefore.ShouldBe("fail");
        evidence.ScanStatusAfter.ShouldBe("pass");
        evidence.IdempotencyChangedCount.ShouldBe(0);
    }

    /// <summary>
    /// Non-idempotent remediation, caught in a real container. A `command` task with no `changed_when` reports a change
    /// every run, which is the most common way generated Ansible fails this stage.
    /// </summary>
    [Fact]
    public async Task Catches_non_idempotent_remediation_in_a_real_container()
    {
        SkipWithoutDocker();
        var options = Options();
        using var sandbox = Sandbox(options);
        Assert.SkipUnless(await sandbox.IsAvailableAsync(Ct), "Docker is installed but the daemon is not reachable.");

        await using (var probe = await sandbox.StartAsync(Ct))
        {
            var ansible = await probe.ExecAsync("command -v ansible-playbook && command -v ansible-lint", Ct);
            Assert.SkipUnless(ansible.ExitCode == 0, "The validation image is not built.");
        }

        var rule = new RuleContent
        {
            RuleId = "SV-999101r1_rule",
            GroupId = "V-999101",
            RuleVersion = "TEST-08-000101",
            Title = "The marker file must exist.",
            FixText = "Create the marker file.",
            CheckContent = "Verify it:\n\n$ sudo test -f /etc/stigsmith-marker\n",
        };

        var validator = new RemediationValidator(
            sandbox, new ComplianceVerifier(options), options, NullLogger<RemediationValidator>.Instance);

        var attempts = await validator.ValidateAsync(
            new ValidationRequest
            {
                Rule = rule,
                // No changed_when, so it reports a change on every run.
                TasksYaml = """
                    - name: "TEST-08-000101 | PATCH | Marker file"
                      ansible.builtin.command: touch /etc/stigsmith-marker
                    """,
            },
            cancellationToken: Ct);

        output.WriteLine(attempts[^1].Summary);
        attempts[^1].Outcome.ShouldNotBe(ValidationOutcome.Passed);
    }
}
