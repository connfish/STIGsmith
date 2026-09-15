using Stigsmith.Validation;

namespace Stigsmith.Tests.Validation;

public class AnsibleOutputParserTests
{
    private const string Recap =
        "PLAY RECAP *********************************************************************\n"
        + "localhost                  : ok=3    changed=1    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0";

    [Fact]
    public void Reads_the_play_recap()
    {
        var recap = AnsibleOutputParser.ParseRecap(Recap);

        recap.Ok.ShouldBe(3);
        recap.Changed.ShouldBe(1);
        recap.Failed.ShouldBe(0);
        recap.Skipped.ShouldBe(2);
        recap.Clean.ShouldBeTrue();
        recap.Idempotent.ShouldBeFalse();
    }

    [Fact]
    public void A_second_apply_with_no_changes_is_idempotent()
    {
        var recap = AnsibleOutputParser.ParseRecap(
            "localhost : ok=3    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0");

        recap.Idempotent.ShouldBeTrue();
    }

    [Fact]
    public void A_failed_task_is_not_clean()
    {
        AnsibleOutputParser.ParseRecap(
            "localhost : ok=1    changed=0    unreachable=0    failed=1    skipped=0")
            .Clean.ShouldBeFalse();
    }

    [Fact]
    public void An_unreachable_host_is_not_clean()
    {
        AnsibleOutputParser.ParseRecap(
            "localhost : ok=0    changed=0    unreachable=1    failed=0    skipped=0")
            .Clean.ShouldBeFalse();
    }

    [Fact]
    public void Handles_older_output_without_the_trailing_counters()
    {
        var recap = AnsibleOutputParser.ParseRecap("localhost : ok=2 changed=1 unreachable=0 failed=0");

        recap.Ok.ShouldBe(2);
        recap.Changed.ShouldBe(1);
        recap.Skipped.ShouldBe(0);
    }

    [Fact]
    public void Output_with_no_recap_yields_nothing_rather_than_a_false_pass()
    {
        var recap = AnsibleOutputParser.ParseRecap("ERROR! the playbook could not be parsed");

        recap.ShouldBe(PlayRecap.None);
        recap.Clean.ShouldBeTrue();
        // Clean but with ok=0, so AppliedSomething is false -- which is what the loop actually asserts on.
        AnsibleOutputParser.AppliedSomething(recap).ShouldBeFalse();
    }

    /// <summary>
    /// The failure this guards against: ansible-playbook exits 0 for a run where every task was skipped. Trusting the
    /// exit code would record a pass for remediation that touched nothing.
    /// </summary>
    [Fact]
    public void A_run_where_everything_was_skipped_did_not_apply_anything()
    {
        var recap = AnsibleOutputParser.ParseRecap(
            "localhost : ok=0    changed=0    unreachable=0    failed=0    skipped=4    rescued=0    ignored=0");

        recap.Clean.ShouldBeTrue();
        AnsibleOutputParser.AppliedSomething(recap).ShouldBeFalse();
    }

    [Fact]
    public void Lint_passes_on_a_zero_exit()
    {
        AnsibleOutputParser.LintPassed(new ExecResult(0, "Passed: 0 failure(s), 0 warning(s)", ""))
            .ShouldBeTrue();
    }

    [Fact]
    public void Lint_fails_when_it_reports_failures()
    {
        AnsibleOutputParser.LintPassed(
            new ExecResult(2, "Failed: 2 failure(s), 1 warning(s)", "")).ShouldBeFalse();
    }

    /// <summary>
    /// ansible-lint exits non-zero for warnings-only runs in some configurations. Blocking there would reject correct
    /// remediation over a naming preference.
    /// </summary>
    [Fact]
    public void Lint_passes_on_a_warnings_only_run_that_exits_non_zero()
    {
        AnsibleOutputParser.LintPassed(
            new ExecResult(2, "Failed: 0 failure(s), 3 warning(s)", "")).ShouldBeTrue();
    }
}

public class ComplianceVerifierTests
{
    [Fact]
    public void Extracts_the_first_prompted_command_and_strips_sudo()
    {
        var command = ComplianceVerifier.ExtractCheckCommand("""
            Verify remote access using SSH prevents users from logging on directly as "root":

            $ sudo grep -i permitrootlogin /etc/ssh/sshd_config
            PermitRootLogin no

            If the keyword is set to any other value, this is a finding.
            """);

        command.ShouldBe("grep -i permitrootlogin /etc/ssh/sshd_config");
    }

    [Fact]
    public void Accepts_a_root_prompt_as_well_as_a_dollar_prompt()
    {
        ComplianceVerifier.ExtractCheckCommand("Check it:\n\n# sestatus | grep -i 'loaded policy'\n")
            .ShouldBe("sestatus | grep -i 'loaded policy'");
    }

    [Fact]
    public void Check_content_with_no_command_yields_nothing_rather_than_a_guess()
    {
        ComplianceVerifier.ExtractCheckCommand(
            "Ask the System Administrator for the training records. The ISSO will verify they exist.")
            .ShouldBeNull();
        ComplianceVerifier.ExtractCheckCommand("").ShouldBeNull();
        ComplianceVerifier.ExtractCheckCommand(null).ShouldBeNull();
    }

    /// <summary>
    /// The most dangerous possible bug in the loop: a verification step that remediates would make the re-scan pass by
    /// its own action and produce evidence of something that never happened.
    /// </summary>
    [Theory]
    [InlineData("$ sudo yum install firewalld")]
    [InlineData("$ sudo systemctl enable --now rsyslog")]
    [InlineData("$ sudo chmod 0600 /var/log/audit/audit.log")]
    [InlineData("$ sudo sysctl --system")]
    [InlineData("$ sudo grubby --update-kernel=ALL --args=audit=1")]
    [InlineData("$ sudo fips-mode-setup --enable")]
    [InlineData("$ sudo firewall-cmd --permanent --set-target=DROP")]
    [InlineData("$ echo 'PermitRootLogin no' > /etc/ssh/sshd_config")]
    [InlineData("$ sudo sed -i 's/yes/no/' /etc/ssh/sshd_config")]
    [InlineData("$ sudo rm /etc/ssh/shosts.equiv")]
    public void A_mutating_command_is_never_used_for_verification(string checkContent)
    {
        ComplianceVerifier.ExtractCheckCommand($"Verify it:\n\n{checkContent}\n").ShouldBeNull();
    }

    /// <summary>
    /// Judged per invocation, not per binary. An earlier version matched bare binary names and so refused
    /// <c>fips-mode-setup --check</c>, reporting "cannot verify" for rules that are perfectly verifiable.
    /// </summary>
    [Theory]
    [InlineData("$ sudo fips-mode-setup --check", "fips-mode-setup --check")]
    [InlineData("$ sudo firewall-cmd --list-all", "firewall-cmd --list-all")]
    [InlineData("$ sudo firewall-cmd --state", "firewall-cmd --state")]
    [InlineData("$ sudo grubby --info=ALL", "grubby --info=ALL")]
    [InlineData("$ sudo nmcli device status", "nmcli device status")]
    [InlineData("$ sudo systemctl is-enabled rsyslog", "systemctl is-enabled rsyslog")]
    [InlineData("$ sudo sysctl fs.protected_symlinks", "sysctl fs.protected_symlinks")]
    [InlineData("$ sudo yum list installed policycoreutils", "yum list installed policycoreutils")]
    [InlineData("$ sudo stat -c \"%a %n\" /var/log/audit", "stat -c \"%a %n\" /var/log/audit")]
    public void A_read_only_invocation_of_a_mutating_binary_is_usable(string checkContent, string expected)
    {
        ComplianceVerifier.ExtractCheckCommand($"Verify it:\n\n{checkContent}\n").ShouldBe(expected);
    }

    /// <summary>Skips past a mutating command to find a read-only one later in the same check content.</summary>
    [Fact]
    public void Finds_a_read_only_command_after_a_mutating_one()
    {
        var command = ComplianceVerifier.ExtractCheckCommand("""
            First apply the setting:

            $ sudo sysctl --system

            Then verify it:

            $ sudo sysctl net.ipv4.conf.all.rp_filter
            net.ipv4.conf.all.rp_filter = 1
            """);

        command.ShouldBe("sysctl net.ipv4.conf.all.rp_filter");
    }

    [Theory]
    [InlineData("Title\nResult\tpass\n", "pass")]
    [InlineData("Result: fail", "fail")]
    [InlineData("Result   notapplicable  ", "notapplicable")]
    [InlineData("Rule\tsomething\nResult\tnotchecked", "notchecked")]
    public void Reads_the_oscap_verdict(string output, string expected)
    {
        ComplianceVerifier.ParseOscapStatus(output).ShouldBe(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Result\tsomething-unexpected")]
    [InlineData("no result line at all")]
    public void Unrecognised_oscap_output_yields_no_verdict(string output)
    {
        ComplianceVerifier.ParseOscapStatus(output).ShouldBeNull();
    }
}

public class PlaybookBuilderTests
{
    [Fact]
    public void Wraps_tasks_in_a_play_targeting_the_container_itself()
    {
        var playbook = PlaybookBuilder.Build(
            "- name: Root SSH\n  ansible.builtin.lineinfile:\n    path: /etc/ssh/sshd_config\n",
            "RHEL-08-010550");

        playbook.ShouldStartWith("---");
        playbook.ShouldContain("hosts: localhost");
        playbook.ShouldContain("connection: local");
        playbook.ShouldContain("become: true");
        playbook.ShouldContain("gather_facts: false");
        playbook.ShouldContain("# Rule: RHEL-08-010550");
        // The tasks are indented under `tasks:`, so the result is a valid play rather than a task list.
        playbook.ShouldContain("  tasks:\n    - name: Root SSH");
    }

    /// <summary>
    /// No hostname reaches the playbook: the sandbox is the target, so there is no inventory and nothing to name.
    /// One fewer place a host identifier could appear.
    /// </summary>
    [Fact]
    public void The_play_names_no_host()
    {
        var playbook = PlaybookBuilder.Build("- name: x\n  ansible.builtin.debug:\n    msg: y\n");

        playbook.ShouldNotContain("example.test");
        playbook.ShouldNotContain("192.0.2.");
        playbook.ShouldContain("hosts: localhost");
    }

    /// <summary>
    /// Generated tasks reference the operator's per-rule toggle. Without a vars file they would skip as undefined, and
    /// the loop would report "applied nothing" against correct Ansible.
    /// </summary>
    [Fact]
    public void Supplies_defaults_for_referenced_variables()
    {
        var vars = PlaybookBuilder.BuildVarsFile(
            ["stigsmith_rhel8_rule_230296", "stigsmith_rhel8_sshd_config_path"],
            new Dictionary<string, string> { ["stigsmith_rhel8_sshd_config_path"] = "/etc/ssh/sshd_config" });

        vars.ShouldStartWith("---");
        vars.ShouldContain("stigsmith_rhel8_rule_230296: true");
        vars.ShouldContain("stigsmith_rhel8_sshd_config_path: /etc/ssh/sshd_config");
    }

    [Fact]
    public void Deduplicates_and_orders_variables_so_the_file_is_stable()
    {
        var vars = PlaybookBuilder.BuildVarsFile(["b_var", "a_var", "b_var"]);

        vars.ShouldBe("---\na_var: true\nb_var: true\n");
    }
}
