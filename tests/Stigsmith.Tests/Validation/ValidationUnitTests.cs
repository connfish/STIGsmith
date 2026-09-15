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

    /// <summary>
    /// A second apply that never ran its tasks proves nothing. Before this check an apply that crashed before its recap
    /// parsed as "0 changed" and passed the idempotency stage.
    /// </summary>
    [Fact]
    public void A_run_with_no_recap_or_nothing_ok_is_not_idempotent()
    {
        AnsibleOutputParser.ParseRecap("ERROR! The requested handler 'restart sshd' was not found").Idempotent.ShouldBeFalse();
        AnsibleOutputParser.ParseRecap("ERROR! nope").RanNothing.ShouldBeTrue();
        AnsibleOutputParser.ParseRecap("localhost : ok=0    changed=0    unreachable=0    failed=0    skipped=1")
            .Idempotent.ShouldBeFalse();
        AnsibleOutputParser.ParseRecap("localhost : ok=2    changed=0    unreachable=0    failed=0    skipped=0")
            .Idempotent.ShouldBeTrue();
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
    // The forms a deny-list never anticipates: interpreters, chaining, substitution, and binaries it had not heard of.
    [InlineData("$ sudo python3 -c \"import os; os.remove('/etc/ssh/shosts.equiv')\"")]
    [InlineData("$ sudo grep -i permitrootlogin /etc/ssh/sshd_config; rm -f /etc/ssh/shosts.equiv")]
    [InlineData("$ sudo grep -i permitrootlogin /etc/ssh/sshd_config && touch /etc/ssh/shosts.equiv")]
    [InlineData("$ sudo cat $(echo /etc/shadow)")]
    [InlineData("$ sudo cat `echo /etc/shadow`")]
    [InlineData("$ sudo cat \"$(echo /etc/shadow)\"")]
    [InlineData("$ sudo dd if=/dev/zero of=/etc/ssh/sshd_config")]
    [InlineData("$ sudo ln -sf /dev/null /etc/ssh/shosts.equiv")]
    [InlineData("$ sudo find /etc/ssh -name shosts.equiv -delete")]
    [InlineData("$ sudo find /etc/ssh -name shosts.equiv -exec rm {} \\;")]
    [InlineData("$ sudo crontab -r")]
    [InlineData("$ sudo auditctl -w /etc/shadow -p wa -k identity")]
    [InlineData("$ sudo semanage port -a -t ssh_port_t -p tcp 2222")]
    [InlineData("$ sudo faillock --user bob --reset")]
    [InlineData("$ sudo awk '{system(\"rm /etc/ssh/shosts.equiv\")}' /etc/passwd")]
    [InlineData("$ sudo xargs rm < /tmp/list")]
    [InlineData("$ sudo sleep 5 &")]
    // Quoting a flag hides it from a naive token check but not from the shell: these reach the binary as bare flags.
    [InlineData("$ sudo iptables -L '-F'")]
    [InlineData("$ sudo iptables -L $'-F'")]
    [InlineData("$ sudo iptables -L \"-F\"")]
    [InlineData("$ sudo openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/k.pem $'-out' /etc/cron.d/x -subj /CN=x")]
    [InlineData("$ sudo ip $'add' addr 10.0.0.1/24 dev eth0")]
    [InlineData("$ sudo ip \"add\" addr 10.0.0.1/24 dev eth0")]
    [InlineData("$ sudo cat \"$HOME/.ssh/id_rsa\"")]
    [InlineData("$ sudo cat ${HOME}/x")]
    [InlineData("$ sudo (grep x /etc/passwd)")]
    [InlineData("$ sudo grep x /etc/passwd < /etc/shadow")]
    [InlineData("$ sudo grep 'unbalanced /etc/passwd")]
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
    // The shapes real DISA check content takes: pipelines, silenced stderr, quoted regexes, awk field programs.
    [InlineData("$ sudo grep -i '^\\s*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'", "grep -i '^\\s*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'")]
    [InlineData("$ sudo grep -E '^(banner|Banner)' /etc/ssh/sshd_config", "grep -E '^(banner|Banner)' /etc/ssh/sshd_config")]
    [InlineData("$ sudo awk -F: '$3 == 0 {print $1}' /etc/passwd", "awk -F: '$3 == 0 {print $1}' /etc/passwd")]
    [InlineData("$ sudo find / -perm -4000 -type f 2>/dev/null", "find / -perm -4000 -type f 2>/dev/null")]
    [InlineData("$ sudo find -L /lib /lib64 -perm /022 -type f -exec ls -l {} \\;", "find -L /lib /lib64 -perm /022 -type f -exec ls -l {} \\;")]
    [InlineData("$ sudo rpm -qa | grep telnet-server", "rpm -qa | grep telnet-server")]
    [InlineData("$ sudo semanage port -l | grep ssh", "semanage port -l | grep ssh")]
    [InlineData("$ sudo auditctl -l | grep /etc/shadow", "auditctl -l | grep /etc/shadow")]
    [InlineData("$ sudo faillock --user bob", "faillock --user bob")]
    [InlineData("$ sudo test -f /etc/stigsmith-marker", "test -f /etc/stigsmith-marker")]
    [InlineData("$ sudo systemctl status auditd 2>&1 | head -3", "systemctl status auditd 2>&1 | head -3")]
    [InlineData("$ sudo ip addr show", "ip addr show")]
    [InlineData("$ sudo iptables -L INPUT -n", "iptables -L INPUT -n")]
    [InlineData("$ sudo find / -name \"*.pem\" -type f", "find / -name \"*.pem\" -type f")]
    [InlineData("$ sudo grep -i \"^\\\\s*banner\" /etc/ssh/sshd_config", "grep -i \"^\\\\s*banner\" /etc/ssh/sshd_config")]
    [InlineData("$ sudo grep -r maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf", "grep -r maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf")]
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
        // The bytes oscap 1.3 really emits: a carriage return before the tab.
        ComplianceVerifier.ParseOscapStatus(output.Replace("\t", "\r\t")).ShouldBe(expected);
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

    [Fact]
    public void A_vars_file_with_no_variables_is_an_empty_mapping_not_an_empty_document()
    {
        // `-e @vars.yml` on an empty document makes ansible-playbook print its usage and exit, which looked like a
        // syntax failure of every rule that referenced no variables.
        PlaybookBuilder.BuildVarsFile([]).ShouldBe("--- {}\n");
    }
}

public class ValidationEvidenceJsonTests
{
    [Fact]
    public void Round_trips_through_json()
    {
        var evidence = new ValidationEvidence
        {
            Outcome = ValidationOutcome.Failed,
            FailedStage = ValidationStage.Rescan,
            ContainerImage = "stigsmith/validation:el8",
            VerifiedBy = ComplianceVerifierKind.CheckContent,
            Summary = "The playbook applied cleanly but the rule still reports 'fail' after remediation.",
            Stages = [new StageEvidence(ValidationStage.Lint, true, "ansible-lint playbook.yml", 0, "Passed", TimeSpan.FromSeconds(1.5))],
        };

        var parsed = ValidationEvidence.FromJson(evidence.ToJson())!;

        parsed.Outcome.ShouldBe(ValidationOutcome.Failed);
        parsed.FailedStage.ShouldBe(ValidationStage.Rescan);
        parsed.VerifiedBy.ShouldBe(ComplianceVerifierKind.CheckContent);
        parsed.Summary.ShouldBe(evidence.Summary);
        parsed.Stage(ValidationStage.Lint)!.Duration.ShouldBe(TimeSpan.FromSeconds(1.5));
    }

    [Fact]
    public void Unreadable_evidence_is_null_rather_than_an_exception()
    {
        ValidationEvidence.FromJson("{}").ShouldBeNull();
        ValidationEvidence.FromJson("not json").ShouldBeNull();
    }
}

/// <summary>
/// Reading check content the way an assessor does. Each case is a shape that a live run showed the exit-code reading
/// getting wrong: a commented default line passing, a negative check read backwards, find exiting zero on nothing.
/// </summary>
public class CheckSpecTests
{
    private const string PermitRootLogin =
        "Verify remote access using SSH prevents users from logging on directly as \"root\" with the following command:\n\n"
        + "$ sudo grep -i permitrootlogin /etc/ssh/sshd_config\nPermitRootLogin no\n\n"
        + "If the \"PermitRootLogin\" keyword is set to \"yes\", this is a finding.";

    private const string TelnetServer =
        "Check to see if the telnet-server package is installed with the following command:\n\n"
        + "$ sudo yum list installed telnet-server\n\nIf the telnet-server package is installed, this is a finding.";

    private const string Policycoreutils =
        "Verify the operating system has the policycoreutils package installed with the following command:\n\n"
        + "$ sudo yum list installed policycoreutils\npolicycoreutils.x86_64       2.9-9.el8       @anaconda\n\n"
        + "If the policycoreutils package is not installed, this is a finding.";

    private static ExecResult Out(string stdout, int exit = 0) => new(exit, stdout, "");

    [Fact]
    public void Shown_output_becomes_the_expectation()
    {
        var spec = ComplianceVerifier.ExtractCheck(PermitRootLogin)!;

        spec.Command.ShouldBe("grep -i permitrootlogin /etc/ssh/sshd_config");
        spec.Polarity.ShouldBe(CheckPolarity.ExpectedOutput);
        spec.ExpectedLines.ShouldBe(["PermitRootLogin no"]);
    }

    [Fact]
    public void A_finding_sentence_with_no_shown_output_reads_output_as_the_finding()
    {
        ComplianceVerifier.ExtractCheck(TelnetServer)!.Polarity.ShouldBe(CheckPolarity.Negative);
    }

    [Fact]
    public void Illustrative_output_is_not_an_expectation_and_a_negated_sentence_is_not_negative()
    {
        var spec = ComplianceVerifier.ExtractCheck(Policycoreutils)!;

        spec.ExpectedLines.ShouldBeEmpty();
        spec.Polarity.ShouldBe(CheckPolarity.ExitCode);
    }

    [Fact]
    public void Prose_directly_under_the_command_is_not_output()
    {
        var spec = ComplianceVerifier.ExtractCheck("$ sudo sestatus\nIf SELinux is not enforcing, this is a finding.")!;

        spec.ExpectedLines.ShouldBeEmpty();
        spec.Polarity.ShouldBe(CheckPolarity.ExitCode);
    }

    [Fact]
    public void A_commented_default_line_is_not_compliance()
    {
        var spec = ComplianceVerifier.ExtractCheck(PermitRootLogin)!;

        ComplianceVerifier.Judge(spec, Out("#PermitRootLogin yes")).Status.ShouldBe("fail");
        ComplianceVerifier.Judge(spec, Out("PermitRootLogin yes")).Status.ShouldBe("fail");
        ComplianceVerifier.Judge(spec, Out("#PermitRootLogin yes\nPermitRootLogin no")).Status.ShouldBe("pass");
        // grep over several files prefixes the path; case and spacing are the operator's business.
        ComplianceVerifier.Judge(spec, Out("/etc/ssh/sshd_config:permitrootlogin   NO")).Status.ShouldBe("pass");
        ComplianceVerifier.Judge(spec, Out("", exit: 1)).Reason.ShouldContain("does not contain 'PermitRootLogin no'");
    }

    [Fact]
    public void A_negative_check_passes_when_the_command_finds_nothing()
    {
        var spec = ComplianceVerifier.ExtractCheck(TelnetServer)!;

        ComplianceVerifier.Judge(spec, Out("", exit: 1)).Status.ShouldBe("pass");
        ComplianceVerifier.Judge(spec, Out("Installed Packages\ntelnet-server.x86_64 0.17-76.el8 @baseos")).Status.ShouldBe("fail");
    }

    [Fact]
    public void Find_exiting_zero_with_nothing_found_is_not_a_pass()
    {
        var spec = ComplianceVerifier.ExtractCheck("$ sudo find / -name aide.conf\n\nIf there is no application installed, this is a finding.")!;

        spec.Polarity.ShouldBe(CheckPolarity.ExitCode);
        ComplianceVerifier.Judge(spec, Out("")).Status.ShouldBe("fail");
        ComplianceVerifier.Judge(spec, Out("/etc/aide.conf")).Status.ShouldBe("pass");
    }

    [Fact]
    public void A_check_that_could_not_run_is_unknown_not_fail()
    {
        var spec = ComplianceVerifier.ExtractCheck(PermitRootLogin)!;

        ComplianceVerifier.Judge(spec, new ExecResult(127, "", "sh: grep: command not found")).Status.ShouldBe("unknown");
        ComplianceVerifier.Judge(spec, new ExecResult(2, "", "grep: /etc/ssh/sshd_config: No such file or directory")).Status.ShouldBe("unknown");
    }
}
