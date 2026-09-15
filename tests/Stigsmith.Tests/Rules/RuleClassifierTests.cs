using Stigsmith.Checklists.Model;
using Stigsmith.Rules;

namespace Stigsmith.Tests.Rules;

/// <summary>
/// Policy tests written from the classifier's stated rules, using rules authored here rather than taken
/// from the fixture catalog.
/// </summary>
/// <remarks>
/// These are deliberately independent of <c>fixtures/expectations/rhel8-classification.json</c>. That
/// answer key was authored alongside the rule catalog and corrected several times while the heuristics
/// were being written (see DECISIONS.md), so agreement with it is weaker evidence than it looks. These
/// cases are the held-out set: if a future change to the signal tables games the fixture, it still has
/// to satisfy the policy here.
/// </remarks>
public class RuleClassifierTests
{
    private static RuleContent Rule(string title, string fix, string check = "") => new()
    {
        RuleId = "SV-000001r1_rule",
        GroupId = "V-000001",
        RuleVersion = "TEST-00-000001",
        Title = title,
        FixText = fix,
        CheckContent = check,
    };

    // --- Step 1: nothing to translate ---

    [Fact]
    public void No_fix_text_is_needs_review()
    {
        var result = RuleClassifier.Classify(Rule("A rule with no fix", fix: "", check: "Check something."));

        result.Automatability.ShouldBe(Automatability.NeedsReview);
        result.Reason.ShouldContain("no fix text");
    }

    [Fact]
    public void No_fix_text_but_a_human_check_procedure_is_manual()
    {
        var result = RuleClassifier.Classify(Rule(
            "A documentation rule",
            fix: "   ",
            check: "The ISSO will verify that the procedure is documented."));

        result.Automatability.ShouldBe(Automatability.Manual);
    }

    // --- Step 2: the fix is a human action ---

    [Theory]
    [InlineData("Document the procedure for monitoring remote access and obtain ISSO approval.")]
    [InlineData("Develop a contingency plan for the system, test it annually, and obtain ISSO approval.")]
    [InlineData("The ISSO will document and obtain written approval for any deviation.")]
    [InlineData("Relocate the system to a controlled access area meeting the physical security requirements.")]
    public void A_documentation_or_policy_fix_is_manual(string fix)
    {
        RuleClassifier.Classify(Rule("Policy rule", fix)).Automatability.ShouldBe(Automatability.Manual);
    }

    /// <summary>
    /// "Ask the System Administrator" in check content is how DISA words a verification step. It must not
    /// make an otherwise-automatable rule manual, or most of the RHEL 8 STIG would classify as manual.
    /// </summary>
    [Fact]
    public void A_human_verification_step_does_not_by_itself_make_the_fix_manual()
    {
        var result = RuleClassifier.Classify(Rule(
            "SSH root logon",
            fix: "Edit the \"/etc/ssh/sshd_config\" file and set the value to \"no\":\n\nPermitRootLogin no",
            check: "Verify the setting. If the SA cannot demonstrate it, this is a finding."));

        result.Automatability.ShouldBe(Automatability.Automatable);
    }

    // --- Step 3: the tool cannot supply what the fix needs ---

    [Fact]
    public void A_fix_needing_a_password_is_needs_review()
    {
        var result = RuleClassifier.Classify(Rule(
            "Boot password",
            fix: "Generate an encrypted grub2 password:\n\n$ sudo grub2-setpassword\nEnter password:"));

        result.Automatability.ShouldBe(Automatability.NeedsReview);
        result.Reason.ShouldContain("password");
    }

    [Fact]
    public void A_fix_whose_value_is_site_defined_is_needs_review()
    {
        var result = RuleClassifier.Classify(Rule(
            "Firewall policy",
            fix: "Set the zone target to DROP:\n\n$ sudo firewall-cmd --permanent --set-target=DROP",
            check: "Ask the System Administrator for the site PPSM CLSA and verify the allowed services match."));

        result.Automatability.ShouldBe(Automatability.NeedsReview);
    }

    [Fact]
    public void A_fix_conditional_on_the_host_being_a_router_is_needs_review()
    {
        var result = RuleClassifier.Classify(Rule(
            "IPv4 forwarding",
            fix: "Add the following line in the \"/etc/sysctl.d/\" directory unless the system is a router:\n\n"
               + "net.ipv4.conf.all.forwarding = 0\n\n$ sudo sysctl --system"));

        result.Automatability.ShouldBe(Automatability.NeedsReview);
        result.Reason.ShouldContain("role");
    }

    [Fact]
    public void A_fix_that_changes_storage_layout_is_needs_review()
    {
        var result = RuleClassifier.Classify(Rule(
            "Separate /var partition",
            fix: "Configure the \"/etc/fstab\" to mount /var with the nodev option."));

        result.Automatability.ShouldBe(Automatability.NeedsReview);
    }

    /// <summary>
    /// The precedence that matters most: a fix containing a real command whose value the tool does not
    /// know must not be treated as automatable. Generating a firewall rule from a value nobody supplied
    /// is worse than generating nothing.
    /// </summary>
    [Fact]
    public void A_site_defined_value_beats_the_presence_of_a_command()
    {
        var result = RuleClassifier.Classify(Rule(
            "Audit off-load",
            fix: "Set the remote server option in \"/etc/audisp/audisp-remote.conf\" with the "
               + "IP address of the log aggregation server.\n\n$ sudo systemctl restart auditd"));

        result.Automatability.ShouldBe(Automatability.NeedsReview);
    }

    // --- Step 4: a concrete configuration change ---

    [Theory]
    [InlineData("Install the package with the following command:\n\n$ sudo yum install firewalld")]
    [InlineData("Start the service:\n\n$ sudo systemctl enable --now rsyslog")]
    [InlineData("Add the following line in a file in the \"/etc/sysctl.d/\" directory:\n\nkernel.kptr_restrict = 1")]
    [InlineData("Run the following command:\n\n$ sudo chmod 0600 /var/log/audit/audit.log")]
    [InlineData("Add the following line to \"/etc/security/pwquality.conf\":\n\nminlen = 15")]
    [InlineData("Configure the daemon with the following command:\n\n$ sudo firewall-cmd --reload")]
    public void A_concrete_configuration_change_is_automatable(string fix)
    {
        RuleClassifier.Classify(Rule("Config rule", fix)).Automatability.ShouldBe(Automatability.Automatable);
    }

    [Fact]
    public void An_unrecognised_command_still_reads_as_automatable_from_the_shell_prompt()
    {
        // Deliberately a command no signal table mentions: the shell prompt is the signal.
        var result = RuleClassifier.Classify(Rule(
            "Some future tool",
            fix: "Apply the required setting:\n\n$ sudo some-future-tool --set-required-value"));

        result.Automatability.ShouldBe(Automatability.Automatable);
        result.Reason.ShouldContain("shell command");
    }

    // --- Step 5: default to asking ---

    [Fact]
    public void A_fix_describing_only_an_outcome_is_needs_review()
    {
        var result = RuleClassifier.Classify(Rule(
            "Vague rule",
            fix: "Ensure the system is configured to meet the requirement."));

        result.Automatability.ShouldBe(Automatability.NeedsReview);
    }

    // --- Domain detection and high-risk flagging ---

    [Theory]
    [InlineData("Set \"PermitRootLogin no\" in \"/etc/ssh/sshd_config\".", RiskDomain.Sshd)]
    [InlineData("Add \"password required pam_pwquality.so\" to \"/etc/pam.d/password-auth\".", RiskDomain.Pam)]
    [InlineData("Set SELINUXTYPE=targeted in \"/etc/selinux/config\".", RiskDomain.Selinux)]
    [InlineData("Install firewalld:\n\n$ sudo yum install firewalld", RiskDomain.Firewall)]
    [InlineData("Add the following line to \"/etc/login.defs\":\n\nPASS_MIN_DAYS 1", RiskDomain.Authentication)]
    [InlineData("Add \"net.ipv4.conf.all.rp_filter = 1\" in \"/etc/sysctl.d/\".", RiskDomain.Network)]
    public void High_risk_domains_are_detected_and_flagged(string fix, RiskDomain expected)
    {
        var result = RuleClassifier.Classify(Rule("Risky rule", fix));

        result.Domains.ShouldContain(expected);
        result.IsHighRisk.ShouldBeTrue();
    }

    [Theory]
    [InlineData("Remove the package:\n\n$ sudo yum remove telnet-server")]
    [InlineData("Start the service:\n\n$ sudo systemctl enable --now chronyd")]
    [InlineData("Run the following command:\n\n$ sudo chmod 0755 /sbin/auditctl")]
    public void Lower_risk_rules_are_not_flagged_high_risk(string fix)
    {
        RuleClassifier.Classify(Rule("Routine rule", fix)).IsHighRisk.ShouldBeFalse();
    }

    /// <summary>
    /// An audit rule watching a PAM or sudoers file is an auditd change, not a PAM or authentication
    /// change: adding a watch cannot lock anyone out. A real RHEL 8 STIG has dozens of these, so getting
    /// it wrong would flag most of the audit section high-risk and train operators to click through.
    /// </summary>
    [Fact]
    public void An_audit_rule_watching_a_sensitive_file_is_not_high_risk()
    {
        var result = RuleClassifier.Classify(Rule(
            "Modifications to /etc/sudoers must generate an audit record.",
            fix: "Configure the audit system to generate an audit event for any modification to the "
               + "\"/etc/sudoers\" file.\n\nAdd the following rule to \"/etc/audit/rules.d/audit.rules\":\n\n"
               + "-w /etc/sudoers -p wa -k identity\n\n$ sudo augenrules --load"));

        result.Automatability.ShouldBe(Automatability.Automatable);
        result.Domains.ShouldContain(RiskDomain.Auditd);
        result.IsHighRisk.ShouldBeFalse();
        result.Domains.ShouldNotContain(RiskDomain.Authentication);
    }

    [Fact]
    public void Configuring_pam_itself_is_still_high_risk_even_when_auditing_is_mentioned()
    {
        var result = RuleClassifier.Classify(Rule(
            "RHEL 8 must lock an account after three failed logon attempts.",
            fix: "Add the following line to \"/etc/security/faillock.conf\":\n\ndeny = 3\n\n"
               + "The audit daemon logs the lockout."));

        result.Domains.ShouldContain(RiskDomain.Pam);
        result.IsHighRisk.ShouldBeTrue();
    }

    [Fact]
    public void Every_classification_carries_a_reason()
    {
        string[] fixes =
        [
            "", "Document the procedure and obtain ISSO approval.",
            "$ sudo grub2-setpassword\nEnter password:",
            "$ sudo yum install firewalld",
            "Ensure the system meets the requirement.",
        ];

        foreach (var fix in fixes)
        {
            var result = RuleClassifier.Classify(Rule("Rule", fix));
            result.Reason.ShouldNotBeNullOrWhiteSpace();
            result.Reason.ShouldEndWith(".");
        }
    }
}
