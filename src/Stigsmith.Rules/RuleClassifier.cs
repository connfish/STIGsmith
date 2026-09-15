using System.Text.RegularExpressions;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Rules;

/// <summary>
/// Decides whether a STIG rule's prescribed fix is something Ansible can carry out, and which
/// subsystems it touches.
/// </summary>
/// <remarks>
/// <para>
/// Pure text heuristics over <c>fixtext</c> and <c>check content</c>, with no model involved. That is
/// deliberate: this layer has to stand alone, be reviewable by an operator who does not trust the tool
/// yet, and give the same answer every run. A model-assisted second pass over the
/// <see cref="Automatability.NeedsReview"/> bucket would be a reasonable addition; it is not a
/// substitute, and nothing downstream may depend on it having run.
/// </para>
/// <para>
/// The signal tables below are ordered by precedence, and that order is the whole design. Reading them
/// top to bottom is reading the policy:
/// </para>
/// <list type="number">
/// <item>No fix text at all — there is nothing to translate.</item>
/// <item>The fix itself is a documentation, policy, or physical action — <see cref="Automatability.Manual"/>.</item>
/// <item>The fix needs a value, secret, or artifact this tool cannot supply, or the correct value is
/// site-defined — <see cref="Automatability.NeedsReview"/>.</item>
/// <item>The fix is a command or a named configuration directive — <see cref="Automatability.Automatable"/>.</item>
/// <item>Anything else — <see cref="Automatability.NeedsReview"/>. The default is to ask, not to guess.</item>
/// </list>
/// <para>
/// Step 3 runs before step 4 on purpose. A rule whose fix text contains a shell command but whose check
/// content says "ask the System Administrator for the site's PPSM CLSA" is not automatable: the command
/// is there, but the tool does not know what to put in it. Ordering it the other way round would
/// confidently generate a firewall rule from a value nobody supplied.
/// </para>
/// </remarks>
public static partial class RuleClassifier
{
    /// <summary>
    /// Step 2. The fix is a thing a person does, not a thing a machine does. Matched against fix text
    /// only: "ask the System Administrator" in <em>check</em> content is how DISA words a verification
    /// step, and says nothing about whether the fix is automatable.
    /// </summary>
    private static readonly Signal[] ManualFixSignals =
    [
        new("documentation action", [
            "document the procedure", "document the system", "document and obtain",
            "develop a list of", "develop a contingency plan",
            "submit it to the configuration control board", "retain the training records",
            "review the list annually", "obtain a documented risk acceptance",
            "document the audit processing failure", "obtain iso approval",
        ], "the fix is to produce or approve documentation, not to change configuration"),

        new("ISSO or SA judgement", [
            "the isso will", "the information system security officer (isso) will",
            "the system administrator will investigate", "the system administrator will review",
            "will verify that any deviation", "with isso approval, either",
        ], "the fix assigns a judgement to a person, not a configuration change"),

        new("physical or organisational", [
            "relocate the system", "controlled access area", "physical security requirements",
            "completes acceptable use training", "before an account is created, and retain",
        ], "the fix is a physical or organisational control"),
    ];

    /// <summary>
    /// Step 3. Something a machine cannot supply, or a value only the site knows. Checked against fix
    /// text and check content together, because either can be where the dependency shows up.
    /// </summary>
    private static readonly Signal[] NeedsReviewSignals =
    [
        new("secret or credential required", [
            "enter password", "setpassword", "confirm password",
        ], "the fix requires a password or passphrase that this tool cannot supply"),

        new("external artifact required", [
            "obtain the dod-approved", "certificate bundle", "obtain the approved",
            "available from the vendor", "upgrade to a supported version",
        ], "the fix depends on an artifact or vendor action outside the host's configuration"),

        new("site-defined value", [
            "ip address of the log aggregation server", "organizational patch schedule",
            "organization-defined", "as defined by the organization", "ppsm clsa",
            "ports, protocols, and services management", "site or program", "the site has documented",
        ], "the correct value is defined by the site, not by the STIG"),

        new("documented exception path", [
            "documented and approved reason", "and obtain isso approval instead",
            "not documented as an operational requirement", "if the site uses a directory service",
            "centralized account management", "is not documented with the information system security officer",
        ], "the rule has a documented-exception path, so the right action depends on site context"),

        new("conditional on host role", [
            "unless the system is a router", "and the system is not a router", "if the system is a router",
        ], "the correct setting depends on the host's role, which this tool does not know"),

        new("storage layout change", [
            "/etc/fstab", "partition layout", "will need to be resized", "dedicate a partition",
            "separate file system", "separate partition",
        ], "the fix changes storage layout, which is site-specific and can prevent boot"),

        new("account state change", [
            "lock all interactive user accounts", "until the passwords can be regenerated",
            "lock all accounts",
        ], "the fix changes account state rather than configuration and can lock out users"),

        new("verification defers to the administrator", [
            "ask the system administrator how", "ask the system administrator to indicate",
            "ask the system administrator for", "ask the sa how", "if there is no evidence",
            "how file integrity checks are performed", "ask the system administrator to demonstrate",
        ], "the check defers to the administrator, so there is no single prescribed change"),
    ];

    /// <summary>
    /// Step 4. Evidence that the fix is a concrete configuration change. Fix text only — a command in
    /// the check content is how you verify, not how you remediate.
    /// </summary>
    private static readonly Signal[] AutomatableFixSignals =
    [
        new("package operation", [
            "yum install", "yum remove", "dnf install", "dnf remove", "rpm -e",
        ], "the fix installs or removes a package"),

        new("service operation", [
            "systemctl enable", "systemctl disable", "systemctl mask", "systemctl start",
            "systemctl restart", "systemctl stop",
        ], "the fix enables, disables, or masks a systemd unit"),

        new("kernel or boot parameter", [
            "sysctl --system", "sysctl -w", "/etc/sysctl.d/", "grubby --update-kernel",
            "/etc/default/grub",
        ], "the fix sets a kernel or boot parameter"),

        new("permission or ownership change", [
            "chmod ", "chown ", "chcon ", "restorecon",
        ], "the fix changes file permissions or ownership"),

        new("configuration file edit", [
            "add the following line", "add or modify the following line", "add/modify the",
            "add or edit the following line", "add the following setting", "add the setting",
            "modify the following line", "uncomment the", "set the following option",
            "add or update the following", "add or modify", "edit the", "edit/modify",
            "by setting the", "to have the following line", "in the file",
        ], "the fix edits a named configuration file"),

        new("tool-specific command", [
            "firewall-cmd", "authselect", "fips-mode-setup", "dconf update", "augenrules --load",
            "postconf -e", "nmcli radio", "grub2-mkconfig", "aide --init",
        ], "the fix runs a configuration management command"),

        new("file removal", [
            "remove any found", "rm /etc/", "rm -f /etc/",
        ], "the fix removes a file"),
    ];

    /// <summary>
    /// Subsystem detection. Matched over the rule title, its version id, the group title, and the fix
    /// text — deliberately <em>not</em> the check content.
    /// </summary>
    /// <remarks>
    /// Check content routinely quotes other subsystems' files as things to inspect. An auditd rule that
    /// adds a watch on <c>/etc/sudoers</c> reads as an authentication rule if the check is included,
    /// which is wrong twice over: adding an audit watch cannot lock anyone out, and the noise buries the
    /// domains that do matter. Restricting detection to the title and the fix keeps the question
    /// "what does remediation change?" rather than "what does verification look at?".
    /// </remarks>
    private static readonly (RiskDomain Domain, string[] Phrases)[] DomainSignals =
    [
        (RiskDomain.Sshd, [
            "sshd_config", "ssh daemon", "sshd", "openssh", "ssh server", "via ssh", "ssh logon",
            "shosts.equiv", "ssh private key", "permitrootlogin", "clientalive", "strictmodes",
            "host-based authentication", "remotely as", "ssh traffic",
        ]),
        (RiskDomain.Pam, [
            "/etc/pam.d", "pam_", "pam module", "password-auth", "system-auth", "faillock",
            "pwquality", "pwhistory", "authselect",
        ]),
        (RiskDomain.Selinux, [
            "selinux", "sestatus", "policycoreutils", "semanage", "setsebool", "targeted policy",
            "restorecon", "chcon",
        ]),
        (RiskDomain.Firewall, [
            "firewalld", "firewall-cmd", "iptables", "nftables", "deny-all", "allow-by-exception",
            "firewall must", "a firewall", "the firewall",
        ]),
        (RiskDomain.Authentication, [
            "password", "passwd", "multifactor", "smart card", "pki-based authentication",
            "authentication device", "openssl-pkcs11", "trust anchor", "sssd_auth_ca",
            "logon attempt", "account lock", "login.defs", "/etc/shadow", "credential",
            "sudoers", "libuser.conf", "maxlogins", "concurrent session",
        ]),
        (RiskDomain.Network, [
            "net.ipv4", "net.ipv6", "ip forwarding", "packet forwarding", "router advertisement",
            "reverse path", "rp_filter", "source route", "wireless", "nmcli", "network interface",
            "mail relay", "smtpd", "postfix", "accept_ra", "forwarding =", "ip-address",
        ]),
        (RiskDomain.Auditd, [
            "auditd", "audit record", "audit rule", "audit log", "auditctl", "augenrules",
            "audisp", "audit_backlog_limit", "audit tool", "/etc/audit", "audit storage",
            "audit processing", "audit system",
        ]),
        (RiskDomain.Boot, [
            "grub", "/boot", "uefi", "bios", "single-user mode", "kernelopts", "bootloader",
        ]),
        (RiskDomain.Crypto, [
            "fips", "cryptograph", "crypto-policies", "openssl", "hashing algorithm", "sha512",
            "sha-512", "encryption", "encrypt",
        ]),
        (RiskDomain.Filesystem, [
            "mode 0", "mode 7", "less permissive", "chmod", "chown", "owned by root", "library file",
            "system command", "/etc/fstab", "nosuid", "mount option", "home director",
        ]),
        (RiskDomain.Kernel, [
            "sysctl", "kernel parameter", "kernel module", "modprobe", "kexec", "usb-storage",
            "protected_symlinks", "blacklist", "kernel image",
        ]),
        (RiskDomain.Packages, [
            "yum", "dnf", "gpgcheck", "package", "rpm", "repository", "telnet-server", "abrt",
            "software component",
        ]),
        (RiskDomain.Services, [
            "systemctl", "systemd", "service must", "daemon", "rsyslog", "chrony", "autofs",
            "ctrl-alt-del", "debug-shell",
        ]),
    ];

    /// <summary>
    /// An auditd rule line, as it appears verbatim in fix text: <c>-w /etc/sudoers -p wa -k identity</c>
    /// or <c>-a always,exit -F path=/usr/bin/su ...</c>. Stripped before domain detection, because the
    /// paths on these lines name what is being <em>watched</em>, not what is being configured. Without
    /// this, every audit rule that watches <c>/etc/shadow</c>, <c>/etc/sudoers</c>, or a PAM file reads
    /// as an authentication or PAM rule and gets flagged high-risk — and a real RHEL 8 STIG has dozens
    /// of them, which would make the high-risk flag mean nothing.
    /// </summary>
    [GeneratedRegex(@"^[ \t]*-[wa][ \t].*$", RegexOptions.Multiline)]
    private static partial Regex AuditRuleLine();

    /// <summary>
    /// A shell command in fix text: DISA writes these as "$ sudo ..." or "# ...". Recognising the
    /// prompt rather than a list of binaries means a fix using a command nobody anticipated still reads
    /// as automatable.
    /// </summary>
    [GeneratedRegex(@"^[ \t]*[$#][ \t]+\S", RegexOptions.Multiline)]
    private static partial Regex ShellPrompt();

    /// <summary>
    /// A configuration directive on its own line: "PermitRootLogin no", "deny = 3", "gpgcheck=1",
    /// "minlen = 15". Anchored to a whole line so prose containing an equals sign does not match.
    /// </summary>
    [GeneratedRegex(@"^[ \t]*[A-Za-z_][A-Za-z0-9_.\-]*[ \t]*(?:=[ \t]*|[ \t]+)[^\s=][^\r\n]*$", RegexOptions.Multiline)]
    private static partial Regex ConfigDirective();

    public static RuleClassification Classify(RuleContent rule)
    {
        var fix = rule.FixText ?? "";
        var check = rule.CheckContent ?? "";
        var fixLower = fix.ToLowerInvariant();
        var bothLower = (fix + "\n" + check).ToLowerInvariant();
        var domains = DetectDomains(rule);

        RuleClassification Result(Automatability automatability, string reason) => new()
        {
            RuleId = rule.RuleId,
            Automatability = automatability,
            Reason = reason,
            Domains = domains,
        };

        // 1. Nothing to translate.
        if (string.IsNullOrWhiteSpace(fix))
        {
            return Match(ManualFixSignals, check.ToLowerInvariant()) is { } manualFromCheck
                ? Result(Automatability.Manual,
                    $"No fix text, and the check is a human procedure: {manualFromCheck.Reason}.")
                : Result(Automatability.NeedsReview,
                    "The rule has no fix text, so there is nothing to translate into Ansible.");
        }

        // 2. The fix is something a person does.
        if (Match(ManualFixSignals, fixLower) is { } manual)
            return Result(Automatability.Manual, Capitalise(manual.Reason) + ".");

        // 3. The fix depends on something this tool does not have. Before step 4 on purpose: a command
        //    whose value nobody supplied is worse than no command at all.
        if (Match(NeedsReviewSignals, bothLower) is { } review)
            return Result(Automatability.NeedsReview, Capitalise(review.Reason) + ".");

        // 4. A concrete configuration change.
        if (Match(AutomatableFixSignals, fixLower) is { } automatable)
            return Result(Automatability.Automatable, Capitalise(automatable.Reason) + ".");

        if (ShellPrompt().IsMatch(fix))
            return Result(Automatability.Automatable, "The fix gives a shell command to run.");

        if (HasFilePath(fix) && ConfigDirective().IsMatch(fix))
            return Result(Automatability.Automatable,
                "The fix names a configuration file and the directive to set in it.");

        // 5. Ask, do not guess.
        return Result(Automatability.NeedsReview,
            "The fix text describes an outcome without naming a command or a configuration directive.");
    }

    public static IReadOnlyList<RuleClassification> ClassifyAll(IEnumerable<RuleContent> rules) =>
        [.. rules.Select(Classify)];

    private static Signal? Match(Signal[] signals, string lowered)
    {
        foreach (var signal in signals)
            if (signal.Phrases.Any(p => lowered.Contains(p, StringComparison.Ordinal)))
                return signal;
        return null;
    }

    private static HashSet<RiskDomain> DetectDomains(RuleContent rule)
    {
        var fix = rule.FixText ?? "";
        var haystack = string.Join('\n',
            rule.Title, rule.RuleVersion, rule.GroupTitle, AuditRuleLine().Replace(fix, ""))
            .ToLowerInvariant();

        var domains = DomainSignals
            .Where(d => d.Phrases.Any(p => haystack.Contains(p, StringComparison.Ordinal)))
            .Select(d => d.Domain)
            .ToHashSet();

        // An audit-record rule reconfigures auditd and nothing else. The subsystem it names -- sudoers,
        // /etc/shadow, a PAM file -- is what it watches, so attributing that subsystem's risk to this
        // rule is wrong: adding a watch cannot lock anyone out. Stripping the rule line above handles
        // the directive itself; this handles the prose around it ("generate an audit event for any
        // modification to the /etc/sudoers file"). Lower-risk domains are left alone -- they are
        // informational, and an audit rule really can be a filesystem or boot concern.
        if (domains.Contains(RiskDomain.Auditd) && IsAuditRecordRule(rule, fix))
            domains.RemoveWhere(RiskDomains.IsHighRisk);

        return domains;
    }

    private static bool IsAuditRecordRule(RuleContent rule, string fix) =>
        AuditRuleLine().IsMatch(fix)
        || rule.Title.Contains("generate an audit", StringComparison.OrdinalIgnoreCase)
        || rule.Title.Contains("audit record", StringComparison.OrdinalIgnoreCase);

    private static bool HasFilePath(string text) =>
        text.Contains("/etc/", StringComparison.Ordinal)
        || text.Contains("/usr/", StringComparison.Ordinal)
        || text.Contains("/var/", StringComparison.Ordinal)
        || text.Contains("/boot/", StringComparison.Ordinal);

    private static string Capitalise(string s) =>
        s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];

    private sealed record Signal(string Name, string[] Phrases, string Reason);
}
