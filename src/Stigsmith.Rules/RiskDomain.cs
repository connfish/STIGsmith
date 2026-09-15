namespace Stigsmith.Rules;

/// <summary>
/// The subsystem a rule's remediation touches. Used for two things: deciding whether a rule is
/// high-risk, and giving an operator something to filter on during triage.
/// </summary>
public enum RiskDomain
{
    // --- High-risk: remediation here can lock an operator out of the host. ---

    /// <summary>OpenSSH server configuration. A bad sshd_config on a remote host ends the session.</summary>
    Sshd,

    /// <summary>PAM stack. A broken pam.d file locks out every account including root.</summary>
    Pam,

    /// <summary>SELinux mode and policy. Enforcing with a wrong policy can prevent login or boot.</summary>
    Selinux,

    /// <summary>Host firewall. A deny-all default applied before the exception drops the admin session.</summary>
    Firewall,

    /// <summary>Password policy, account lockout, MFA, PKI. Failure mode is nobody can authenticate.</summary>
    Authentication,

    /// <summary>Network and routing configuration, including sysctl network parameters.</summary>
    Network,

    // --- Lower-risk: a failed remediation is recoverable without console access. ---

    Auditd,
    Boot,
    Crypto,
    Filesystem,
    Kernel,
    Packages,
    Services,
}

public static class RiskDomains
{
    /// <summary>
    /// The domains the milestone spec names as high-risk: sshd, PAM, SELinux, firewall,
    /// authentication, and network configuration. A rule in any of these needs explicit opt-in before
    /// generation and always gets a check-mode path.
    /// </summary>
    public static readonly IReadOnlySet<RiskDomain> HighRisk = new HashSet<RiskDomain>
    {
        RiskDomain.Sshd,
        RiskDomain.Pam,
        RiskDomain.Selinux,
        RiskDomain.Firewall,
        RiskDomain.Authentication,
        RiskDomain.Network,
    };

    public static bool IsHighRisk(RiskDomain domain) => HighRisk.Contains(domain);

    /// <summary>The lowercase token used in the fixture expectations file and in API responses.</summary>
    public static string ToToken(this RiskDomain domain) => domain switch
    {
        RiskDomain.Sshd => "sshd",
        RiskDomain.Pam => "pam",
        RiskDomain.Selinux => "selinux",
        RiskDomain.Firewall => "firewall",
        RiskDomain.Authentication => "authentication",
        RiskDomain.Network => "network",
        RiskDomain.Auditd => "auditd",
        RiskDomain.Boot => "boot",
        RiskDomain.Crypto => "crypto",
        RiskDomain.Filesystem => "filesystem",
        RiskDomain.Kernel => "kernel",
        RiskDomain.Packages => "packages",
        RiskDomain.Services => "services",
        _ => domain.ToString().ToLowerInvariant(),
    };
}
