namespace Stigsmith.Validation;

/// <summary>Settings for the validation sandbox and the loop.</summary>
public sealed class ValidationOptions
{
    public const string SectionName = "Stigsmith:Validation";

    /// <summary>
    /// The container image the loop applies remediation in. An el8-family base, because a RHEL 8 STIG's fixes assume
    /// el8 paths and package names. Build it once from <c>docker/validation/Dockerfile</c>; it needs ansible-core,
    /// ansible-lint, and openscap-scanner, and pulling those at run time would break on an air-gapped host.
    /// </summary>
    public string Image { get; set; } = "stigsmith/validation:el8";

    /// <summary>
    /// The SCAP Security Guide STIG profile. SSG content ships in the el8 repositories; DISA's own benchmark, which
    /// names its profiles <c>xccdf_mil.disa.stig_profile_…</c>, does not, and target environments cannot fetch it.
    /// </summary>
    public string ScapProfile { get; set; } = "xccdf_org.ssgproject.content_profile_stig";

    public string ScapDatastreamPath { get; set; } = "/usr/share/xml/scap/ssg/content/ssg-almalinux8-ds.xml";

    /// <summary>
    /// Whether to try a real SCAP scan before falling back to the rule's own check content. On by default: the
    /// milestone asks for a re-scan, and a real scan is worth more as evidence.
    /// </summary>
    public bool PreferOscap { get; set; } = true;

    /// <summary>
    /// How long one rule's whole loop may take. Two applies plus a scan in a cold container is slow; a rule that
    /// exceeds this is a rule whose remediation hangs, which is a finding in itself.
    /// </summary>
    public TimeSpan PerRuleTimeout { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Exactly one repair attempt, as the milestone specifies. Configurable to 0 to disable repair; raising it is not
    /// supported — a model that cannot fix its own output given the error twice is not going to on the third try, and
    /// "needs-human-review" is the useful answer.
    /// </summary>
    public int MaxRepairAttempts { get; set; } = 1;

    /// <summary>Path inside the container. Under /tmp because the container is destroyed either way.</summary>
    public string WorkDirectory { get; set; } = "/tmp/stigsmith";

    /// <summary>
    /// The ansible-lint configuration inside the image, passed with <c>-c</c>. ansible-lint reads no environment
    /// variable for this, so the image's config was silently ignored until the first live run tripped a rule it lists.
    /// </summary>
    public string AnsibleLintConfig { get; set; } = "/etc/ansible-lint.yml";

    /// <summary>
    /// Whether to run the container privileged. Off by default.
    /// </summary>
    /// <remarks>
    /// A container is not a host. Remediation that sets a kernel parameter, enables a systemd unit, or rewrites the
    /// bootloader cannot apply in an unprivileged container, and the loop reports that honestly as a failed apply
    /// rather than a pass. Turning this on widens what can apply, at the cost of giving an untrusted generated
    /// playbook real capabilities against the host kernel — the operator's decision, not a default.
    /// </remarks>
    public bool Privileged { get; set; }

    /// <summary>Memory cap for the container. A generated playbook is untrusted input.</summary>
    public long MemoryLimitBytes { get; set; } = 2L * 1024 * 1024 * 1024;

    /// <summary>CPU cap in nano-CPUs. Two cores by default.</summary>
    public long CpuLimit { get; set; } = 2_000_000_000;
}
