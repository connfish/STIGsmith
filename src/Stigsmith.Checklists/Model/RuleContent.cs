namespace Stigsmith.Checklists.Model;

/// <summary>
/// Everything a remediation author needs about a STIG rule, and nothing about the host it was
/// scanned against. The absence of host fields here is the structural half of constraint 3:
/// prompt assembly accepts a <see cref="RuleContent"/>, so it is not possible to pass it a
/// hostname or an IP address by accident. See <see cref="HostMetadata"/> for the other half.
/// </summary>
public sealed record RuleContent
{
    /// <summary>e.g. SV-230221r1017044_rule</summary>
    public required string RuleId { get; init; }

    /// <summary>Vulnerability / group id, e.g. V-230221.</summary>
    public string GroupId { get; init; } = "";

    /// <summary>STIG-local version string, e.g. RHEL-08-010000.</summary>
    public string RuleVersion { get; init; } = "";

    public required string Title { get; init; }

    public string GroupTitle { get; init; } = "";

    public Severity Severity { get; init; } = Severity.Unknown;

    /// <summary>Vuln_Discuss / discussion: why the rule exists.</summary>
    public string Discussion { get; init; } = "";

    /// <summary>DISA's verification procedure. The source of truth for how validation confirms a fix.</summary>
    public string CheckContent { get; init; } = "";

    /// <summary>DISA's prescribed fix, in prose. The thing generation translates into Ansible.</summary>
    public string FixText { get; init; } = "";

    public IReadOnlyList<string> CciRefs { get; init; } = [];

    public IReadOnlyList<string> LegacyIds { get; init; } = [];

    /// <summary>Benchmark this rule came from, e.g. "RHEL 8 STIG :: Version 1, Release: 14".</summary>
    public string StigRef { get; init; } = "";

    public string Weight { get; init; } = "10.0";

    public bool Documentable { get; init; }

    public string Mitigations { get; init; } = "";

    public string PotentialImpacts { get; init; } = "";

    public string ThirdPartyTools { get; init; } = "";

    public string MitigationControl { get; init; } = "";

    public string Responsibility { get; init; } = "";

    public string SecurityOverrideGuidance { get; init; } = "";

    public string IaControls { get; init; } = "";

    public string FalsePositives { get; init; } = "";

    public string FalseNegatives { get; init; } = "";

    /// <summary>
    /// Short numeric id, e.g. "230221" from V-230221. Used as the join key between checklist
    /// findings, XCCDF results, and Ansible task tags, which spell the same rule many ways.
    /// </summary>
    public string NumericId => RuleIdentifiers.Numeric(GroupId) is { Length: > 0 } g ? g : RuleIdentifiers.Numeric(RuleId);
}
