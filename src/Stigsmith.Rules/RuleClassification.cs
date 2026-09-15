namespace Stigsmith.Rules;

/// <summary>
/// What the classifier concluded about one rule, and why. The reason is not decoration: an operator
/// deciding whether to trust a "needs-review" verdict needs to see which signal fired, and an
/// operator overriding an "automatable" verdict needs to know what the tool thought it saw.
/// </summary>
public sealed record RuleClassification
{
    public required string RuleId { get; init; }

    public required Automatability Automatability { get; init; }

    /// <summary>One sentence naming the signal that decided it.</summary>
    public required string Reason { get; init; }

    public IReadOnlySet<RiskDomain> Domains { get; init; } = new HashSet<RiskDomain>();

    /// <summary>
    /// True when remediation touches a subsystem that can lock an operator out of the host. These
    /// require explicit opt-in before generation and always get a check-mode path.
    /// </summary>
    public bool IsHighRisk => Domains.Any(RiskDomains.IsHighRisk);

    /// <summary>The high-risk domains only, for explaining the flag to an operator.</summary>
    public IEnumerable<RiskDomain> HighRiskDomains => Domains.Where(RiskDomains.IsHighRisk);

    public string DomainTokens => string.Join(',', Domains.Select(d => d.ToToken()).Order());
}
