namespace Stigsmith.Rules;

/// <summary>Why a rule may or may not be sent for remediation generation.</summary>
public enum EligibilityVerdict
{
    /// <summary>Generate it.</summary>
    Eligible = 0,

    /// <summary>High-risk, and the operator has not opted in to this rule's risk domains.</summary>
    BlockedPendingOptIn = 1,

    /// <summary>Not automatable, so there is nothing to generate.</summary>
    NotAutomatable = 2,
}

public sealed record EligibilityDecision(EligibilityVerdict Verdict, string Reason, bool RequireCheckMode)
{
    public bool IsEligible => Verdict == EligibilityVerdict.Eligible;
}

/// <summary>
/// The gate between classification and generation. High-risk rules — sshd, PAM, SELinux, firewall,
/// authentication, network — need the operator to opt in by domain before anything is generated for
/// them, and whatever is generated must always carry a check-mode path.
/// </summary>
/// <remarks>
/// Opt-in is per risk domain rather than a single global flag, so an operator who is happy to let the
/// tool touch PAM on a lab host has not thereby consented to it rewriting the firewall. The
/// check-mode requirement is not conditional on the opt-in: consenting to generation is not consenting
/// to apply blind.
/// </remarks>
public static class GenerationEligibility
{
    public static EligibilityDecision Evaluate(
        RuleClassification classification,
        IReadOnlySet<RiskDomain> optedInDomains)
    {
        if (classification.Automatability != Automatability.Automatable)
            return new EligibilityDecision(
                EligibilityVerdict.NotAutomatable,
                $"Classified {classification.Automatability.ToToken()}: {classification.Reason}",
                RequireCheckMode: false);

        var missing = classification.HighRiskDomains.Where(d => !optedInDomains.Contains(d)).ToArray();
        if (missing.Length > 0)
            return new EligibilityDecision(
                EligibilityVerdict.BlockedPendingOptIn,
                "High-risk remediation: a mistake here can lock an operator out of the host. "
                + $"Opt in to {string.Join(", ", missing.Select(d => d.ToToken()))} to generate for this rule.",
                RequireCheckMode: true);

        return new EligibilityDecision(
            EligibilityVerdict.Eligible,
            classification.IsHighRisk
                ? $"Opted in to {string.Join(", ", classification.HighRiskDomains.Select(d => d.ToToken()))}."
                : "Automatable and not high-risk.",
            // Not conditional on the opt-in: consenting to generation is not consenting to apply blind.
            RequireCheckMode: classification.IsHighRisk);
    }
}

public static class AutomatabilityExtensions
{
    public static string ToToken(this Automatability a) => a switch
    {
        Automatability.Automatable => "automatable",
        Automatability.Manual => "manual",
        Automatability.NeedsReview => "needs-review",
        _ => "unclassified",
    };
}
