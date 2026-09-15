using Stigsmith.Rules;

namespace Stigsmith.Tests.Rules;

public class GenerationEligibilityTests
{
    private static RuleClassification Classified(
        Automatability automatability, params RiskDomain[] domains) => new()
    {
        RuleId = "SV-000001r1_rule",
        Automatability = automatability,
        Reason = "test",
        Domains = domains.ToHashSet(),
    };

    private static readonly IReadOnlySet<RiskDomain> NothingOptedIn = new HashSet<RiskDomain>();

    [Fact]
    public void An_ordinary_automatable_rule_is_eligible_with_no_opt_in()
    {
        var decision = GenerationEligibility.Evaluate(
            Classified(Automatability.Automatable, RiskDomain.Packages), NothingOptedIn);

        decision.IsEligible.ShouldBeTrue();
        decision.RequireCheckMode.ShouldBeFalse();
    }

    [Fact]
    public void A_high_risk_rule_is_blocked_until_its_domain_is_opted_in()
    {
        var decision = GenerationEligibility.Evaluate(
            Classified(Automatability.Automatable, RiskDomain.Sshd), NothingOptedIn);

        decision.Verdict.ShouldBe(EligibilityVerdict.BlockedPendingOptIn);
        decision.Reason.ShouldContain("sshd");
        decision.RequireCheckMode.ShouldBeTrue();
    }

    [Fact]
    public void Opting_in_to_one_domain_does_not_opt_in_to_another()
    {
        var classification = Classified(Automatability.Automatable, RiskDomain.Pam, RiskDomain.Firewall);

        var decision = GenerationEligibility.Evaluate(
            classification, new HashSet<RiskDomain> { RiskDomain.Pam });

        decision.Verdict.ShouldBe(EligibilityVerdict.BlockedPendingOptIn);
        decision.Reason.ShouldContain("firewall");
        decision.Reason.ShouldNotContain("pam");
    }

    /// <summary>
    /// Consenting to generation is not consenting to apply blind: check-mode stays required even after
    /// the operator has opted in.
    /// </summary>
    [Fact]
    public void Check_mode_is_still_required_after_opting_in()
    {
        var decision = GenerationEligibility.Evaluate(
            Classified(Automatability.Automatable, RiskDomain.Sshd),
            new HashSet<RiskDomain> { RiskDomain.Sshd });

        decision.IsEligible.ShouldBeTrue();
        decision.RequireCheckMode.ShouldBeTrue();
    }

    [Theory]
    [InlineData(Automatability.Manual)]
    [InlineData(Automatability.NeedsReview)]
    [InlineData(Automatability.Unclassified)]
    public void A_rule_that_is_not_automatable_is_never_eligible(Automatability automatability)
    {
        var allDomains = Enum.GetValues<RiskDomain>().ToHashSet();

        var decision = GenerationEligibility.Evaluate(Classified(automatability, RiskDomain.Sshd), allDomains);

        decision.Verdict.ShouldBe(EligibilityVerdict.NotAutomatable);
        decision.IsEligible.ShouldBeFalse();
    }
}
