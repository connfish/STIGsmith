using Stigsmith.Checklists.Model;

namespace Stigsmith.Rules;

/// <summary>
/// How much of a checklist this tool can actually help with. Reported because an honest number is
/// more useful than a flattering one: an operator who is told "62 of 72 automatable" and finds it is
/// really 40 stops trusting the tool, whereas one told "40 automatable, 16 need your judgement" can
/// plan their week.
/// </summary>
public sealed record ClassificationCoverage
{
    public required int Total { get; init; }
    public required int Automatable { get; init; }
    public required int Manual { get; init; }
    public required int NeedsReview { get; init; }

    /// <summary>Counts restricted to findings that are currently open — the work actually in front of the operator.</summary>
    public required int OpenTotal { get; init; }
    public required int OpenAutomatable { get; init; }
    public required int OpenManual { get; init; }
    public required int OpenNeedsReview { get; init; }

    /// <summary>Automatable rules that are also high-risk, so they need explicit opt-in before generation.</summary>
    public required int AutomatableHighRisk { get; init; }

    public required IReadOnlyDictionary<RiskDomain, int> ByDomain { get; init; }

    public double AutomatableShare => Total == 0 ? 0 : (double)Automatable / Total;

    public static ClassificationCoverage From(IEnumerable<(Finding Finding, RuleClassification Classification)> pairs)
    {
        var all = pairs.ToArray();
        var open = all.Where(p => p.Finding.Status == FindingStatus.Open).ToArray();

        int Count(IReadOnlyCollection<(Finding, RuleClassification)> set, Automatability a) =>
            set.Count(p => p.Item2.Automatability == a);

        return new ClassificationCoverage
        {
            Total = all.Length,
            Automatable = Count(all, Automatability.Automatable),
            Manual = Count(all, Automatability.Manual),
            NeedsReview = Count(all, Automatability.NeedsReview),
            OpenTotal = open.Length,
            OpenAutomatable = Count(open, Automatability.Automatable),
            OpenManual = Count(open, Automatability.Manual),
            OpenNeedsReview = Count(open, Automatability.NeedsReview),
            AutomatableHighRisk = all.Count(p =>
                p.Classification.Automatability == Automatability.Automatable && p.Classification.IsHighRisk),
            ByDomain = all.SelectMany(p => p.Classification.Domains)
                .GroupBy(d => d)
                .ToDictionary(g => g.Key, g => g.Count()),
        };
    }

    public static ClassificationCoverage From(Checklist checklist) =>
        From(checklist.Findings.Select(f => (f, RuleClassifier.Classify(f.Rule))));

    /// <summary>The line an operator sees after import, and the one the milestone asks for.</summary>
    public string Summary() =>
        $"{Total} rules: {Automatable} automatable, {Manual} manual, {NeedsReview} needs-review "
        + $"({AutomatableShare:P0} automatable). "
        + $"Of {OpenTotal} open: {OpenAutomatable} automatable, {OpenManual} manual, {OpenNeedsReview} needs-review. "
        + $"{AutomatableHighRisk} automatable rules are high-risk and need explicit opt-in.";
}
