namespace Stigsmith.Validation;

/// <summary>One rule's validation outcome within a report.</summary>
public sealed record ValidationReportRow(
    string RuleId,
    string RuleVersion,
    ValidationOutcome Outcome,
    ValidationStage? FailedStage,
    int Attempts,
    string ScanStatusBefore,
    string ScanStatusAfter,
    ComplianceVerifierKind VerifiedBy,
    int IdempotencyChangedCount,
    string Summary);

/// <summary>
/// The pass/fail report for a validation run over a batch of rules.
/// </summary>
/// <remarks>
/// Deliberately reports the four outcomes separately rather than as a percentage. "31 of 45 passed" invites reading
/// the other 14 as broken, when in practice most are rules a container cannot validate or rules that need a human —
/// and those are different problems with different owners.
/// </remarks>
public sealed record ValidationReport
{
    public required IReadOnlyList<ValidationReportRow> Rows { get; init; }

    public int Total => Rows.Count;
    public int Passed => Rows.Count(r => r.Outcome == ValidationOutcome.Passed);
    public int NeedsHumanReview => Rows.Count(r => r.Outcome == ValidationOutcome.NeedsHumanReview);
    public int Failed => Rows.Count(r => r.Outcome == ValidationOutcome.Failed);
    public int Skipped => Rows.Count(r => r.Outcome == ValidationOutcome.Skipped);

    /// <summary>Rules that needed the repair attempt and then passed. Worth knowing: it is the model's self-correction rate.</summary>
    public int PassedAfterRepair => Rows.Count(r => r.Outcome == ValidationOutcome.Passed && r.Attempts > 1);

    /// <summary>How many passes rest on a real SCAP scan rather than on the rule's own check command.</summary>
    public int VerifiedByOscap =>
        Rows.Count(r => r.Outcome == ValidationOutcome.Passed && r.VerifiedBy == ComplianceVerifierKind.Oscap);

    public static ValidationReport From(IEnumerable<(string RuleId, string RuleVersion, IReadOnlyList<ValidationEvidence> Attempts)> results) =>
        new()
        {
            Rows = [.. results.Select(r =>
            {
                var last = r.Attempts[^1];
                return new ValidationReportRow(
                    r.RuleId, r.RuleVersion, last.Outcome, last.FailedStage, r.Attempts.Count,
                    last.ScanStatusBefore, last.ScanStatusAfter, last.VerifiedBy,
                    last.IdempotencyChangedCount, last.Summary);
            })],
        };

    public string Summary() =>
        $"{Total} rules validated: {Passed} passed, {NeedsHumanReview} need human review, "
        + $"{Failed} failed, {Skipped} skipped. "
        + $"{PassedAfterRepair} passed only after one repair. "
        + $"{VerifiedByOscap} of the passes were confirmed by a real SCAP scan.";
}
