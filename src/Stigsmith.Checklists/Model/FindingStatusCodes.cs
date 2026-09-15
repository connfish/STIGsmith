namespace Stigsmith.Checklists.Model;

/// <summary>
/// Status tokens differ per format: .ckl uses "NotAFinding" / "Not_Applicable", .cklb uses
/// snake_case, XCCDF uses pass/fail/notapplicable. Kept together so a new format adds one method.
/// </summary>
public static class FindingStatusCodes
{
    public static FindingStatus FromCkl(string? v) => v?.Trim() switch
    {
        "NotAFinding" => FindingStatus.NotAFinding,
        "Open" => FindingStatus.Open,
        "Not_Applicable" => FindingStatus.NotApplicable,
        "Not_Reviewed" or "" or null => FindingStatus.NotReviewed,
        _ => FindingStatus.NotReviewed,
    };

    public static string ToCkl(FindingStatus s) => s switch
    {
        FindingStatus.NotAFinding => "NotAFinding",
        FindingStatus.Open => "Open",
        FindingStatus.NotApplicable => "Not_Applicable",
        _ => "Not_Reviewed",
    };

    public static FindingStatus FromCklb(string? v) => v?.Trim().ToLowerInvariant() switch
    {
        "not_a_finding" => FindingStatus.NotAFinding,
        "open" => FindingStatus.Open,
        "not_applicable" => FindingStatus.NotApplicable,
        _ => FindingStatus.NotReviewed,
    };

    public static string ToCklb(FindingStatus s) => s switch
    {
        FindingStatus.NotAFinding => "not_a_finding",
        FindingStatus.Open => "open",
        FindingStatus.NotApplicable => "not_applicable",
        _ => "not_reviewed",
    };

    /// <summary>
    /// XCCDF rule-result values (XCCDF 1.2 §6.6.4.2). "fixed" means the scanner remediated it, so
    /// the rule now passes; "error"/"unknown"/"notchecked" cannot be distinguished from an
    /// unreviewed rule without human judgement and so map to NotReviewed rather than Open.
    /// </summary>
    public static FindingStatus FromXccdf(string? v) => v?.Trim().ToLowerInvariant() switch
    {
        "pass" or "fixed" => FindingStatus.NotAFinding,
        "fail" => FindingStatus.Open,
        "notapplicable" => FindingStatus.NotApplicable,
        "notselected" => FindingStatus.NotApplicable,
        _ => FindingStatus.NotReviewed,
    };
}
