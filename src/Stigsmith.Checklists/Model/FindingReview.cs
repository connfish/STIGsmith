namespace Stigsmith.Checklists.Model;

/// <summary>
/// An operator's verdict on a rule, separate from the rule itself. These are the only three fields a
/// review changes, and the only three Stigsmith writes back into a checklist on export.
/// </summary>
public sealed record FindingReview(FindingStatus Status, string FindingDetails = "", string Comments = "");
