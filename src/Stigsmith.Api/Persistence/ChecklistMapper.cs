using Stigsmith.Checklists.Model;

namespace Stigsmith.Api.Persistence;

/// <summary>
/// Translates between the parsed <see cref="Checklist"/> and its database rows.
/// </summary>
/// <remarks>
/// Import keeps the original document text on the checklist row. Export then re-emits from that text
/// rather than from the rows, patching in the statuses and comments the database now holds — which is
/// what makes the round trip lossless for fields Stigsmith does not model. Rebuilding an export from
/// the rows alone would drop them.
/// </remarks>
public static class ChecklistMapper
{
    public static ChecklistRecord ToRecord(Checklist checklist, string fileName, string originalDocument)
    {
        var first = checklist.Stigs.FirstOrDefault()?.Info ?? new StigInfo();
        var host = checklist.Host;

        return new ChecklistRecord
        {
            Title = checklist.Title is { Length: > 0 } t ? t : $"{host.DisplayName} — {first.Title}",
            SourceFormat = checklist.SourceFormat,
            FileName = fileName,
            OriginalDocument = originalDocument,

            HostName = host.HostName,
            HostIp = host.HostIp,
            HostMac = host.HostMac,
            HostFqdn = host.HostFqdn,
            TargetComment = host.TargetComment,
            Role = host.Role,
            AssetType = host.AssetType,
            TechArea = host.TechArea,
            TargetKey = host.TargetKey,
            IsWebOrDatabase = host.IsWebOrDatabase,
            WebDbSite = host.WebDbSite,
            WebDbInstance = host.WebDbInstance,

            StigId = first.StigId,
            StigTitle = first.Title,
            StigVersion = first.Version,
            StigReleaseInfo = first.ReleaseInfo,

            Findings = [.. checklist.Findings.Select(ToRecord)],
        };
    }

    private static FindingRecord ToRecord(Finding f) => new()
    {
        RuleId = f.Rule.RuleId,
        GroupId = f.Rule.GroupId,
        NumericId = f.Rule.NumericId,
        RuleVersion = f.Rule.RuleVersion,
        Title = f.Rule.Title,
        Severity = f.Rule.Severity,
        Status = f.Status,
        FindingDetails = f.FindingDetails,
        Comments = f.Comments,
        FixText = f.Rule.FixText,
        CheckContent = f.Rule.CheckContent,
        Discussion = f.Rule.Discussion,
        CciRefs = string.Join(',', f.Rule.CciRefs),
    };

    /// <summary>
    /// The review verdicts held in the database, keyed by rule id, ready to be applied to a re-parsed
    /// source document on export.
    /// </summary>
    public static Dictionary<string, FindingReview> ToReviews(ChecklistRecord record) =>
        record.Findings.ToDictionary(
            f => f.RuleId,
            f => new FindingReview(f.Status, f.FindingDetails, f.Comments),
            StringComparer.OrdinalIgnoreCase);
}
