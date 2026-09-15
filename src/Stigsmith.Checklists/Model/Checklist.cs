namespace Stigsmith.Checklists.Model;

/// <summary>A benchmark's identity as recorded in a checklist.</summary>
public sealed record StigInfo
{
    public string StigId { get; init; } = "";
    public string Title { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public string Version { get; init; } = "";
    public string ReleaseInfo { get; init; } = "";
    public string Uuid { get; init; } = "";
    public string Classification { get; init; } = "";
    public string Description { get; init; } = "";
    public string FileName { get; init; } = "";
    public string Notice { get; init; } = "";
    public string Source { get; init; } = "";
    public string CustomName { get; init; } = "";
    public string ReferenceIdentifier { get; init; } = "";

    /// <summary>
    /// SI_DATA name/value pairs exactly as read, so .ckl export can reproduce the STIG_INFO block
    /// including keys this tool does not model.
    /// </summary>
    internal IReadOnlyList<KeyValuePair<string, string>>? RawSiData { get; init; }
}

/// <summary>One benchmark's findings within a checklist. A .ckl or .cklb may carry several.</summary>
public sealed record StigSection
{
    public StigInfo Info { get; init; } = new();
    public IReadOnlyList<Finding> Findings { get; init; } = [];
    internal System.Text.Json.Nodes.JsonNode? RawCklbStig { get; init; }
}

/// <summary>
/// A normalized checklist: exactly one host, one or more benchmarks. Every supported input format
/// (.ckl, .cklb, XCCDF, ARF) reduces to this, and every export renders from it.
/// </summary>
public sealed record Checklist
{
    public string Title { get; init; } = "";
    public string Id { get; init; } = "";
    public HostMetadata Host { get; init; } = HostMetadata.Empty;
    public IReadOnlyList<StigSection> Stigs { get; init; } = [];
    public ChecklistFormat SourceFormat { get; init; } = ChecklistFormat.Unknown;

    /// <summary>The original .cklb document, for lossless re-export. Null for other formats.</summary>
    internal System.Text.Json.Nodes.JsonNode? RawCklb { get; init; }

    public IEnumerable<Finding> Findings => Stigs.SelectMany(s => s.Findings);

    public IReadOnlyDictionary<FindingStatus, int> CountsByStatus() =>
        Findings.GroupBy(f => f.Status).ToDictionary(g => g.Key, g => g.Count());

    /// <summary>
    /// Applies review verdicts by rule id. Rule content, and the format-specific passthrough behind
    /// it, are left exactly as they were read — only the three fields an operator (or a validated
    /// remediation) actually changes are written. Narrow on purpose: a signature that took whole
    /// findings would let a caller holding a partially-populated rule overwrite real rule content.
    /// </summary>
    public Checklist WithReviews(IReadOnlyDictionary<string, FindingReview> reviewsByRuleId) => this with
    {
        Stigs = [.. Stigs.Select(s => s with
        {
            Findings = [.. s.Findings.Select(f => reviewsByRuleId.TryGetValue(f.Rule.RuleId, out var r)
                ? f with { Status = r.Status, FindingDetails = r.FindingDetails, Comments = r.Comments }
                : f)],
        })],
    };
}
