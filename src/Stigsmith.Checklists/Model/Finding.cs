namespace Stigsmith.Checklists.Model;

/// <summary>
/// One rule as reviewed against one host: the rule content plus the operator's verdict on it.
/// </summary>
public sealed record Finding
{
    public required RuleContent Rule { get; init; }

    public FindingStatus Status { get; init; } = FindingStatus.NotReviewed;

    /// <summary>Evidence the reviewer (or the scanner) recorded for the status.</summary>
    public string FindingDetails { get; init; } = "";

    public string Comments { get; init; } = "";

    public string SeverityOverride { get; init; } = "";

    public string SeverityJustification { get; init; } = "";

    /// <summary>
    /// Fields of the source document this tool does not model. Carried so export can put them back
    /// verbatim, which is what makes round-tripping lossless. Deliberately internal: nothing outside
    /// the parsers should read it, and nothing that assembles model prompts can reach it.
    /// </summary>
    internal RawRulePayload? Raw { get; init; }

    public bool IsOpen => Status == FindingStatus.Open;
}

/// <summary>Format-specific passthrough for fields Stigsmith does not model. See <see cref="Finding.Raw"/>.</summary>
internal sealed record RawRulePayload
{
    /// <summary>Ordered STIG_DATA (attribute, data) pairs from a .ckl VULN element.</summary>
    public IReadOnlyList<KeyValuePair<string, string>>? CklStigData { get; init; }

    /// <summary>The original .cklb rule object, so unmodelled keys survive export.</summary>
    public System.Text.Json.Nodes.JsonNode? CklbRule { get; init; }
}
