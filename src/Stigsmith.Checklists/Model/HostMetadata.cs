namespace Stigsmith.Checklists.Model;

/// <summary>
/// The host-identifying half of a checklist, kept in its own type so it never travels with
/// <see cref="RuleContent"/>. Constraint 3: none of these fields may reach a language model.
/// </summary>
public sealed record HostMetadata
{
    public static readonly HostMetadata Empty = new();

    public string HostName { get; init; } = "";
    public string HostIp { get; init; } = "";
    public string HostMac { get; init; } = "";
    public string HostFqdn { get; init; } = "";
    public string TargetComment { get; init; } = "";
    public string Role { get; init; } = "None";
    public string AssetType { get; init; } = "Computing";
    public string TechArea { get; init; } = "";
    public string TargetKey { get; init; } = "";
    public bool IsWebOrDatabase { get; init; }
    public string WebDbSite { get; init; } = "";
    public string WebDbInstance { get; init; } = "";

    /// <summary>
    /// Every value on this record, for the prompt-hygiene test to assert absence of. Empty values
    /// are excluded because "the prompt does not contain the empty string" is not a useful claim.
    /// </summary>
    public IEnumerable<string> IdentifyingValues() =>
        new[] { HostName, HostIp, HostMac, HostFqdn, TargetComment, TechArea, TargetKey, WebDbSite, WebDbInstance }
            .Where(v => !string.IsNullOrWhiteSpace(v));

    public string DisplayName =>
        new[] { HostName, HostFqdn, HostIp }.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "(unnamed host)";
}
