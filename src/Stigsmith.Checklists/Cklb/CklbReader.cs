using System.Text.Json;
using System.Text.Json.Nodes;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Checklists.Cklb;

/// <summary>
/// Reads the STIG Viewer 3.x .cklb JSON format.
/// </summary>
/// <remarks>
/// UNCERTAIN: .cklb has no published schema — this implementation was derived from observed
/// STIG Viewer 3 output and the format is documented far less well than .ckl. Specifically:
/// (a) <c>severity</c> is a lowercase token in every sample seen, but STIG Viewer also accepts
///     an <c>overrides.severity</c> object which this reader surfaces as SeverityOverride only;
/// (b) <c>rule_id</c> vs <c>rule_id_src</c> are identical in all samples — we key on rule_id;
/// (c) <c>ccis</c> is an array of strings in v1.0 files but has been seen as objects in some
///     third-party exports, so both shapes are accepted;
/// (d) <c>cklb_version</c> is echoed back unchanged rather than validated, because rejecting an
///     unknown version would refuse to read files a future STIG Viewer writes.
/// Because of (a)-(d) the whole source document is retained and re-emitted on export, so any key
/// this reader misunderstands still survives a round trip. See DECISIONS.md.
/// </remarks>
public static class CklbReader
{
    private static readonly JsonDocumentOptions ParseOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    public static Checklist Read(string json)
    {
        var node = JsonNode.Parse(json, documentOptions: ParseOptions)
            ?? throw new ChecklistFormatException("The .cklb document is empty.");
        if (node is not JsonObject root)
            throw new ChecklistFormatException("Expected a JSON object at the root of a .cklb document.");
        if (root["stigs"] is not JsonArray stigs)
            throw new ChecklistFormatException("The .cklb document has no 'stigs' array.");

        return new Checklist
        {
            SourceFormat = ChecklistFormat.Cklb,
            Title = Str(root, "title"),
            Id = Str(root, "id"),
            Host = ReadTarget(root["target_data"] as JsonObject),
            Stigs = [.. stigs.OfType<JsonObject>().Select(ReadStig)],
            RawCklb = root,
        };
    }

    public static Checklist ReadFile(string path) => Read(File.ReadAllText(path));

    private static HostMetadata ReadTarget(JsonObject? t)
    {
        if (t is null) return HostMetadata.Empty;
        return new HostMetadata
        {
            AssetType = Str(t, "target_type") is { Length: > 0 } tt ? tt : "Computing",
            HostName = Str(t, "host_name"),
            HostIp = Str(t, "ip_address"),
            HostMac = Str(t, "mac_address"),
            HostFqdn = Str(t, "fqdn"),
            TargetComment = Str(t, "comments"),
            Role = Str(t, "role") is { Length: > 0 } r ? r : "None",
            IsWebOrDatabase = Bool(t, "is_web_database"),
            TechArea = Str(t, "technology_area"),
            WebDbSite = Str(t, "web_db_site"),
            WebDbInstance = Str(t, "web_db_instance"),
        };
    }

    private static StigSection ReadStig(JsonObject stig) => new()
    {
        Info = new StigInfo
        {
            StigId = Str(stig, "stig_id"),
            Title = Str(stig, "stig_name"),
            DisplayName = Str(stig, "display_name"),
            ReleaseInfo = Str(stig, "release_info"),
            Version = Str(stig, "version"),
            Uuid = Str(stig, "uuid"),
            ReferenceIdentifier = Str(stig, "reference_identifier"),
        },
        Findings = [.. (stig["rules"] as JsonArray ?? []).OfType<JsonObject>().Select(ReadRule)],
        RawCklbStig = stig,
    };

    private static Finding ReadRule(JsonObject r) => new()
    {
        Rule = new RuleContent
        {
            RuleId = Str(r, "rule_id"),
            GroupId = Str(r, "group_id"),
            RuleVersion = Str(r, "rule_version"),
            Title = Str(r, "rule_title"),
            GroupTitle = Str(r, "group_title"),
            Severity = SeverityExtensions.ParseSeverity(Str(r, "severity")),
            Discussion = Str(r, "discussion"),
            CheckContent = Str(r, "check_content"),
            FixText = Str(r, "fix_text"),
            CciRefs = StringArray(r, "ccis"),
            LegacyIds = StringArray(r, "legacy_ids"),
            StigRef = Str(r, "stig_ref"),
            Weight = Str(r, "weight") is { Length: > 0 } w ? w : "10.0",
            Documentable = Bool(r, "documentable"),
            Mitigations = Str(r, "mitigations"),
            PotentialImpacts = Str(r, "potential_impacts"),
            ThirdPartyTools = Str(r, "third_party_tools"),
            MitigationControl = Str(r, "mitigation_control"),
            Responsibility = Str(r, "responsibility"),
            SecurityOverrideGuidance = Str(r, "security_override_guidance"),
            IaControls = Str(r, "ia_controls"),
            FalsePositives = Str(r, "false_positives"),
            FalseNegatives = Str(r, "false_negatives"),
        },
        Status = FindingStatusCodes.FromCklb(Str(r, "status")),
        FindingDetails = Str(r, "finding_details"),
        Comments = Str(r, "comments"),
        SeverityOverride = Str(r["overrides"] as JsonObject, "severity"),
        SeverityJustification = Str(r["overrides"] as JsonObject, "justification"),
        Raw = new RawRulePayload { CklbRule = r },
    };

    private static string Str(JsonObject? o, string key) => o?[key] switch
    {
        null => "",
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        var n => n.ToString(),
    };

    private static bool Bool(JsonObject? o, string key) =>
        o?[key] is JsonValue v && (v.TryGetValue<bool>(out var b) ? b
            : bool.TryParse(v.ToString(), out var p) && p);

    /// <summary>Accepts both ["CCI-000366"] and [{"cci":"CCI-000366"}] — see remarks on the class.</summary>
    private static IReadOnlyList<string> StringArray(JsonObject o, string key)
    {
        if (o[key] is not JsonArray arr) return [];
        return [.. arr.Select(n => n switch
        {
            JsonValue v when v.TryGetValue<string>(out var s) => s,
            JsonObject obj => obj.FirstOrDefault().Value?.ToString() ?? "",
            _ => n?.ToString() ?? "",
        }).Where(s => s.Length > 0)];
    }
}
