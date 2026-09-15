using System.Text.Json;
using System.Text.Json.Nodes;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Checklists.Cklb;

/// <summary>
/// Writes STIG Viewer 3.x .cklb. For a checklist that came from a .cklb, the original document is
/// cloned and only the fields Stigsmith owns are overwritten — status, finding details, comments,
/// and target data. That is deliberate: .cklb has no published schema (see
/// <see cref="CklbReader"/>), so reconstructing one from scratch would drop keys the reader does
/// not understand. Checklists from other formats get a document built from the v1.0 shape.
/// </summary>
public static class CklbWriter
{
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    public static string Write(Checklist checklist)
    {
        var root = checklist.RawCklb is JsonObject original
            ? PatchExisting(original, checklist)
            : BuildFresh(checklist);
        return root.ToJsonString(WriteOptions) + "\n";
    }

    public static void WriteFile(Checklist checklist, string path) => File.WriteAllText(path, Write(checklist));

    private static JsonObject PatchExisting(JsonObject original, Checklist checklist)
    {
        var root = (JsonObject)original.DeepClone();
        root["target_data"] = TargetData(checklist.Host);
        if (checklist.Title.Length > 0) root["title"] = checklist.Title;

        // Index this checklist's findings by rule id so the clone's rule objects can be updated in
        // place; the clone's ordering, not ours, is the one that survives.
        var findings = checklist.Findings
            .GroupBy(f => f.Rule.RuleId)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        foreach (var rule in (root["stigs"] as JsonArray ?? [])
                     .OfType<JsonObject>()
                     .SelectMany(s => (s["rules"] as JsonArray ?? []).OfType<JsonObject>()))
        {
            var id = rule["rule_id"]?.ToString() ?? "";
            if (!findings.TryGetValue(id, out var f)) continue;
            rule["status"] = FindingStatusCodes.ToCklb(f.Status);
            rule["finding_details"] = f.FindingDetails;
            rule["comments"] = f.Comments;
        }

        return root;
    }

    private static JsonObject BuildFresh(Checklist checklist) => new()
    {
        ["title"] = checklist.Title,
        ["id"] = checklist.Id is { Length: > 0 } id
            ? id
            : DeterministicGuid.String("checklist", checklist.Host.HostName, checklist.Title),
        ["stigs"] = new JsonArray([.. checklist.Stigs.Select(StigNode)]),
        ["active"] = false,
        ["mode"] = 1,
        ["has_path"] = true,
        ["target_data"] = TargetData(checklist.Host),
        ["cklb_version"] = "1.0",
    };

    private static JsonObject StigNode(StigSection s) => new()
    {
        ["stig_name"] = s.Info.Title,
        ["display_name"] = s.Info.DisplayName is { Length: > 0 } d ? d : s.Info.Title,
        ["stig_id"] = s.Info.StigId,
        ["version"] = s.Info.Version,
        ["release_info"] = s.Info.ReleaseInfo,
        ["uuid"] = s.Info.Uuid is { Length: > 0 } u
            ? u
            : DeterministicGuid.String("stig", s.Info.StigId, s.Info.Version),
        ["reference_identifier"] = s.Info.ReferenceIdentifier,
        ["size"] = s.Findings.Count,
        ["rules"] = new JsonArray([.. s.Findings.Select(RuleNode)]),
    };

    private static JsonObject RuleNode(Finding f)
    {
        if (f.Raw?.CklbRule is JsonObject raw)
        {
            var clone = (JsonObject)raw.DeepClone();
            clone["status"] = FindingStatusCodes.ToCklb(f.Status);
            clone["finding_details"] = f.FindingDetails;
            clone["comments"] = f.Comments;
            return clone;
        }

        var r = f.Rule;
        return new JsonObject
        {
            ["uuid"] = DeterministicGuid.String("rule", r.RuleId, r.RuleVersion),
            ["stig_uuid"] = "",
            ["target_key"] = null,
            ["stig_ref"] = r.StigRef,
            ["group_id"] = r.GroupId,
            ["rule_id"] = r.RuleId,
            ["rule_id_src"] = r.RuleId,
            ["weight"] = r.Weight,
            ["classification"] = "",
            ["severity"] = r.Severity.ToToken(),
            ["rule_version"] = r.RuleVersion,
            ["group_title"] = r.GroupTitle,
            ["rule_title"] = r.Title,
            ["fix_text"] = r.FixText,
            ["false_positives"] = r.FalsePositives,
            ["false_negatives"] = r.FalseNegatives,
            ["discussion"] = r.Discussion,
            ["check_content"] = r.CheckContent,
            ["documentable"] = r.Documentable,
            ["mitigations"] = r.Mitigations,
            ["potential_impacts"] = r.PotentialImpacts,
            ["third_party_tools"] = r.ThirdPartyTools,
            ["mitigation_control"] = r.MitigationControl,
            ["responsibility"] = r.Responsibility,
            ["security_override_guidance"] = r.SecurityOverrideGuidance,
            ["ia_controls"] = r.IaControls,
            ["legacy_ids"] = new JsonArray([.. r.LegacyIds.Select(v => (JsonNode)JsonValue.Create(v))]),
            ["ccis"] = new JsonArray([.. r.CciRefs.Select(v => (JsonNode)JsonValue.Create(v))]),
            ["group_tree"] = new JsonArray(),
            ["status"] = FindingStatusCodes.ToCklb(f.Status),
            ["overrides"] = new JsonObject(),
            ["comments"] = f.Comments,
            ["finding_details"] = f.FindingDetails,
        };
    }

    private static JsonObject TargetData(HostMetadata h) => new()
    {
        ["target_type"] = h.AssetType,
        ["host_name"] = h.HostName,
        ["ip_address"] = h.HostIp,
        ["mac_address"] = h.HostMac,
        ["fqdn"] = h.HostFqdn,
        ["comments"] = h.TargetComment,
        ["role"] = h.Role,
        ["is_web_database"] = h.IsWebOrDatabase,
        ["technology_area"] = h.TechArea,
        ["web_db_site"] = h.WebDbSite,
        ["web_db_instance"] = h.WebDbInstance,
    };
}
