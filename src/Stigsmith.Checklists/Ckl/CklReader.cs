using System.Xml.Linq;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Checklists.Ckl;

/// <summary>
/// Reads the STIG Viewer 2.x .ckl format: a flat XML document whose rule metadata is a list of
/// (VULN_ATTRIBUTE, ATTRIBUTE_DATA) pairs rather than named elements. Repeated attributes are
/// legal — CCI_REF and LEGACY_ID both appear more than once per rule.
/// </summary>
public static class CklReader
{
    public static Checklist Read(string xml) => FromDocument(XDocument.Parse(xml, LoadOptions.PreserveWhitespace));

    public static Checklist ReadFile(string path) => Read(File.ReadAllText(path));

    public static Checklist FromDocument(XDocument doc)
    {
        var root = doc.Root ?? throw new ChecklistFormatException("The .ckl document has no root element.");
        if (root.Name.LocalName != "CHECKLIST")
            throw new ChecklistFormatException($"Expected root element CHECKLIST, found {root.Name.LocalName}.");

        return new Checklist
        {
            SourceFormat = ChecklistFormat.Ckl,
            Host = ReadAsset(root.Element("ASSET")),
            Stigs = [.. root.Element("STIGS")?.Elements("iSTIG").Select(ReadStig) ?? []],
        };
    }

    private static HostMetadata ReadAsset(XElement? asset)
    {
        if (asset is null) return HostMetadata.Empty;
        string V(string name) => asset.Element(name)?.Value.Trim() ?? "";
        return new HostMetadata
        {
            Role = V("ROLE") is { Length: > 0 } r ? r : "None",
            AssetType = V("ASSET_TYPE") is { Length: > 0 } a ? a : "Computing",
            HostName = V("HOST_NAME"),
            HostIp = V("HOST_IP"),
            HostMac = V("HOST_MAC"),
            HostFqdn = V("HOST_FQDN"),
            TargetComment = V("TARGET_COMMENT"),
            TechArea = V("TECH_AREA"),
            TargetKey = V("TARGET_KEY"),
            IsWebOrDatabase = string.Equals(V("WEB_OR_DATABASE"), "true", StringComparison.OrdinalIgnoreCase),
            WebDbSite = V("WEB_DB_SITE"),
            WebDbInstance = V("WEB_DB_INSTANCE"),
        };
    }

    private static StigSection ReadStig(XElement istig)
    {
        var siData = istig.Element("STIG_INFO")?.Elements("SI_DATA")
            .Select(si => new KeyValuePair<string, string>(
                si.Element("SID_NAME")?.Value.Trim() ?? "",
                si.Element("SID_DATA")?.Value ?? ""))
            .ToArray() ?? [];

        var byName = siData
            .Where(kv => kv.Key.Length > 0)
            .GroupBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
        string S(string name) => byName.TryGetValue(name, out var v) ? v.Trim() : "";

        return new StigSection
        {
            Info = new StigInfo
            {
                StigId = S("stigid"),
                Title = S("title"),
                Version = S("version"),
                ReleaseInfo = S("releaseinfo"),
                Uuid = S("uuid"),
                Classification = S("classification"),
                Description = S("description"),
                FileName = S("filename"),
                Notice = S("notice"),
                Source = S("source"),
                CustomName = S("customname"),
                DisplayName = S("title"),
                RawSiData = siData,
            },
            Findings = [.. istig.Elements("VULN").Select(ReadVuln)],
        };
    }

    private static Finding ReadVuln(XElement vuln)
    {
        var pairs = vuln.Elements("STIG_DATA")
            .Select(sd => new KeyValuePair<string, string>(
                sd.Element("VULN_ATTRIBUTE")?.Value.Trim() ?? "",
                sd.Element("ATTRIBUTE_DATA")?.Value ?? ""))
            .ToArray();

        // Repeated attributes are legal, so index as a multimap and take First() for scalars.
        var multi = pairs.Where(kv => kv.Key.Length > 0)
            .GroupBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(kv => kv.Value).ToArray(), StringComparer.OrdinalIgnoreCase);

        string A(string name) => multi.TryGetValue(name, out var v) ? v[0].Trim() : "";
        string[] All(string name) => multi.TryGetValue(name, out var v)
            ? [.. v.Select(x => x.Trim()).Where(x => x.Length > 0)]
            : [];

        var rule = new RuleContent
        {
            RuleId = A("Rule_ID"),
            GroupId = A("Vuln_Num"),
            RuleVersion = A("Rule_Ver"),
            Title = A("Rule_Title"),
            GroupTitle = A("Group_Title"),
            Severity = SeverityExtensions.ParseSeverity(A("Severity")),
            Discussion = A("Vuln_Discuss"),
            CheckContent = A("Check_Content"),
            FixText = A("Fix_Text"),
            CciRefs = All("CCI_REF"),
            LegacyIds = All("LEGACY_ID"),
            StigRef = A("STIGRef"),
            Weight = A("Weight") is { Length: > 0 } w ? w : "10.0",
            Documentable = string.Equals(A("Documentable"), "true", StringComparison.OrdinalIgnoreCase),
            Mitigations = A("Mitigations"),
            PotentialImpacts = A("Potential_Impact"),
            ThirdPartyTools = A("Third_Party_Tools"),
            MitigationControl = A("Mitigation_Control"),
            Responsibility = A("Responsibility"),
            SecurityOverrideGuidance = A("Security_Override_Guidance"),
            IaControls = A("IA_Controls"),
            FalsePositives = A("False_Positives"),
            FalseNegatives = A("False_Negatives"),
        };

        return new Finding
        {
            Rule = rule,
            Status = StatusCodes.FromCkl(vuln.Element("STATUS")?.Value),
            FindingDetails = vuln.Element("FINDING_DETAILS")?.Value ?? "",
            Comments = vuln.Element("COMMENTS")?.Value ?? "",
            SeverityOverride = vuln.Element("SEVERITY_OVERRIDE")?.Value ?? "",
            SeverityJustification = vuln.Element("SEVERITY_JUSTIFICATION")?.Value ?? "",
            Raw = new RawRulePayload { CklStigData = pairs },
        };
    }
}

public sealed class ChecklistFormatException(string message) : Exception(message);
