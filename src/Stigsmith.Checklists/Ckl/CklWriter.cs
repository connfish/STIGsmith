using System.Text;
using System.Xml;
using System.Xml.Linq;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Checklists.Ckl;

/// <summary>
/// Writes STIG Viewer 2.x .ckl. Where a finding was read from a .ckl, its original STIG_DATA pairs
/// are emitted verbatim so nothing this tool does not model is silently dropped; findings that came
/// from another format get a synthesized block in DISA's attribute order.
/// </summary>
public static class CklWriter
{
    /// <summary>
    /// STIG_DATA attribute order as STIG Viewer emits it. Used only for findings with no .ckl
    /// provenance; a round-tripped .ckl keeps whatever order it arrived in.
    /// </summary>
    private static readonly string[] AttributeOrder =
    [
        "Vuln_Num", "Severity", "Group_Title", "Rule_ID", "Rule_Ver", "Rule_Title", "Vuln_Discuss",
        "IA_Controls", "Check_Content", "Fix_Text", "False_Positives", "False_Negatives",
        "Documentable", "Mitigations", "Potential_Impact", "Third_Party_Tools", "Mitigation_Control",
        "Responsibility", "Security_Override_Guidance", "Check_Content_Ref", "Weight", "Class",
        "STIGRef", "TargetKey", "STIG_UUID", "LEGACY_ID", "CCI_REF",
    ];

    private static readonly string[] SiDataOrder =
    [
        "version", "classification", "customname", "stigid", "description", "filename",
        "releaseinfo", "title", "uuid", "notice", "source",
    ];

    public static string Write(Checklist checklist)
    {
        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XComment("DISA STIG Viewer :: 3.x"),
            new XElement("CHECKLIST",
                Asset(checklist.Host),
                new XElement("STIGS", checklist.Stigs.Select(Stig))));

        var settings = new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "\t",
            Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            NewLineChars = "\n",
        };

        using var buffer = new MemoryStream();
        using (var writer = XmlWriter.Create(buffer, settings))
        {
            doc.Save(writer);
        }

        return settings.Encoding.GetString(buffer.ToArray()) + "\n";
    }

    public static void WriteFile(Checklist checklist, string path) => File.WriteAllText(path, Write(checklist), new UTF8Encoding(false));

    private static XElement Asset(HostMetadata h) => new("ASSET",
        new XElement("ROLE", h.Role),
        new XElement("ASSET_TYPE", h.AssetType),
        new XElement("HOST_NAME", h.HostName),
        new XElement("HOST_IP", h.HostIp),
        new XElement("HOST_MAC", h.HostMac),
        new XElement("HOST_FQDN", h.HostFqdn),
        new XElement("TARGET_COMMENT", h.TargetComment),
        new XElement("TECH_AREA", h.TechArea),
        new XElement("TARGET_KEY", h.TargetKey),
        new XElement("WEB_OR_DATABASE", h.IsWebOrDatabase ? "true" : "false"),
        new XElement("WEB_DB_SITE", h.WebDbSite),
        new XElement("WEB_DB_INSTANCE", h.WebDbInstance));

    private static XElement Stig(StigSection section) => new("iSTIG",
        new XElement("STIG_INFO", SiData(section.Info).Select(kv =>
            new XElement("SI_DATA", new XElement("SID_NAME", kv.Key), new XElement("SID_DATA", kv.Value)))),
        section.Findings.Select(Vuln));

    private static IEnumerable<KeyValuePair<string, string>> SiData(StigInfo info)
    {
        if (info.RawSiData is { Count: > 0 } raw) return raw;

        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["version"] = info.Version,
            ["classification"] = info.Classification,
            ["customname"] = info.CustomName,
            ["stigid"] = info.StigId,
            ["description"] = info.Description,
            ["filename"] = info.FileName,
            ["releaseinfo"] = info.ReleaseInfo,
            ["title"] = info.Title,
            ["uuid"] = info.Uuid,
            ["notice"] = info.Notice,
            ["source"] = info.Source,
        };
        return SiDataOrder.Select(k => new KeyValuePair<string, string>(k, map[k]));
    }

    private static XElement Vuln(Finding f) => new("VULN",
        StigData(f).Select(kv =>
            new XElement("STIG_DATA", new XElement("VULN_ATTRIBUTE", kv.Key), new XElement("ATTRIBUTE_DATA", kv.Value))),
        new XElement("STATUS", StatusCodes.ToCkl(f.Status)),
        new XElement("FINDING_DETAILS", f.FindingDetails),
        new XElement("COMMENTS", f.Comments),
        new XElement("SEVERITY_OVERRIDE", f.SeverityOverride),
        new XElement("SEVERITY_JUSTIFICATION", f.SeverityJustification));

    private static IEnumerable<KeyValuePair<string, string>> StigData(Finding f)
    {
        if (f.Raw?.CklStigData is { Count: > 0 } raw) return raw;

        var r = f.Rule;
        var scalars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Vuln_Num"] = r.GroupId,
            ["Severity"] = r.Severity.ToToken(),
            ["Group_Title"] = r.GroupTitle,
            ["Rule_ID"] = r.RuleId,
            ["Rule_Ver"] = r.RuleVersion,
            ["Rule_Title"] = r.Title,
            ["Vuln_Discuss"] = r.Discussion,
            ["IA_Controls"] = r.IaControls,
            ["Check_Content"] = r.CheckContent,
            ["Fix_Text"] = r.FixText,
            ["False_Positives"] = r.FalsePositives,
            ["False_Negatives"] = r.FalseNegatives,
            ["Documentable"] = r.Documentable ? "true" : "false",
            ["Mitigations"] = r.Mitigations,
            ["Potential_Impact"] = r.PotentialImpacts,
            ["Third_Party_Tools"] = r.ThirdPartyTools,
            ["Mitigation_Control"] = r.MitigationControl,
            ["Responsibility"] = r.Responsibility,
            ["Security_Override_Guidance"] = r.SecurityOverrideGuidance,
            ["Check_Content_Ref"] = "M",
            ["Weight"] = r.Weight,
            ["Class"] = "Unclass",
            ["STIGRef"] = r.StigRef,
            ["TargetKey"] = "",
            ["STIG_UUID"] = "",
        };

        var result = new List<KeyValuePair<string, string>>();
        foreach (var key in AttributeOrder)
        {
            if (key is "LEGACY_ID")
                result.AddRange(r.LegacyIds.Select(v => new KeyValuePair<string, string>(key, v)));
            else if (key is "CCI_REF")
                result.AddRange(r.CciRefs.Select(v => new KeyValuePair<string, string>(key, v)));
            else
                result.Add(new(key, scalars[key]));
        }
        return result;
    }
}
