using System.Net;
using System.Xml.Linq;
using Stigsmith.Checklists.Ckl;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Checklists.Xccdf;

/// <summary>
/// Reads XCCDF 1.1/1.2 results and ARF collections produced by OpenSCAP (<c>oscap</c>) and SCC.
/// </summary>
/// <remarks>
/// Rather than walking each container format's nesting, this reads by element name across the whole
/// document: every <c>Benchmark</c> found contributes rule content, every <c>TestResult</c>
/// contributes results and target data. A plain XCCDF result file, an XCCDF file with its benchmark
/// inlined, and an ARF collection all reduce to the same two sets, so one traversal covers all
/// three and a new container layout does not need new code.
/// <para>
/// UNCERTAIN: a results-only XCCDF file (no Benchmark present) cannot supply fixtext or check
/// content. Findings from such a file carry an empty FixText, which classification reports as
/// needs-review rather than guessing. Import the matching benchmark or .ckl to get full content.
/// </para>
/// </remarks>
public static class XccdfReader
{
    public static Checklist Read(string xml) => FromDocument(XDocument.Parse(xml));

    public static Checklist ReadFile(string path) => Read(File.ReadAllText(path));

    public static Checklist FromDocument(XDocument doc)
    {
        var root = doc.Root ?? throw new ChecklistFormatException("The XCCDF/ARF document has no root element.");
        var isArf = root.Name.LocalName is "asset-report-collection";

        var benchmarks = Descendants(root, "Benchmark").ToArray();
        var testResults = Descendants(root, "TestResult").ToArray();
        if (benchmarks.Length == 0 && testResults.Length == 0)
            throw new ChecklistFormatException("No Benchmark or TestResult element found; this is not an XCCDF results or ARF document.");

        var rules = benchmarks
            .SelectMany(b => Descendants(b, "Rule").Select(r => ReadRule(r, BenchmarkRef(b))))
            .GroupBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var info = benchmarks.Length > 0 ? ReadBenchmarkInfo(benchmarks[0]) : new StigInfo();

        // A TestResult without a Benchmark still names its rules; synthesize placeholder content so
        // the finding is visible in triage rather than silently dropped.
        var findings = testResults
            .SelectMany(tr => Descendants(tr, "rule-result"))
            .Select(rr => ReadRuleResult(rr, rules, info))
            .Where(f => f is not null)
            .Select(f => f!)
            .ToArray();

        return new Checklist
        {
            SourceFormat = isArf ? ChecklistFormat.Arf : ChecklistFormat.Xccdf,
            Title = info.Title,
            Id = testResults.FirstOrDefault()?.Attribute("id")?.Value ?? "",
            Host = testResults.Length > 0 ? ReadTarget(testResults[0]) : HostMetadata.Empty,
            Stigs = [new StigSection { Info = info, Findings = findings }],
        };
    }

    private static IEnumerable<XElement> Descendants(XElement root, string localName) =>
        root.DescendantsAndSelf().Where(e => e.Name.LocalName == localName);

    private static XElement? Child(XElement parent, string localName) =>
        parent.Elements().FirstOrDefault(e => e.Name.LocalName == localName);

    private static string ChildValue(XElement parent, string localName) => Child(parent, localName)?.Value.Trim() ?? "";

    private static StigInfo ReadBenchmarkInfo(XElement benchmark) => new()
    {
        StigId = benchmark.Attribute("id")?.Value ?? "",
        Title = ChildValue(benchmark, "title"),
        DisplayName = ChildValue(benchmark, "title"),
        Version = ChildValue(benchmark, "version"),
        Description = ChildValue(benchmark, "description"),
        ReleaseInfo = Child(benchmark, "version")?.Attribute("time")?.Value ?? "",
    };

    private static string BenchmarkRef(XElement benchmark)
    {
        var title = ChildValue(benchmark, "title");
        var version = ChildValue(benchmark, "version");
        return version.Length > 0 ? $"{title} :: Version {version}" : title;
    }

    private static HostMetadata ReadTarget(XElement testResult)
    {
        var facts = Descendants(testResult, "fact")
            .Where(f => f.Attribute("name") is not null)
            .GroupBy(f => f.Attribute("name")!.Value, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Value.Trim(), StringComparer.OrdinalIgnoreCase);

        string Fact(string suffix) => facts
            .FirstOrDefault(kv => kv.Key.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)).Value ?? "";

        var target = ChildValue(testResult, "target");
        return new HostMetadata
        {
            HostName = target,
            HostFqdn = Fact(":fqdn") is { Length: > 0 } f ? f : (target.Contains('.') ? target : ""),
            // target-address repeats for each interface; the first non-loopback is the useful one.
            HostIp = Descendants(testResult, "target-address")
                .Select(e => e.Value.Trim())
                .FirstOrDefault(v => v.Length > 0 && v != "127.0.0.1" && v != "::1") ?? Fact(":ipv4"),
            HostMac = Fact(":mac"),
            AssetType = "Computing",
            Role = "None",
        };
    }

    private static RuleContent ReadRule(XElement rule, string benchmarkRef)
    {
        var id = RuleIdentifiers.StripXccdfPrefix(rule.Attribute("id")?.Value ?? "");
        var description = ChildValue(rule, "description");

        return new RuleContent
        {
            RuleId = id,
            GroupId = GroupIdOf(rule),
            RuleVersion = ChildValue(rule, "version"),
            Title = ChildValue(rule, "title"),
            GroupTitle = rule.Parent is { } g && g.Name.LocalName == "Group" ? ChildValue(g, "title") : "",
            Severity = SeverityExtensions.ParseSeverity(rule.Attribute("severity")?.Value),
            Discussion = DisaTag(description, "VulnDiscussion"),
            FalsePositives = DisaTag(description, "FalsePositives"),
            FalseNegatives = DisaTag(description, "FalseNegatives"),
            Documentable = string.Equals(DisaTag(description, "Documentable"), "true", StringComparison.OrdinalIgnoreCase),
            Mitigations = DisaTag(description, "Mitigations"),
            PotentialImpacts = DisaTag(description, "PotentialImpacts"),
            ThirdPartyTools = DisaTag(description, "ThirdPartyTools"),
            MitigationControl = DisaTag(description, "MitigationControl"),
            Responsibility = DisaTag(description, "Responsibility"),
            SecurityOverrideGuidance = DisaTag(description, "SeverityOverrideGuidance"),
            IaControls = DisaTag(description, "IAControls"),
            FixText = ChildValue(rule, "fixtext"),
            CheckContent = CheckContentOf(rule),
            CciRefs = [.. Descendants(rule, "ident")
                .Select(e => e.Value.Trim())
                .Where(v => v.StartsWith("CCI-", StringComparison.OrdinalIgnoreCase))],
            LegacyIds = [.. Descendants(rule, "ident")
                .Select(e => e.Value.Trim())
                .Where(v => v.StartsWith("V-", StringComparison.OrdinalIgnoreCase) || v.StartsWith("SV-", StringComparison.OrdinalIgnoreCase))],
            StigRef = benchmarkRef,
            Weight = rule.Attribute("weight")?.Value ?? "10.0",
        };
    }

    private static string GroupIdOf(XElement rule)
    {
        if (rule.Parent is { } parent && parent.Name.LocalName == "Group")
        {
            var raw = parent.Attribute("id")?.Value ?? "";
            const string marker = "_group_";
            var i = raw.IndexOf(marker, StringComparison.Ordinal);
            if (i >= 0) return raw[(i + marker.Length)..];
        }
        // Fall back to the V-number embedded in the rule id.
        var n = RuleIdentifiers.Numeric(rule.Attribute("id")?.Value);
        return n.Length > 0 ? $"V-{n}" : "";
    }

    /// <summary>
    /// Manual STIG benchmarks put the verification prose in check/check-content; automated
    /// benchmarks point check-content-ref at an OVAL definition instead, in which case there is no
    /// prose to return and the OVAL reference is recorded so it is not lost.
    /// </summary>
    private static string CheckContentOf(XElement rule)
    {
        foreach (var check in Descendants(rule, "check"))
        {
            if (Child(check, "check-content") is { } inline && inline.Value.Trim().Length > 0)
                return inline.Value.Trim();
        }
        var oval = Descendants(rule, "check-content-ref").FirstOrDefault()?.Attribute("name")?.Value;
        return oval is { Length: > 0 } ? $"Automated check via OVAL definition {oval}." : "";
    }

    /// <summary>
    /// DISA packs its per-rule metadata into the XCCDF description as escaped pseudo-XML
    /// (&lt;VulnDiscussion&gt;...&lt;/VulnDiscussion&gt;&lt;FalsePositives/&gt;...). The description
    /// is not valid XML on its own — the tags are unnamespaced and siblings without a root — so it
    /// is extracted textually rather than re-parsed.
    /// </summary>
    internal static string DisaTag(string description, string tag)
    {
        if (description.Length == 0) return "";
        var text = description.Contains("&lt;", StringComparison.Ordinal) ? WebUtility.HtmlDecode(description) : description;
        var open = $"<{tag}>";
        var close = $"</{tag}>";
        var start = text.IndexOf(open, StringComparison.OrdinalIgnoreCase);
        if (start < 0) return "";
        start += open.Length;
        var end = text.IndexOf(close, start, StringComparison.OrdinalIgnoreCase);
        return end < 0 ? "" : text[start..end].Trim();
    }

    private static Finding? ReadRuleResult(XElement rr, IReadOnlyDictionary<string, RuleContent> rules, StigInfo info)
    {
        var idref = rr.Attribute("idref")?.Value;
        if (string.IsNullOrWhiteSpace(idref)) return null;

        var id = RuleIdentifiers.StripXccdfPrefix(idref);
        var result = ChildValue(rr, "result");
        var rule = rules.TryGetValue(id, out var known)
            ? known
            : new RuleContent
            {
                RuleId = id,
                GroupId = RuleIdentifiers.Numeric(id) is { Length: > 0 } n ? $"V-{n}" : "",
                Title = $"(rule content not present in this results document: {id})",
                Severity = SeverityExtensions.ParseSeverity(rr.Attribute("severity")?.Value),
                StigRef = info.Title,
            };

        var messages = Descendants(rr, "message").Select(m => m.Value.Trim()).Where(v => v.Length > 0).ToArray();

        return new Finding
        {
            Rule = rule,
            Status = StatusCodes.FromXccdf(result),
            FindingDetails = string.Join("\n", new[] { $"SCAP result: {result}" }.Concat(messages)),
            Comments = "",
        };
    }
}
