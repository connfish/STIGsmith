using System.Text.RegularExpressions;

namespace Stigsmith.Checklists.Model;

/// <summary>
/// The same rule is spelled at least five ways across the formats this tool touches:
/// V-230221, SV-230221r1017044_rule, xccdf_mil.disa.stig_rule_SV-230221r1017044_rule,
/// RHEL-08-010000, and "V230221" in role task tags. Everything that needs to match a rule across
/// two sources goes through here rather than string-comparing raw ids.
/// </summary>
public static partial class RuleIdentifiers
{
    [GeneratedRegex(@"[VS]+-?(\d{4,7})", RegexOptions.IgnoreCase)]
    private static partial Regex VulnNumber();

    [GeneratedRegex(@"\b([A-Z]{2,10}-\d{2}-\d{6})\b", RegexOptions.IgnoreCase)]
    private static partial Regex StigVersionId();

    /// <summary>Extracts the bare digits of a V/SV identifier: "SV-230221r1_rule" -&gt; "230221".</summary>
    public static string Numeric(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return "";
        var m = VulnNumber().Match(id);
        return m.Success ? m.Groups[1].Value : "";
    }

    /// <summary>Extracts a STIG version id like RHEL-08-010000 from arbitrary text.</summary>
    public static string? StigVersion(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var m = StigVersionId().Match(text);
        return m.Success ? m.Groups[1].Value.ToUpperInvariant() : null;
    }

    /// <summary>
    /// Strips the XCCDF rule-id wrapper: "xccdf_mil.disa.stig_rule_SV-230221r1_rule" -&gt;
    /// "SV-230221r1_rule". Returns the input unchanged when there is no wrapper.
    /// </summary>
    public static string StripXccdfPrefix(string ruleId)
    {
        const string marker = "_rule_";
        var i = ruleId.IndexOf(marker, StringComparison.Ordinal);
        return i >= 0 ? ruleId[(i + marker.Length)..] : ruleId;
    }

    /// <summary>
    /// True when two rule identifiers, in any of their spellings, denote the same rule.
    /// Falls back to exact comparison when neither carries a V-number.
    /// </summary>
    public static bool SameRule(string? a, string? b)
    {
        var na = Numeric(a);
        var nb = Numeric(b);
        if (na.Length > 0 && nb.Length > 0) return na == nb;
        return !string.IsNullOrWhiteSpace(a) && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }
}
