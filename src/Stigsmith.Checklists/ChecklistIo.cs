using Stigsmith.Checklists.Ckl;
using Stigsmith.Checklists.Cklb;
using Stigsmith.Checklists.Model;
using Stigsmith.Checklists.Xccdf;

namespace Stigsmith.Checklists;

/// <summary>
/// Front door for checklist import and export. Detects format from content rather than extension —
/// operators rename these files constantly and a .xml that is really an ARF collection is common.
/// </summary>
public static class ChecklistIo
{
    public static ChecklistFormat Detect(string content)
    {
        var head = content.AsSpan(0, Math.Min(content.Length, 4096)).ToString();
        var trimmed = head.TrimStart('﻿', ' ', '\t', '\r', '\n');

        if (trimmed.StartsWith('{')) return ChecklistFormat.Cklb;
        if (trimmed.Contains("<CHECKLIST", StringComparison.Ordinal)) return ChecklistFormat.Ckl;
        if (trimmed.Contains("asset-report-collection", StringComparison.Ordinal)) return ChecklistFormat.Arf;
        if (trimmed.Contains("<Benchmark", StringComparison.Ordinal) || trimmed.Contains("<TestResult", StringComparison.Ordinal)
            || trimmed.Contains("xccdf", StringComparison.OrdinalIgnoreCase)) return ChecklistFormat.Xccdf;
        return ChecklistFormat.Unknown;
    }

    public static Checklist Read(string content) => Detect(content) switch
    {
        ChecklistFormat.Ckl => CklReader.Read(content),
        ChecklistFormat.Cklb => CklbReader.Read(content),
        ChecklistFormat.Xccdf or ChecklistFormat.Arf => XccdfReader.Read(content),
        _ => throw new ChecklistFormatException(
            "Could not identify the file as .ckl, .cklb, XCCDF results, or ARF."),
    };

    public static Checklist ReadFile(string path) => Read(File.ReadAllText(path));

    /// <summary>Exports to .ckl or .cklb. XCCDF and ARF are import-only: they are scanner output, not review artifacts.</summary>
    public static string Write(Checklist checklist, ChecklistFormat format) => format switch
    {
        ChecklistFormat.Ckl => CklWriter.Write(checklist),
        ChecklistFormat.Cklb => CklbWriter.Write(checklist),
        _ => throw new ArgumentOutOfRangeException(nameof(format), format, "Export supports .ckl and .cklb only."),
    };

    public static void WriteFile(Checklist checklist, ChecklistFormat format, string path) =>
        File.WriteAllText(path, Write(checklist, format));
}
