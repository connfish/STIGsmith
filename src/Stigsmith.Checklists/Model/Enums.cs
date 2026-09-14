namespace Stigsmith.Checklists.Model;

/// <summary>DISA severity. CAT I = High, CAT II = Medium, CAT III = Low.</summary>
public enum Severity
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

/// <summary>Review status of a single rule against a single host.</summary>
public enum FindingStatus
{
    NotReviewed = 0,
    Open = 1,
    NotAFinding = 2,
    NotApplicable = 3,
}

public enum ChecklistFormat
{
    Unknown = 0,
    /// <summary>STIG Viewer 2.x XML checklist.</summary>
    Ckl = 1,
    /// <summary>STIG Viewer 3.x JSON checklist.</summary>
    Cklb = 2,
    /// <summary>XCCDF 1.2 results document (OpenSCAP / SCC).</summary>
    Xccdf = 3,
    /// <summary>Asset Reporting Format collection wrapping XCCDF results.</summary>
    Arf = 4,
}

public static class SeverityExtensions
{
    public static string ToCategory(this Severity s) => s switch
    {
        Severity.High => "CAT I",
        Severity.Medium => "CAT II",
        Severity.Low => "CAT III",
        _ => "unknown",
    };

    /// <summary>Parses the lowercase severity token used by both .ckl and .cklb.</summary>
    public static Severity ParseSeverity(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        // XCCDF benchmarks also emit these; treat as informational.
        "info" or "unknown" or "" or null => Severity.Unknown,
        _ => Severity.Unknown,
    };

    public static string ToToken(this Severity s) => s switch
    {
        Severity.High => "high",
        Severity.Medium => "medium",
        Severity.Low => "low",
        _ => "unknown",
    };
}
