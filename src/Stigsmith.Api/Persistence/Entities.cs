using Stigsmith.Checklists.Model;
using Stigsmith.Rules;
using Stigsmith.Validation;

namespace Stigsmith.Api.Persistence;

/// <summary>
/// An imported checklist. The original document text is kept so export can fall back to lossless
/// re-emission and so an operator can always retrieve exactly what they handed the tool.
/// </summary>
public sealed class ChecklistRecord
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public string Title { get; set; } = "";
    public ChecklistFormat SourceFormat { get; set; }
    public DateTimeOffset ImportedAt { get; set; } = DateTimeOffset.UtcNow;
    public string FileName { get; set; } = "";

    // Host metadata. Stored on the checklist, never on a finding, so a query that feeds generation
    // cannot pick host fields up by joining. See constraint 3 in the README.
    public string HostName { get; set; } = "";
    public string HostIp { get; set; } = "";
    public string HostMac { get; set; } = "";
    public string HostFqdn { get; set; } = "";
    public string TargetComment { get; set; } = "";
    public string Role { get; set; } = "None";
    public string AssetType { get; set; } = "Computing";
    public string TechArea { get; set; } = "";
    public string TargetKey { get; set; } = "";
    public bool IsWebOrDatabase { get; set; }
    public string WebDbSite { get; set; } = "";
    public string WebDbInstance { get; set; } = "";

    public string StigId { get; set; } = "";
    public string StigTitle { get; set; } = "";
    public string StigVersion { get; set; } = "";
    public string StigReleaseInfo { get; set; } = "";

    /// <summary>The document exactly as imported, for lossless re-export.</summary>
    public string OriginalDocument { get; set; } = "";

    public List<FindingRecord> Findings { get; set; } = [];
}

/// <summary>One rule as reviewed against the checklist's host, plus this tool's classification of it.</summary>
public sealed class FindingRecord
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid ChecklistId { get; set; }
    public ChecklistRecord? Checklist { get; set; }

    public string RuleId { get; set; } = "";
    public string GroupId { get; set; } = "";
    public string NumericId { get; set; } = "";
    public string RuleVersion { get; set; } = "";
    public string Title { get; set; } = "";
    public Severity Severity { get; set; }
    public FindingStatus Status { get; set; }
    public string FindingDetails { get; set; } = "";
    public string Comments { get; set; } = "";
    public string FixText { get; set; } = "";
    public string CheckContent { get; set; } = "";
    public string Discussion { get; set; } = "";
    public string CciRefs { get; set; } = "";

    // M3 classification output.
    public Automatability Automatability { get; set; }
    public string ClassificationReason { get; set; } = "";
    public bool IsHighRisk { get; set; }
    public string RiskCategories { get; set; } = "";

    public List<GenerationRecord> Generations { get; set; } = [];
}

/// <summary>
/// A single model call and its result. Prompt, model, and parameters are persisted verbatim so any
/// run can be reproduced and audited — an ISSO asking "what exactly did the model see?" gets an
/// answer, and the prompt-hygiene guarantee is checkable after the fact, not just at test time.
/// </summary>
public sealed class GenerationRecord
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid FindingId { get; set; }
    public FindingRecord? Finding { get; set; }

    public string Provider { get; set; } = "";
    public string Model { get; set; } = "";
    public string ParametersJson { get; set; } = "{}";
    public string SystemPrompt { get; set; } = "";
    public string UserPrompt { get; set; } = "";
    public string PromptSha256 { get; set; } = "";
    public string RawResponse { get; set; } = "";
    public string Yaml { get; set; } = "";
    public string RetrievedExampleIds { get; set; } = "";
    public string TargetOs { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public int PromptTokens { get; set; }
    public int CompletionTokens { get; set; }
    public string? Error { get; set; }

    public List<ValidationRunRecord> ValidationRuns { get; set; } = [];
}

/// <summary>The evidence bundle for one pass through the validation loop.</summary>
public sealed class ValidationRunRecord
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid GenerationId { get; set; }
    public GenerationRecord? Generation { get; set; }

    public ValidationOutcome Outcome { get; set; }
    public string FailedStage { get; set; } = "";
    public int RepairAttempt { get; set; }

    public string LintOutput { get; set; } = "";
    public string SyntaxCheckOutput { get; set; } = "";
    public string ApplyOutput { get; set; } = "";
    public string ScanStatusBefore { get; set; } = "";
    public string ScanStatusAfter { get; set; } = "";
    public string IdempotencyOutput { get; set; } = "";
    public int IdempotencyChangedCount { get; set; } = -1;
    public string ContainerImage { get; set; } = "";
    public string EvidenceJson { get; set; } = "{}";

    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAt { get; set; }
}
