namespace Stigsmith.Api.Validation;

/// <summary>One generated remediation to validate.</summary>
public sealed record ValidationJob(Guid ValidationRunId, Guid ChecklistId, Guid GenerationId);

/// <summary>Validation progress pushed to subscribers, on the same hub as generation.</summary>
public static class ValidationEvents
{
    public const string Started = "validationStarted";
    public const string Stage = "validationStage";
    public const string Completed = "validationCompleted";
}

public sealed record ValidationStarted(Guid ValidationRunId, Guid GenerationId, string RuleVersion, string Image);

public sealed record ValidationStageEvent(
    Guid ValidationRunId, string Stage, bool Passed, int ExitCode, double Seconds, string Output);

public sealed record ValidationCompleted(
    Guid ValidationRunId,
    Guid GenerationId,
    string RuleVersion,
    string Outcome,
    string? FailedStage,
    int Attempts,
    string ScanStatusBefore,
    string ScanStatusAfter,
    string VerifiedBy,
    int IdempotencyChangedCount,
    string Summary);
