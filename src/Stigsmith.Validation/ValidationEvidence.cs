using System.Text.Json;
using System.Text.Json.Serialization;

namespace Stigsmith.Validation;

/// <summary>The result of running one command in the sandbox.</summary>
public sealed record ExecResult(int ExitCode, string Stdout, string Stderr)
{
    public bool Succeeded => ExitCode == 0;

    /// <summary>Both streams, in the order an operator would read them.</summary>
    public string Combined => string.Join('\n', new[] { Stdout, Stderr }.Where(s => s.Length > 0));

    public static ExecResult NotRun => new(-1, "", "not run");
}

/// <summary>
/// What one stage of the loop did.
/// </summary>
/// <remarks>
/// Recorded per stage rather than as one blob, because "it failed" is useless to an ISSO and "it linted clean,
/// applied 1 changed task, the re-scan flipped the finding to pass, and the second apply reported 0 changed" is
/// the thing that makes generated YAML acceptable.
/// </remarks>
public sealed record StageEvidence(
    ValidationStage Stage,
    bool Passed,
    string Command,
    int ExitCode,
    string Output,
    TimeSpan Duration)
{
    public static StageEvidence Skipped(ValidationStage stage, string why) =>
        new(stage, Passed: false, Command: "", ExitCode: -1, Output: why, Duration: TimeSpan.Zero);
}

/// <summary>
/// The full evidence bundle for one pass through the validation loop. This is the artifact that turns generated
/// YAML into something an operator can put in front of an ISSO, so it is stored verbatim and in full.
/// </summary>
public sealed record ValidationEvidence
{
    public required ValidationOutcome Outcome { get; init; }

    /// <summary>The stage that failed, or null when everything passed.</summary>
    public ValidationStage? FailedStage { get; init; }

    /// <summary>0 for the first attempt, 1 for the single repair attempt.</summary>
    public int RepairAttempt { get; init; }

    public required string ContainerImage { get; init; }

    public IReadOnlyList<StageEvidence> Stages { get; init; } = [];

    /// <summary>The rule's status before remediation, as the verifier reported it.</summary>
    public string ScanStatusBefore { get; init; } = "";

    /// <summary>The rule's status after remediation. "pass" is the whole point.</summary>
    public string ScanStatusAfter { get; init; } = "";

    /// <summary>
    /// How the finding was verified. Recorded because it changes how much the result is worth: an
    /// <see cref="ComplianceVerifierKind.Oscap"/> result is a real SCAP scan, a
    /// <see cref="ComplianceVerifierKind.CheckContent"/> result is DISA's own check command run as a shell test.
    /// </summary>
    public ComplianceVerifierKind VerifiedBy { get; init; }

    /// <summary>Tasks reported changed on the second apply. Zero is the idempotency requirement; -1 means not measured.</summary>
    public int IdempotencyChangedCount { get; init; } = -1;

    /// <summary>The playbook as applied, so the evidence is self-contained.</summary>
    public string Playbook { get; init; } = "";

    public string Summary { get; init; } = "";

    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAt { get; init; }

    public StageEvidence? Stage(ValidationStage stage) => Stages.FirstOrDefault(s => s.Stage == stage);

    public string ToJson() => JsonSerializer.Serialize(this, EvidenceJson.Options);
}

public enum ComplianceVerifierKind
{
    /// <summary>Not verified at all.</summary>
    None = 0,

    /// <summary>A real <c>oscap xccdf eval</c> against an installed SCAP datastream.</summary>
    Oscap = 1,

    /// <summary>DISA's own check content, turned into a shell test and run in the sandbox.</summary>
    CheckContent = 2,
}

internal static class EvidenceJson
{
    internal static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };
}
