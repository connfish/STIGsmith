namespace Stigsmith.Api.Generation;

/// <summary>One rule to generate remediation for.</summary>
/// <param name="GenerationId">Pre-allocated so the caller can subscribe to this generation's stream before it starts.</param>
public sealed record GenerationJob(
    Guid GenerationId,
    Guid ChecklistId,
    Guid FindingId,
    string TargetOs,
    bool RequireCheckMode);
