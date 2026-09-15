using System.Threading.Channels;

namespace Stigsmith.Api.Validation;

/// <summary>One generated remediation to validate.</summary>
public sealed record ValidationJob(Guid ValidationRunId, Guid ChecklistId, Guid GenerationId);

/// <summary>
/// The queue between an operator asking for validation and the container actually running.
/// </summary>
/// <remarks>
/// Separate from the generation queue on purpose. Validation is far slower than generation — two applies and a scan in
/// a cold container — and sharing one queue would let a batch of validations starve the generation of rules an operator
/// is waiting to read. Bounded with <c>FullMode.Wait</c> for the same reason as the generation queue: dropping a job
/// would silently skip a rule the operator believes is queued.
/// </remarks>
public sealed class ValidationQueue
{
    private readonly Channel<ValidationJob> _channel = Channel.CreateBounded<ValidationJob>(
        new BoundedChannelOptions(capacity: 2000)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
        });

    public ValueTask EnqueueAsync(ValidationJob job, CancellationToken cancellationToken = default) =>
        _channel.Writer.WriteAsync(job, cancellationToken);

    public IAsyncEnumerable<ValidationJob> ReadAllAsync(CancellationToken cancellationToken) =>
        _channel.Reader.ReadAllAsync(cancellationToken);

    public int Depth => _channel.Reader.CanCount ? _channel.Reader.Count : -1;
}

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
