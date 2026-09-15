using System.Threading.Channels;

namespace Stigsmith.Api.Generation;

/// <summary>One rule to generate remediation for.</summary>
/// <param name="GenerationId">Pre-allocated so the caller can subscribe to this generation's stream before it starts.</param>
public sealed record GenerationJob(
    Guid GenerationId,
    Guid ChecklistId,
    Guid FindingId,
    string TargetOs,
    bool RequireCheckMode);

/// <summary>
/// The queue between an operator asking for generation and the model actually running.
/// </summary>
/// <remarks>
/// Bounded, and full means wait rather than drop. A 1500-finding checklist can queue hundreds of rules at
/// once against a local model that handles one at a time; an unbounded channel would let the request pile up
/// tens of thousands of jobs in memory, and dropping jobs would silently skip rules an operator believes are
/// queued. Backpressure at enqueue time is the honest behaviour.
/// </remarks>
public sealed class GenerationQueue
{
    private readonly Channel<GenerationJob> _channel = Channel.CreateBounded<GenerationJob>(
        new BoundedChannelOptions(capacity: 2000)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
        });

    public ValueTask EnqueueAsync(GenerationJob job, CancellationToken cancellationToken = default) =>
        _channel.Writer.WriteAsync(job, cancellationToken);

    public IAsyncEnumerable<GenerationJob> ReadAllAsync(CancellationToken cancellationToken) =>
        _channel.Reader.ReadAllAsync(cancellationToken);

    /// <summary>Approximate depth, for reporting queue state to an operator.</summary>
    public int Depth => _channel.Reader.CanCount ? _channel.Reader.Count : -1;
}
