using System.Threading.Channels;

namespace Stigsmith.Api;

/// <summary>
/// The bounded queue between an operator's request and the single worker that drains it. Full means wait,
/// not drop: a 1500-finding checklist can queue hundreds of jobs against a model or a container that handles
/// one at a time, and silently dropping a job would skip a rule the operator believes is queued.
/// </summary>
public sealed class JobQueue<TJob>
{
    private readonly Channel<TJob> _channel = Channel.CreateBounded<TJob>(
        new BoundedChannelOptions(capacity: 2000) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });

    public ValueTask EnqueueAsync(TJob job, CancellationToken cancellationToken = default) =>
        _channel.Writer.WriteAsync(job, cancellationToken);

    public IAsyncEnumerable<TJob> ReadAllAsync(CancellationToken cancellationToken) =>
        _channel.Reader.ReadAllAsync(cancellationToken);

    /// <summary>Approximate depth, for reporting queue state to an operator.</summary>
    public int Depth => _channel.Reader.CanCount ? _channel.Reader.Count : -1;
}
