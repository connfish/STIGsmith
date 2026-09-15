using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Stigsmith.Generation.Conventions;

/// <summary>
/// Holds the indexed role for the process lifetime, built on first use.
/// </summary>
/// <remarks>
/// Lazy rather than indexed at startup: reading a role is filesystem I/O against a path the operator
/// supplied, and a wrong path or an unreadable directory should degrade convention retrieval, not stop the
/// API from booting. <see cref="Reindex"/> exists because a role is a git checkout an operator will pull —
/// the index does not watch the filesystem, so picking up changes is an explicit action.
/// </remarks>
public sealed class ConventionIndexProvider(
    IOptions<ConventionRoleOptions> options,
    ILogger<AnsibleRoleIndexer> indexerLogger)
{
    private readonly AnsibleRoleIndexer _indexer = new(indexerLogger);
    private readonly Lock _gate = new();
    private RoleIndex? _index;

    public ConventionRoleOptions Options => options.Value;

    public RoleIndex Current
    {
        get
        {
            lock (_gate)
            {
                return _index ??= _indexer.Index(options.Value);
            }
        }
    }

    public RoleIndex Reindex()
    {
        lock (_gate)
        {
            return _index = _indexer.Index(options.Value);
        }
    }
}
