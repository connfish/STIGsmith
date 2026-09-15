namespace Stigsmith.Validation;

/// <summary>
/// A disposable container to apply generated remediation in.
/// </summary>
/// <remarks>
/// Behind an interface for one reason only: the loop's decision logic — which stage failed, whether to repair,
/// when to give up and ask a human, what evidence to keep — is the part worth testing exhaustively, and it can
/// be tested against a scripted sandbox on a machine with no container runtime. The real implementation is
/// <see cref="Docker.DockerValidationSandbox"/> and there is no mock of it in the test suite: a mocked container
/// that never applies a playbook would report success about nothing.
/// </remarks>
public interface IValidationSandbox
{
    /// <summary>The image sessions are created from, for the evidence record.</summary>
    string Image { get; }

    /// <summary>True when a container runtime is reachable. Checked before queueing work.</summary>
    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);

    /// <summary>Starts a fresh container. Disposing the session destroys it.</summary>
    Task<IValidationSession> StartAsync(CancellationToken cancellationToken = default);
}

/// <summary>One container's lifetime. Disposal removes it, including on the failure paths.</summary>
public interface IValidationSession : IAsyncDisposable
{
    string ContainerId { get; }

    /// <summary>Writes a file into the container, creating parent directories.</summary>
    Task WriteFileAsync(string path, string content, CancellationToken cancellationToken = default);

    /// <summary>Runs a command and captures both streams. Never throws on a non-zero exit — that is data.</summary>
    Task<ExecResult> ExecAsync(string command, CancellationToken cancellationToken = default);
}
