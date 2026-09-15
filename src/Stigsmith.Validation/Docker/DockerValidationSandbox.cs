using System.Formats.Tar;
using System.Text;
using Docker.DotNet;
using Docker.DotNet.Models;
using Microsoft.Extensions.Logging;

namespace Stigsmith.Validation.Docker;

/// <summary>
/// Runs the validation loop in a throwaway Docker container.
/// </summary>
/// <remarks>
/// <para>
/// One container per attempt, removed on disposal including on every failure path — a validation run that left
/// containers behind would fill an operator's disk over a 1500-finding checklist.
/// </para>
/// <para>
/// <b>A container is not a host, and that limits what the loop can prove.</b> Remediation that sets a kernel
/// parameter, enables a systemd unit, or rewrites the bootloader cannot succeed in an unprivileged container, and the
/// loop honestly reports it as a failed apply rather than a pass. That is the right outcome — better a rule marked
/// needs-human-review than a false pass — but it means the container is a good validator for file and package
/// remediation and a poor one for kernel, boot, and service rules. Running privileged widens what applies at the cost
/// of giving an untrusted generated playbook real capabilities against the host kernel, which is a decision for the
/// operator and not a default.
/// </para>
/// </remarks>
public sealed class DockerValidationSandbox : IValidationSandbox, IDisposable
{
    private readonly IDockerClient _client;
    private readonly IDisposable? _ownedClient;
    private readonly ValidationOptions _options;
    private readonly ILogger<DockerValidationSandbox>? _logger;

    public DockerValidationSandbox(
        ValidationOptions options,
        ILogger<DockerValidationSandbox>? logger = null,
        IDockerClient? client = null)
    {
        _options = options;
        _logger = logger;
        if (client is not null)
        {
            _client = client;
            return;
        }

        // The builder reads DOCKER_HOST and the active docker context, so Docker Desktop, colima, Podman and a
        // rootless daemon all work without any Stigsmith-specific configuration.
        var owned = new DockerClientBuilder().Build();
        _client = owned;
        _ownedClient = owned;
    }

    public string Image => _options.Image;

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await _client.System.PingAsync(cancellationToken);
            // Never pulled: target environments are air-gapped, and an operator who has not built the image
            // needs to be told so, not handed a container with no ansible in it.
            await _client.Images.InspectImageAsync(_options.Image, cancellationToken);
            return true;
        }
        catch (DockerImageNotFoundException)
        {
            _logger?.LogWarning("Validation image {Image} is not present. Build it with: make image", _options.Image);
            return false;
        }
        catch (Exception ex) when (ex is DockerApiException or DockerConfigurationException or HttpRequestException
                                      or TimeoutException or IOException or TaskCanceledException)
        {
            _logger?.LogWarning(ex, "No Docker daemon is reachable, so validation cannot run.");
            return false;
        }
    }

    public async Task<IValidationSession> StartAsync(CancellationToken cancellationToken = default)
    {
        var created = await _client.Containers.CreateContainerAsync(
            new CreateContainerParameters
            {
                Image = _options.Image,
                // Keep the container alive so each stage can be exec'd into it. `sleep infinity` rather than a shell,
                // so nothing is waiting on stdin.
                Cmd = ["sleep", "infinity"],
                Tty = false,
                AttachStdout = false,
                AttachStderr = false,
                Labels = new Dictionary<string, string> { ["stigsmith"] = "validation" },
                HostConfig = new HostConfig
                {
                    AutoRemove = false,
                    Privileged = _options.Privileged,
                    // A generated playbook is untrusted input. Cap what a runaway task can consume so one bad rule
                    // cannot take the host down with it.
                    Memory = _options.MemoryLimitBytes,
                    NanoCPUs = _options.CpuLimit,
                },
            },
            cancellationToken);

        try
        {
            await _client.Containers.StartContainerAsync(created.ID, new ContainerStartParameters(), cancellationToken);
        }
        catch
        {
            // Created but never handed to a session, so nothing else would ever remove it.
            await RemoveAsync(_client, created.ID, _logger);
            throw;
        }

        _logger?.LogDebug("Started validation container {ContainerId} from {Image}.", created.ID[..12], _options.Image);
        return new DockerSession(_client, created.ID, _logger);
    }

    public void Dispose() => _ownedClient?.Dispose();

    private static async Task RemoveAsync(IDockerClient client, string containerId, ILogger? logger)
    {
        try
        {
            await client.Containers.RemoveContainerAsync(
                containerId,
                new ContainerRemoveParameters { Force = true, RemoveVolumes = true },
                CancellationToken.None);
        }
        catch (Exception ex) when (ex is DockerApiException or HttpRequestException or IOException)
        {
            // Already tearing down. A container that cannot be removed is worth a log, not an exception that masks
            // whatever the validation actually concluded.
            logger?.LogWarning(ex, "Could not remove validation container {ContainerId}.", containerId);
        }
    }

    private sealed class DockerSession(IDockerClient client, string containerId, ILogger? logger) : IValidationSession
    {
        public string ContainerId => containerId;

        public async Task WriteFileAsync(string path, string content, CancellationToken cancellationToken = default)
        {
            var directory = Path.GetDirectoryName(path)?.Replace('\\', '/') ?? "/tmp";
            var name = Path.GetFileName(path);

            await ExecAsync($"mkdir -p {directory}", cancellationToken);

            // Docker's put-archive API takes a tar stream. System.Formats.Tar is in the framework, so writing one
            // needs no extra dependency.
            using var tar = new MemoryStream();
            await using (var writer = new TarWriter(tar, TarEntryFormat.Pax, leaveOpen: true))
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, name)
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)),
                    Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite
                         | UnixFileMode.GroupRead | UnixFileMode.OtherRead,
                };
                await writer.WriteEntryAsync(entry, cancellationToken);
            }
            tar.Position = 0;

            await client.Containers.ExtractArchiveToContainerAsync(
                containerId,
                new CopyToContainerParameters { Path = directory, AllowOverwriteDirWithFile = true },
                tar,
                cancellationToken);
        }

        public async Task<ExecResult> ExecAsync(string command, CancellationToken cancellationToken = default)
        {
            var exec = await client.Exec.CreateContainerExecAsync(
                containerId,
                new ContainerExecCreateParameters
                {
                    // Through a shell on purpose: these are pipelines and redirections lifted from DISA check content,
                    // not argv arrays.
                    Cmd = ["/bin/sh", "-lc", command],
                    AttachStdout = true,
                    AttachStderr = true,
                    TTY = false,
                },
                cancellationToken);

            using var stream = await client.Exec.StartContainerExecAsync(
                exec.ID, new ContainerExecStartParameters { Detach = false, TTY = false }, cancellationToken);
            var (stdout, stderr) = await stream.ReadOutputToEndAsync(cancellationToken);

            var inspected = await client.Exec.InspectContainerExecAsync(exec.ID, cancellationToken);
            logger?.LogTrace("exec [{ExitCode}] {Command}", inspected.ExitCode, command);

            return new ExecResult((int)(inspected.ExitCode ?? -1), stdout ?? "", stderr ?? "");
        }

        public ValueTask DisposeAsync() => new(RemoveAsync(client, containerId, logger));
    }
}
