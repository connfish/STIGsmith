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
    private readonly ValidationOptions _options;
    private readonly ILogger<DockerValidationSandbox>? _logger;
    private readonly bool _ownsClient;

    public DockerValidationSandbox(
        ValidationOptions options,
        ILogger<DockerValidationSandbox>? logger = null,
        IDockerClient? client = null)
    {
        _options = options;
        _logger = logger;
        _ownsClient = client is null;
        _client = client ?? new DockerClientConfiguration().CreateClient();
    }

    public string Image => _options.Image;

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await _client.System.PingAsync(cancellationToken);
            return true;
        }
        catch (Exception ex) when (ex is DockerApiException or HttpRequestException or TimeoutException
                                      or IOException or TaskCanceledException)
        {
            _logger?.LogWarning(ex, "No Docker daemon is reachable, so validation cannot run.");
            return false;
        }
    }

    public async Task<IValidationSession> StartAsync(CancellationToken cancellationToken = default)
    {
        var image = await ResolveImageAsync(cancellationToken);

        var created = await _client.Containers.CreateContainerAsync(
            new CreateContainerParameters
            {
                Image = image,
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

        await _client.Containers.StartContainerAsync(created.ID, new ContainerStartParameters(), cancellationToken);
        _logger?.LogDebug("Started validation container {ContainerId} from {Image}.", created.ID[..12], image);

        return new DockerSession(_client, created.ID, _logger);
    }

    /// <summary>
    /// Returns the configured image if it is present locally, otherwise the fallback.
    /// </summary>
    /// <remarks>
    /// Deliberately does not pull. Target environments are air-gapped, so a pull would hang rather than fail fast, and
    /// an operator who has not built the validation image needs to be told that — not to have the tool quietly
    /// substitute a bare image whose missing ansible would present as a lint failure.
    /// </remarks>
    private async Task<string> ResolveImageAsync(CancellationToken cancellationToken)
    {
        if (await ImageExistsAsync(_options.Image, cancellationToken)) return _options.Image;

        _logger?.LogWarning(
            "Validation image {Image} is not present locally. Falling back to {Fallback}, which has neither "
            + "ansible-lint nor oscap installed, so stages depending on them will report as failed. Build the image "
            + "from docker/validation/Dockerfile to get real validation.",
            _options.Image, _options.FallbackImage);

        return _options.FallbackImage;
    }

    private async Task<bool> ImageExistsAsync(string image, CancellationToken cancellationToken)
    {
        try
        {
            await _client.Images.InspectImageAsync(image, cancellationToken);
            return true;
        }
        catch (DockerImageNotFoundException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (_ownsClient) _client.Dispose();
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
                new ContainerPathStatParameters { Path = directory, AllowOverwriteDirWithFile = true },
                tar,
                cancellationToken);
        }

        public async Task<ExecResult> ExecAsync(string command, CancellationToken cancellationToken = default)
        {
            var exec = await client.Exec.ExecCreateContainerAsync(
                containerId,
                new ContainerExecCreateParameters
                {
                    // Through a shell on purpose: these are pipelines and redirections lifted from DISA check content,
                    // not argv arrays.
                    Cmd = ["/bin/sh", "-lc", command],
                    AttachStdout = true,
                    AttachStderr = true,
                    Tty = false,
                },
                cancellationToken);

            using var stream = await client.Exec.StartAndAttachContainerExecAsync(exec.ID, tty: false, cancellationToken);
            var (stdout, stderr) = await stream.ReadOutputToEndAsync(cancellationToken);

            var inspected = await client.Exec.InspectContainerExecAsync(exec.ID, cancellationToken);
            logger?.LogTrace("exec [{ExitCode}] {Command}", inspected.ExitCode, command);

            return new ExecResult((int)inspected.ExitCode, stdout ?? "", stderr ?? "");
        }

        public async ValueTask DisposeAsync()
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
    }
}
