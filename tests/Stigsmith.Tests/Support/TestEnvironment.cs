using Docker.DotNet;

namespace Stigsmith.Tests.Support;

/// <summary>
/// Capability probes for the external tools the later milestones drive. Tests that need Docker,
/// Ollama, or an Ansible toolchain call <c>Assert.Skip.When(...)</c> on these rather than failing:
/// M1's acceptance criterion is that <c>dotnet test</c> passes from a clean clone, and a clean clone
/// has none of them. CI's container job runs on a runner that does.
/// </summary>
public static class TestEnvironment
{
    private static readonly Lazy<bool> DockerAvailable = new(ProbeDocker);
    private static readonly Lazy<bool> OllamaAvailable = new(() => ProbeHttp(OllamaBaseUrl + "/api/tags"));
    private static readonly Lazy<bool> AnsibleAvailable = new(() => OnPath("ansible-playbook") && OnPath("ansible-lint"));

    public static string OllamaBaseUrl =>
        Environment.GetEnvironmentVariable("STIGSMITH_OLLAMA_URL") ?? "http://localhost:11434";

    public static bool HasDocker => DockerAvailable.Value;
    public static bool HasOllama => OllamaAvailable.Value;
    public static bool HasAnsible => AnsibleAvailable.Value;

    /// <summary>Repository root, found by walking up to the directory holding the solution file.</summary>
    public static string RepoRoot { get; } = FindRepoRoot();

    public static string FixturePath(params string[] parts) =>
        Path.Combine([RepoRoot, "fixtures", .. parts]);

    public static string ReadFixture(params string[] parts) => File.ReadAllText(FixturePath(parts));

    public static string ExampleRolePath => Path.Combine(RepoRoot, "examples", "example-role");

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Stigsmith.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException(
            "Could not locate the repository root (no Stigsmith.slnx found above the test output directory).");
    }

    private static bool OnPath(string exe)
    {
        var paths = Environment.GetEnvironmentVariable("PATH")?.Split(Path.PathSeparator) ?? [];
        return paths.Any(p => !string.IsNullOrWhiteSpace(p) && File.Exists(Path.Combine(p, exe)));
    }

    /// <summary>
    /// Asks the daemon rather than looking for a socket path or a CLI on PATH: a docker binary with no daemon behind
    /// it is exactly the machine where the suites must skip, and the socket lives in a different place under Docker
    /// Desktop, colima and rootless Docker. The client resolves DOCKER_HOST and the active docker context itself.
    /// </summary>
    private static bool ProbeDocker()
    {
        try
        {
            using var client = new DockerClientBuilder().Build();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            client.System.PingAsync(timeout.Token).GetAwaiter().GetResult();
            return true;
        }
        catch
        {
            // Whatever kept the daemon from answering, the suites that need one skip.
            return false;
        }
    }

    private static bool ProbeHttp(string url)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            return http.GetAsync(url).GetAwaiter().GetResult().IsSuccessStatusCode;
        }
        catch
        {
            // Any failure to reach the endpoint means "not available"; the reason does not change
            // what the caller does, which is skip.
            return false;
        }
    }
}
