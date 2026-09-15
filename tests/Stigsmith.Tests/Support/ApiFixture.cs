using System.Net.Http.Headers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Stigsmith.Api.Persistence;
using Stigsmith.Generation.Providers;
using Stigsmith.Validation;
using Testcontainers.PostgreSql;

namespace Stigsmith.Tests.Support;

/// <summary>
/// The API wired to a real PostgreSQL in a container, with migrations applied. Real Postgres rather
/// than an in-memory provider on purpose: the schema uses jsonb columns and composite indexes, and an
/// in-memory provider would accept a migration Postgres rejects.
/// </summary>
/// <remarks>
/// Requires a container runtime. Suites using this call <see cref="SkipIfUnavailable"/> first, so
/// <c>dotnet test</c> still passes on a clean clone with no Docker (see DECISIONS.md). CI runs them in
/// the job that sets STIGSMITH_ENABLE_CONTAINER_TESTS=1.
/// </remarks>
public sealed class ApiFixture : IAsyncLifetime
{
    private PostgreSqlContainer? _postgres;
    private WebApplicationFactory<Program>? _factory;

    public HttpClient Client { get; private set; } = null!;

    /// <summary>The scripted model behind the API, for inspecting the prompts it was sent.</summary>
    public ScriptedRemediationProvider Provider { get; } = new();

    /// <summary>The scripted container behind the API, for steering which validation stage fails.</summary>
    public ScriptedSandbox Sandbox { get; } = new();

    public static void SkipIfUnavailable() =>
        Assert.SkipUnless(TestEnvironment.HasDocker,
            "No container runtime available; this suite needs PostgreSQL in a container.");

    public async ValueTask InitializeAsync()
    {
        if (!TestEnvironment.HasDocker) return;

        _postgres = new PostgreSqlBuilder("postgres:17-alpine")
            .WithDatabase("stigsmith")
            .Build();
        await _postgres.StartAsync();

        var connection = _postgres.GetConnectionString();
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ConnectionStrings:stigsmithdb", connection);
            builder.UseSetting("Stigsmith:Generation:ConventionRole:Path", TestEnvironment.ExampleRolePath);
            builder.UseEnvironment("Development");

            // Swap the model for a scripted one. The generation API tests are about the queue, the worker, the
            // persisted prompt and the extractor -- none of which need a real model, and all of which would
            // otherwise be untestable anywhere without Ollama installed.
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IRemediationProvider>();
                services.AddSingleton<ScriptedRemediationProvider>(Provider);
                services.AddSingleton<IRemediationProvider>(sp => sp.GetRequiredService<ScriptedRemediationProvider>());

                // Same reasoning for the container: the validation endpoints, the worker, the evidence persistence and
                // the report are all testable without Docker, and would otherwise be untestable anywhere without it.
                // DockerValidationSandbox itself is covered only by DockerSandboxTests, which skip here.
                services.RemoveAll<IValidationSandbox>();
                services.AddSingleton<IValidationSandbox>(Sandbox);
            });
        });

        Client = _factory.CreateClient();

        using var scope = _factory.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<StigsmithDbContext>().Database.MigrateAsync();
    }

    public async ValueTask DisposeAsync()
    {
        _factory?.Dispose();
        if (_postgres is not null) await _postgres.DisposeAsync();
    }

    /// <summary>Uploads a fixture file to the import endpoint as multipart form data.</summary>
    public async Task<HttpResponseMessage> ImportFixture(params string[] fixtureParts)
    {
        var path = TestEnvironment.FixturePath(fixtureParts);
        using var content = new MultipartFormDataContent();
        var bytes = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
        var part = new ByteArrayContent(bytes);
        part.Headers.ContentType = new MediaTypeHeaderValue(
            path.EndsWith(".cklb") ? "application/json" : "application/xml");
        content.Add(part, "file", Path.GetFileName(path));
        return await Client.PostAsync("/api/checklists/import", content);
    }
}
