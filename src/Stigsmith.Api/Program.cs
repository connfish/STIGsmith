using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Scalar.AspNetCore;
using Stigsmith.Api;
using Stigsmith.Api.Endpoints;
using Stigsmith.Api.Generation;
using Stigsmith.Api.Persistence;
using Stigsmith.Api.Validation;
using Stigsmith.Generation.Conventions;
using Stigsmith.Generation.Providers;
using Stigsmith.Validation;
using Stigsmith.Validation.Docker;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();
builder.Services.AddSignalR();

var connection = builder.Configuration.GetConnectionString("stigsmithdb")
    ?? "Host=localhost;Port=5432;Database=stigsmith;Username=postgres;Password=postgres";
builder.Services.AddDbContext<StigsmithDbContext>(o => o.UseNpgsql(connection));

// Constraint 5: the convention role is read from a path supplied at runtime, never vendored.
builder.Services.Configure<ConventionRoleOptions>(builder.Configuration.GetSection(ConventionRoleOptions.SectionName));
builder.Services.AddSingleton<ConventionIndexProvider>();

// Generation. Ollama is the default provider, not a fallback (constraint 4): target environments are
// frequently air-gapped, so out of the box Stigsmith talks to a model on the operator's own hardware.
builder.Services.Configure<GenerationOptions>(builder.Configuration.GetSection(GenerationOptions.SectionName));
builder.Services.Configure<OllamaOptions>(builder.Configuration.GetSection(OllamaOptions.SectionName));
builder.Services.AddHttpClient<IRemediationProvider, OllamaRemediationProvider>((services, client) =>
{
    var ollama = services.GetRequiredService<IOptions<OllamaOptions>>().Value;
    client.BaseAddress = new Uri(ollama.BaseUrl);
    client.Timeout = ollama.Timeout;
});
builder.Services.AddSingleton<JobQueue<GenerationJob>>();
builder.Services.AddHostedService<GenerationWorker>();

// Validation. The sandbox is a real Docker container: generated Ansible is worthless until it has been
// linted, applied, re-scanned, and proven idempotent, and there is no way to prove that without running it.
builder.Services.Configure<ValidationOptions>(builder.Configuration.GetSection(ValidationOptions.SectionName));
builder.Services.AddSingleton<IValidationSandbox>(sp => new DockerValidationSandbox(
    sp.GetRequiredService<IOptions<ValidationOptions>>().Value,
    sp.GetRequiredService<ILogger<DockerValidationSandbox>>()));
builder.Services.AddSingleton<JobQueue<ValidationJob>>();
builder.Services.AddHostedService<ValidationWorker>();

var app = builder.Build();

// A single-instance local tool: apply the schema on boot so starting the stack is the whole setup.
using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<StigsmithDbContext>().Database.Migrate();

app.UseStatusCodePages();
app.MapHealthChecks("/health");
app.MapOpenApi();
app.MapScalarApiReference();
app.MapChecklistEndpoints();
app.MapConventionEndpoints();
app.MapGenerationEndpoints();
app.MapValidationEndpoints();
app.MapHub<GenerationHub>("/hubs/generation");

app.Run();
