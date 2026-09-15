using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Scalar.AspNetCore;
using Stigsmith.Api.Endpoints;
using Stigsmith.Api.Persistence;
using Stigsmith.Api.Generation;
using Stigsmith.Generation.Conventions;
using Stigsmith.Generation.Providers;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connection = builder.Configuration.GetConnectionString("stigsmithdb")
    ?? "Host=localhost;Port=5432;Database=stigsmith;Username=postgres;Password=postgres";
builder.Services.AddDbContext<StigsmithDbContext>(o => o.UseNpgsql(connection));

// Constraint 5: the convention role is read from a path supplied at runtime, never vendored.
builder.Services.Configure<ConventionRoleOptions>(
    builder.Configuration.GetSection(ConventionRoleOptions.SectionName));
builder.Services.AddSingleton<ConventionIndexProvider>();

// Generation. Ollama is the default provider, not a fallback (constraint 4): the target environments are
// frequently air-gapped, so out of the box Stigsmith talks to a model on the operator's own hardware and makes
// no outbound network calls.
builder.Services.Configure<GenerationOptions>(
    builder.Configuration.GetSection(GenerationOptions.SectionName));
builder.Services.Configure<OllamaOptions>(
    builder.Configuration.GetSection(OllamaOptions.SectionName));

builder.Services.AddHttpClient<IRemediationProvider, OllamaRemediationProvider>((services, client) =>
{
    var ollama = services.GetRequiredService<IOptions<OllamaOptions>>().Value;
    client.BaseAddress = new Uri(ollama.BaseUrl);
    client.Timeout = ollama.Timeout;
});

builder.Services.AddSingleton<GenerationQueue>();
builder.Services.AddHostedService<GenerationWorker>();
builder.Services.AddSignalR();

var app = builder.Build();

app.MapDefaultEndpoints();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseStatusCodePages();
app.MapChecklistEndpoints();
app.MapConventionEndpoints();
app.MapGenerationEndpoints();
app.MapHub<GenerationHub>("/hubs/generation");

app.Run();
