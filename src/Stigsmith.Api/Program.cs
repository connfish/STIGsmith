using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using Stigsmith.Api.Endpoints;
using Stigsmith.Api.Persistence;
using Stigsmith.Generation.Conventions;

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

app.Run();
