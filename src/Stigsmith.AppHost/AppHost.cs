var builder = DistributedApplication.CreateBuilder(args);

var postgres = builder.AddPostgres("postgres")
    .WithDataVolume()
    .WithPgAdmin();

var db = postgres.AddDatabase("stigsmithdb");

// Ollama runs as a container so a developer gets the default (local) provider without installing
// anything. Constraint 4: local is first-class, so it is part of the normal dev topology rather
// than something you opt into.
var ollama = builder.AddContainer("ollama", "ollama/ollama", "latest")
    .WithHttpEndpoint(port: 11434, targetPort: 11434, name: "http")
    .WithVolume("stigsmith-ollama", "/root/.ollama");

builder.AddProject<Projects.Stigsmith_Api>("api")
    .WithReference(db)
    .WaitFor(db)
    .WithEnvironment("Stigsmith__Generation__Ollama__BaseUrl", ollama.GetEndpoint("http"));

builder.Build().Run();
