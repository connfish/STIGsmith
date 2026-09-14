# STIGSMITH

Ingests SCAP scan results and STIG checklists, works out which open findings can be automated, and
drafts **validated** Ansible remediation for them.

The framing matters: this is a **translation** problem, not a generation problem. Every STIG rule
already ships DISA's prescribed fix in its `fixtext` field and its verification procedure in
`check content`. Stigsmith converts that prose into idempotent Ansible that matches your existing
conventions. It does not invent remediations.

And the model call is not the product. The **validation loop** is: generated Ansible is worthless
until it has been linted, applied in a disposable container, re-scanned, and proven idempotent.
Every run stores the evidence — lint output, apply output, before/after scan status, idempotency
result — because that evidence is what turns generated YAML into something an ISSO will accept.

## How this tool handles your data

Three things about data handling are worth stating plainly, because they are the difference between
a tool that can be adopted in this space and one that cannot.

### No real scan data lives in this repository

Checklists from live systems carry hostnames, IP addresses, and detailed finding data that is
frequently CUI. Nothing of the kind is committed here. Every fixture under `fixtures/` is synthetic:
hosts are named `host-alpha.example.test` and friends, and all addresses come from the RFC 5737
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). If you are adding a
fixture, keep it that way.

### Host identifiers never reach the language model

The model sees the rule and nothing else: rule ID, title, severity, `fixtext`, and `check content`.
It does not see a hostname, an IP address, a MAC address, an FQDN, a target comment, or any other
host-identifying field.

This is enforced in two ways, not by convention:

- **Structurally.** Rule content and host metadata are separate types
  (`RuleContent` and `HostMetadata`). Prompt assembly accepts a `RuleContent`, which has no host
  fields on it at all, so there is no host value available to pass by mistake.
- **By test.** `PromptHygieneTests` builds prompts from checklists whose host fields are populated
  with deliberately distinctive values and asserts the assembled prompt contains none of them. The
  test fails the build if a future change introduces a leak.

Every generation is persisted with the exact prompt that was sent, so the guarantee is auditable
after the fact and not only at test time.

### A local model is a first-class provider, not a fallback

Ollama is fully supported and is the **default**. Target environments for this kind of work are
frequently air-gapped, and a tool that requires a cloud API is a tool nobody in this space can
adopt. Providers sit behind an `IRemediationProvider` interface so a cloud model can be swapped in
where policy allows it, but out of the box Stigsmith talks to a model running on your own hardware
and makes no outbound network calls.

## Stack

.NET 10 / C# 14, ASP.NET Core Minimal APIs, PostgreSQL 17 (Npgsql + EF Core 10),
`System.Threading.Channels` + `IHostedService` job queues, SignalR for streaming, Docker.DotNet for
the validation sandbox, .NET Aspire for local orchestration, xUnit v3 + Shouldly + NSubstitute +
Testcontainers for tests.

## Running it

```bash
# Aspire: API + Postgres + Ollama
dotnet run --project src/Stigsmith.AppHost

# or, without the Aspire CLI / on an air-gapped host
docker compose up

# tests
dotnet test
```

`dotnet test` passes on a clean clone with no Docker, no Ollama, and no Ansible installed: suites
that need those probe for them and skip. Set `STIGSMITH_ENABLE_CONTAINER_TESTS=1` on a machine that
has a container runtime to run them for real.

## Where things are

| Project | Holds |
|---|---|
| `Stigsmith.Checklists` | `.ckl` / `.cklb` / XCCDF / ARF parsing and export, the normalized finding model |
| `Stigsmith.Rules` | Automatability classification and high-risk tagging |
| `Stigsmith.Generation` | Convention retrieval, prompt assembly, `IRemediationProvider` |
| `Stigsmith.Validation` | The lint → apply → re-scan → idempotency loop and its evidence |
| `Stigsmith.Api` | Minimal API endpoints, persistence, job queues, SignalR hubs |

`DECISIONS.md` records what was decided and what was rejected. `PROGRESS.md` is the current state of
the work, written to be picked up cold.
