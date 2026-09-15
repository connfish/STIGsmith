# Progress

**Current milestone:** M2 complete. Starting M3.

`dotnet test` → **47 passed, 9 skipped, 0 failed.** The 9 skips are the API integration tests, which
need a container runtime this machine does not have. See "Environment gaps" below.

## Done

### M1 — Skeleton ✅

- Solution `Stigsmith.slnx` with the six specified projects plus `Stigsmith.AppHost` and
  `Stigsmith.ServiceDefaults` (Aspire).
- EF Core 10 + Npgsql schema for checklists, findings, generations, and validation runs, with the
  `InitialSchema` migration generated. Host columns live on the checklist row only.
- Aspire AppHost (API + Postgres + pgAdmin + Ollama) and a `docker-compose.yml` fallback.
- `/health` and `/alive` from Aspire service defaults; OpenAPI + Scalar in development.
- CI: build + test on a bare runner, and a second job with `STIGSMITH_ENABLE_CONTAINER_TESTS=1`.

### M2 — Checklist ingest ✅

**Parsers and writers.** `.ckl` (XDocument) and `.cklb` (System.Text.Json.Nodes) both read and write;
XCCDF 1.1/1.2 results and ARF collections import. `ChecklistIo` detects format from content, not
extension. Everything normalizes to one `Checklist` model with `HostMetadata` held separately from
`RuleContent`.

**Round-tripping.** `.ckl` and `.cklb` both round-trip **byte for byte**, including fields Stigsmith
does not model (`Finding.Raw` carries them through). Verified three passes deep, so the writer is a
fixed point. Cross-format exports are pinned to golden files.

**Fixtures** (all synthetic — `*.example.test`, RFC 5737 addresses):

| File | What it is |
|---|---|
| `fixtures/ckl/rhel8-host-alpha.ckl` | 72 rules, all four statuses |
| `fixtures/cklb/rhel8-host-bravo.cklb` | same rules, `.cklb`, different status offset |
| `fixtures/ckl/edge-cases.ckl` | repeated CCI/legacy ids, empty and whitespace-only fields, no fixtext, non-ASCII, escaped markup, an unmodelled vendor attribute |
| `fixtures/multihost/` | three hosts, mixed `.ckl`/`.cklb`, 60/40/55 rules |
| `fixtures/xccdf/*-xccdf.xml`, `*-arf.xml` | OpenSCAP-shaped results, benchmark inlined |
| `fixtures/expectations/rhel8-classification.json` | M3's graded answer key |

**API.** `GET /api/checklists`, `GET /api/checklists/{id}`, `POST /api/checklists/import`,
`GET /api/checklists/{id}/export?format=Ckl|Cklb`. Export re-parses the stored source document and
applies the database's reviews, so it stays lossless.

**Constraint 3 is guarded by tests already**, two milestones before the model shows up:
`FindingRecord` and `RuleContent` are both asserted by reflection to have no host-identifying member.

## Stubbed / not started

- M3 classification, M4 retrieval, M5 generation, M6 validation loop.
- Job queues (`Channels` + `IHostedService`) and SignalR hubs. Not needed until M5.
- The `examples/example-role/` synthetic Ansible role is an empty directory skeleton; M4 fills it.
- M7 UI. Bonus only; not started, and will not be unless M6 lands solidly.

## Environment gaps — read this before trusting downstream milestones

This machine has **no Docker, no Ollama, no `ansible-lint`, no `oscap`**. Consequences, concretely:

- **Unverified here:** the import and export endpoints, and the EF migration against a real
  PostgreSQL. Those are the 9 skipped tests. The parsing and export logic underneath them is fully
  covered by tests that do run (`ChecklistMapperTests` exercises the same export path without a
  database), so the risk is in the HTTP and EF wiring, not the format handling.
- **M5** will cover Ollama prompt and parameter assembly against a fake HTTP handler; the live call
  will skip without a reachable Ollama.
- **M6**'s container path will be written against Docker.DotNet but cannot be executed here at all.
  Treat it as unrun code until someone runs it with Docker present.

Both are in `DECISIONS.md` with reasoning. Weigh "passes on this machine" accordingly for anything
downstream of M5.

## Next

M3: heuristic classification over `fixtext`/`check content` into automatable / manual / needs-review,
plus high-risk tagging (sshd, PAM, SELinux, firewall, authentication, network). Graded against
`fixtures/expectations/rhel8-classification.json`, with honest coverage numbers reported.
