# Progress

**Current milestone:** M3 complete. Starting M4.

`dotnet test` → **94 passed, 11 skipped, 0 failed.** The skips are the API integration tests, which need
a container runtime this machine does not have. See "Environment gaps" below.

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

### M3 — Rule classification ✅

Coverage over the full synthetic RHEL 8 checklist:

```
72 rules: 47 automatable, 9 manual, 16 needs-review (65% automatable).
Of 45 open: 29 automatable, 6 manual, 10 needs-review.
22 automatable rules are high-risk and need explicit opt-in.
```

- `RuleClassifier` is five ordered heuristic steps over `fixtext` and `check content`, no model
  involved. The order is the policy; "the tool cannot supply this value" is checked before "this is a
  concrete change", so a command with an unsupplied value never reads as automatable.
- High-risk tagging across sshd, PAM, SELinux, firewall, authentication, and network. **100% recall
  against the answer key, 0 false positives of 72.**
- `GenerationEligibility` gates generation on per-domain opt-in and always requires a check-mode path.
- `GET /api/checklists/{id}/coverage`; the import response also carries the coverage line.
- Classification runs at import and is stored per finding, so triage filters on an indexed column.

**Read the M3 section of `DECISIONS.md` before trusting the 100% agreement figure.** The answer key was
corrected five times while the heuristics were written — every correction was a genuine internal
inconsistency in the key, but a key adjusted alongside the thing it grades is partly fitted to it. The
held-out set (`RuleClassifierTests`, 32 cases written from the policy, touching no catalog rule) is the
stronger evidence. If you want better, have someone else key a fresh sample.

## Stubbed / not started

- M4 retrieval, M5 generation, M6 validation loop.
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

M4: convention retrieval. Index an Ansible role supplied by path in config — parse task files, extract
per-task metadata (name, module, variables, handler notified, `when` guards, tags), and key it on the
STIG rule id each task addresses where that is derivable. Retrieval feeds few-shot examples into M5's
prompts, which is what makes output match house conventions instead of generic Ansible.

Constraint 5: the role comes from a runtime path, never vendored. `examples/example-role/` gets a small
synthetic role for tests only.

Open question for M4, to be decided and recorded: BM25/lexical over task names and fixtext, or
embeddings via the local model. Lexical first unless there is a reason not to — it is simpler, needs no
model at index time, and the join key (rule id in task names and tags) is mostly exact-match anyway.
