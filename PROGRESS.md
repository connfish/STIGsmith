# Progress

**Current milestone:** M1 complete. Starting M2.

## Done

### M1 — Skeleton ✅

- Solution `Stigsmith.slnx` with the six specified projects plus `Stigsmith.AppHost` and
  `Stigsmith.ServiceDefaults` (Aspire).
- Normalized checklist model with host metadata held separately from rule content
  (`HostMetadata` / `RuleContent`) — this is the structural half of constraint 3 and it is in place
  from the start rather than bolted on.
- `.ckl`, `.cklb`, XCCDF, and ARF readers plus `.ckl` / `.cklb` writers. **Written in M1, not yet
  tested — golden-file tests are M2's acceptance criterion.**
- EF Core 10 + Npgsql schema for checklists, findings, generations, and validation runs, with the
  `InitialSchema` migration generated.
- Aspire AppHost (API + Postgres + pgAdmin + Ollama) and a `docker-compose.yml` fallback.
- `/health` and `/alive` from Aspire service defaults; OpenAPI + Scalar in development.
- CI: build + test on a bare runner, and a second job with `STIGSMITH_ENABLE_CONTAINER_TESTS=1`.

`dotnet test` → 2 passed, 0 failed.

## Stubbed / not started

- M2 golden-file round-trip tests and synthetic fixtures.
- M3 classification, M4 retrieval, M5 generation, M6 validation loop.
- API endpoints beyond `GET /api/checklists`.
- Job queues (`Channels` + `IHostedService`) and SignalR hubs.
- M7 UI. Bonus only; not started.

## Blocked / environment gaps

Nothing blocked, but this machine has **no Docker, no Ollama, no `ansible-lint`, no `oscap`**.
Consequences:

- M6's container path will be written against Docker.DotNet but cannot be executed here. It will be
  structured so a machine with Docker runs it unchanged, and the tests will skip rather than fail.
- M5's Ollama provider will be tested against a fake HTTP handler for prompt/parameter assembly, and
  the live call will be covered by a test that skips without a reachable Ollama.

Both are recorded in `DECISIONS.md`. Treat "passes on this machine" as weaker evidence than usual for
anything downstream of M5.

## Next

M2: synthetic fixtures (`.ckl`, `.cklb`, XCCDF, ARF; multi-host set) and the round-trip tests.
