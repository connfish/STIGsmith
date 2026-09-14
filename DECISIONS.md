# Decisions

Newest last. Each entry: what was decided, why, and what was rejected.

---

## M1 — Skeleton

### Environment this was built on lacks Docker, Ollama, `ansible-lint`, and `oscap`

The development machine has the .NET 10 SDK and nothing else from the runtime dependency list.

**Decided:** write every integration against the real tool, and have the tests that need an absent
tool probe for it and skip (`TestEnvironment.HasDocker` / `HasOllama` / `HasAnsible`). CI runs the
suite twice: once on a bare runner, and once with `STIGSMITH_ENABLE_CONTAINER_TESTS=1` where Docker
is present.

**Why:** M1's acceptance criterion is `dotnet test` passing from a clean clone, which rules out
hard-failing on a missing container runtime. Skipping is also honest in a way that mocking is not —
a skipped test says "this was not verified here", where a mocked container says "verified" about
nothing.

**Rejected:** mocking `IDockerClient` and calling the loop tested. That tests the mock. The
validation loop's whole value is that it really applies the playbook, so a test that does not is
close to worthless. The mocks that do exist cover argument assembly, not the loop's verdict.

**Consequence to be aware of:** the M6 loop's container path has not been executed end to end on
this machine. `PROGRESS.md` says so explicitly.

### Milestone-by-milestone commits with `TreatWarningsAsErrors`

Warnings-as-errors is on from the first commit rather than retrofitted. Retrofitting it means a
large mechanical commit later and, in practice, a `NoWarn` list that never shrinks.

### Central Package Management

Versions live in `Directory.Packages.props`. Eight projects sharing EF Core and OpenTelemetry
versions drift otherwise, and drift across a solution that talks to a database is the kind of bug
that shows up only at runtime. One exception: `Aspire.Hosting.AppHost` is implicit to the Aspire SDK
and cannot be centrally pinned (`NU1009`), so it is not listed.

### xUnit v3 on Microsoft.Testing.Platform, via `global.json`

The .NET 10 SDK refuses to run xUnit v3 through the VSTest bridge. The opt-in is
`"test": { "runner": "Microsoft.Testing.Platform" }` in `global.json` — not a project property and
not `dotnet.config`, both of which were tried first and had no effect.

Also, per the spec: **no FluentAssertions.** It is no longer free for commercial use. Shouldly.

### Format-specific fields are preserved verbatim rather than modelled exhaustively

Both parsers keep the source representation of each rule (`Finding.Raw`) and export re-emits it,
overwriting only the fields Stigsmith owns: status, finding details, comments, and host metadata.

**Why:** round-tripping is an acceptance criterion, and "nobody adopts a tool that traps their
data". Modelling all 27 `.ckl` STIG_DATA attributes and every `.cklb` key would still silently drop
whatever DISA adds next. Passthrough is both the smaller implementation and the more durable one.

`Finding.Raw` is `internal` on purpose: it is the one place an unmodelled host-ish field could hide,
and making it unreachable from `Stigsmith.Generation` keeps the constraint-3 guarantee structural.

### Enums live with the code that owns them

`Automatability` in `Stigsmith.Rules`, `ValidationOutcome` / `ValidationStage` in
`Stigsmith.Validation`. The EF entities in `Stigsmith.Api` reference them rather than declaring
their own copies, so there is no mapping layer between "the classifier's answer" and "the column".

### Host metadata is stored on the checklist row, never on a finding row

`FindingRecord` has no host columns. A query that assembles generation input joins findings, and if
host fields were on that table they would be one careless `select` away from a prompt. Constraint 3
holds in the schema, not just in the object model.
