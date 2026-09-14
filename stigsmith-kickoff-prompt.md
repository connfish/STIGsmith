# STIGSMITH — Claude Code Kickoff Prompt

> Paste everything below the line into Claude Code. Run `/init` first if the repo is empty.
> Consider starting in plan mode (`shift+tab`) so you can approve the approach before it writes code.

---

## Project

Build **STIGSMITH**, a tool that ingests SCAP scan results and STIG checklists, identifies open
findings, and drafts **validated** Ansible remediation for them using a language model.

The critical framing: this is a **translation** problem, not a generation problem. Every STIG rule
already ships DISA's prescribed fix in its `fixtext` field and its verification procedure in
`check content`. The model converts that prose into idempotent Ansible matching the operator's
existing conventions. It does not invent remediations.

The product is not the model call. The product is the **validation loop** around it — generated
Ansible is worthless until it has been linted, applied in a disposable container, re-scanned, and
proven idempotent. Build that loop as if it were the whole point, because it is.

## Hard constraints — read these first

1. **Clean room.** Original implementation built from public sources only: DISA STIG content,
   the XCCDF/OVAL specifications, and the documented `.ckl` / `.cklb` formats. Do not reproduce
   or reverse-engineer any proprietary or internal tool.
2. **No real scan data in the repo.** Checklists from live systems contain hostnames, IPs, and
   detailed finding data that is frequently CUI. All fixtures must be synthetic, with obviously
   fake hostnames (`host-alpha.example.test`) and RFC 5737 documentation IP ranges.
3. **Strip identifiers before any model call.** The model receives rule ID, title, severity,
   `fixtext`, and `check content` — never hostname, IP, or any host-identifying field. Enforce
   this in code with a test that asserts the assembled prompt contains no host fields, not just
   by convention.
4. **Local model is first-class.** Ollama must be a fully supported provider, not a fallback.
   Target environments are frequently air-gapped, and a tool that requires a cloud API is a tool
   nobody in this space can adopt. Put the provider behind an interface so cloud and local swap
   cleanly, and default the config to local.
5. **Never vendor someone else's Ansible role into this repo.** The retrieval index (M4) reads a
   role from a **path supplied at runtime** via config. The repo ships only a small synthetic
   example role for tests.

Document constraints 2–4 in the README in plain language. How this tool handles data is part of
what makes it credible.

## Stack — decided, do not re-litigate

**Backend**
- .NET 10 (LTS), C# 14, nullable enabled, `TreatWarningsAsErrors`
- ASP.NET Core Minimal APIs with endpoint groups
- PostgreSQL 17, Npgsql + EF Core 10
- `System.Threading.Channels` + `IHostedService` for the generation and validation job queues
- SignalR for streaming generation output and validation progress
- Docker.DotNet for orchestrating validation containers
- `Microsoft.AspNetCore.OpenApi` + Scalar for API docs
- .NET Aspire for local orchestration (API + Postgres + Ollama)
- xUnit v3, NSubstitute, Shouldly, Testcontainers
  (do **not** use FluentAssertions — no longer free for commercial use)

**Frontend** (M7, bonus only)
- Angular 22, standalone components, signals, zoneless change detection
- Angular Material + CDK, with `cdk-virtual-scroll` — checklists run 400–1500 findings and a
  naive Material table dies well before that
- `@microsoft/signalr` client bridged into signals

## Milestones

Work in order. Commit at the end of each with a real message. Do not start a milestone before the
previous one's acceptance criteria pass.

### M1 — Skeleton
Solution layout (`Stigsmith.Checklists`, `Stigsmith.Rules`, `Stigsmith.Generation`,
`Stigsmith.Validation`, `Stigsmith.Api`, `Stigsmith.Tests`), Aspire host, Docker Compose fallback,
EF migrations, health endpoint, CI running build + test.

*Done when:* `dotnet test` passes in CI from a clean clone.

### M2 — Checklist ingest
Parse and export both formats: `.ckl` (XML, `XDocument`) and `.cklb` (JSON, `System.Text.Json`).
Also import XCCDF and ARF results from OpenSCAP/SCC. Normalize all of them into a single internal
finding model: rule ID, version, severity, status, finding details, comments, plus host metadata
held separately from rule content so the separation required by constraint 3 is structural.

Round-tripping matters — nobody adopts a tool that traps their data. Import a checklist, export it,
and the result must be readable by STIG Viewer with statuses and comments intact.

*Done when:* golden-file round-trip tests pass for both formats, and a synthetic multi-host
checklist set imports cleanly.

### M3 — Rule classification
Not every rule is automatable. Classify each into:
- **automatable** — config change Ansible can make
- **manual** — policy or documentation check ("the ISSO will verify...")
- **needs-review** — ambiguous, or the fix depends on site context

Separately, tag **high-risk** rules whose remediation can lock an operator out of the host: sshd,
PAM, SELinux, firewall, authentication, and network config. These require explicit opt-in before
generation and must always produce a check-mode path.

Start with heuristics over `fixtext` and `check content`; a model-assisted pass is fine as a second
stage, but the heuristic layer must stand alone and be testable.

*Done when:* classification runs over a full synthetic RHEL 8 checklist and coverage numbers are
reported — "N automatable, M manual, K needs-review". Honest coverage numbers are a feature.

### M4 — Convention retrieval
Index an existing Ansible role supplied by path in config. Parse its task files, extract
per-task metadata (name, module, variables referenced, handler notified, `when` guards, tags),
and build a retrieval index keyed on the STIG rule ID each task addresses where that's derivable
from task names or tags.

At generation time, retrieve the closest few existing tasks and include them as few-shot examples.
This is what makes output match house conventions — variable prefixes, handler names, tagging
scheme — instead of generic Ansible. It is the highest-leverage piece of the whole project.

Embeddings via the local model are fine; plain BM25/lexical retrieval over task names and fixtext
is an acceptable and much simpler starting point. Pick one, justify it in `DECISIONS.md`.

*Done when:* retrieval returns sensible neighbors for a rule against the synthetic example role,
with tests asserting relevance on known pairs.

### M5 — Generation
`IRemediationProvider` interface with an Ollama implementation first. Prompt assembly pulls rule
content + retrieved examples + target OS, and **nothing host-identifying**. Stream tokens over
SignalR. Persist every generation with its full prompt, model, and parameters so runs are
reproducible and auditable.

*Done when:* generating for a batch of automatable rules produces syntactically valid YAML, and
the prompt-hygiene test from constraint 3 passes.

### M6 — Validation sandbox (this is the stop point)
The loop, in order:
1. `ansible-lint` and `ansible-playbook --syntax-check`
2. Apply in a disposable RHEL-compatible container (Rocky or Alma UBI base)
3. **Re-run the SCAP scan** and confirm the finding flipped to pass
4. Apply a second time and assert zero `changed` tasks — idempotency
5. On failure, one repair attempt with the error fed back as context; if it fails again, mark
   `needs-human-review` and move on

Every run stores structured evidence: lint output, apply output, before/after scan status,
idempotency result. That evidence is what turns generated YAML into something an ISSO would accept.

*Done when:* an end-to-end run over at least 10 synthetic automatable rules produces a pass/fail
report with evidence, and at least one deliberately-broken rule correctly lands in
`needs-human-review`.

### M7 — Triage UI (bonus, only if M6 is solid)

**Function:** virtualized findings list, keyboard-first master-detail (`j`/`k` to move, `1`–`4` to
set status, `/` to search), bulk status+comment application, generated-Ansible diff panel with
approve/reject, and live validation progress. Filters encoded in the URL so views are shareable.

**This is a dense professional tool, not a web app.** The reference points are STIG Viewer, Linear,
and GitHub's file browser — software an analyst stares at for six hours while walking 1200 findings.
It is not a dashboard, not a landing page, and there is no marketing surface anywhere in it. Build
it plain and let the density and keyboard handling be the impressive part.

Follow this spec literally. Do not improvise on visual design.

**Layout.** Fixed app shell at `100vh` with no page-level scroll. Four regions: a 240px left rail
(checklist and host selection), a center findings list at roughly 40% width, a right detail pane,
and a status bar pinned to the bottom showing counts by status. Each region scrolls independently.
A 40px toolbar across the top holds filters. No centered content, no hero, no max-width container.

**Type.** One sans family and one monospace. Monospace is used for rule IDs, hostnames, finding
details, and all YAML — not as a decorative label face. Exactly three sizes (12px meta, 13px body
and list rows, 15px detail headings) and exactly two weights (400, 600). Sentence case throughout.
No all-caps labels, no letter-spacing tricks.

**Color.** Neutral grays for all chrome. Color appears only where it carries meaning:
severity (CAT I / II / III), finding status, and validation result. One single accent for
interactive and focus states — not purple, indigo, or violet. Nothing else is colored. No gradients
anywhere, including on text and buttons.

**Density and surfaces.** Use Angular Material's density API at -2 or -3; the defaults are sized for
touch and waste vertical space. Row height 28–32px. 4px base spacing unit. Separate regions with
1px solid borders, not shadows. Border radius 3px maximum. Drop shadows only on true overlays
(menus, dialogs).

**Motion.** Effectively none. Hover and focus state changes at 100ms; the detail pane updating on
selection. No entrance animations, no page transitions, no skeleton shimmer — streaming generation
and validation use a plain determinate progress bar and a scrolling log.

**Do not use any of these.** Each is a tell, and each would make the tool read as generated:
gradient backgrounds or gradient text; emoji; an icon beside every label (icons only where they
replace text entirely, as in toolbar buttons); rounded cards floating on a tinted page background;
centered layouts or hero sections; `01 / 02 / 03` numbered markers; tracked-out all-caps eyebrow
labels; meta strings joined with middle dots; more than one accent color; toast notifications for
routine actions (the status bar reports them); animated counters.

**Components.** Use Angular Material components with a tightened custom theme. Do not hand-roll a
design system or write bespoke button, menu, and dialog styling — restyled Material is
consistent and unremarkable, which is the goal here.

**Theme.** Ship one theme done properly. If that's light, don't half-build a dark mode.

**Quality floor.** Visible keyboard focus rings are functional here, not decoration — this is a
keyboard-driven interface and focus must be obvious at all times. WCAG AA contrast. Respect
`prefers-reduced-motion`. No layout shift when the detail pane loads.

**Process.** Build `_tokens.scss` (color, type scale, spacing, density) and the empty layout shell
first. Screenshot it and check it against the "do not use" list above before building any
components. If any part of what you've built would look the same on a project about something
entirely different, that part is wrong — fix it and note the change in `DECISIONS.md`.

## How to work

- **Do not ask me for permission mid-run.** Make reasonable decisions, record them in
  `DECISIONS.md` with reasoning and rejected alternatives, and keep going.
- Maintain `PROGRESS.md`: current milestone, what's done, what's stubbed, what's blocked, what
  you'd do next. Assume I will read it and take over cold.
- Write tests as you go. The parsers need golden-file tests; the prompt assembly needs the
  hygiene test; the validation loop needs a deliberately-failing case.
- Where you're unsure about a format detail or a spec interpretation, say so in a code comment
  and in `DECISIONS.md`. Flagged uncertainty is far more useful to me than confident guessing —
  especially around `.cklb`, which is less well documented than `.ckl`.
- If a milestone is bigger than expected, finish it properly and stop. A working M4 beats a
  half-built M6.

## Stop and hand off when

M6 is complete and committed, or you hit something that genuinely needs my input. Write a handoff
summary in `PROGRESS.md`: what works, what's stubbed, coverage numbers from M3, what you'd attack
next, and anything you're uncertain about.
