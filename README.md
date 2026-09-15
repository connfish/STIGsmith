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
`System.Threading.Channels` + `IHostedService` job queues, SignalR for streaming, Docker.DotNet.Enhanced for
the validation sandbox, xUnit v3 + Shouldly + NSubstitute + Testcontainers for tests.

## The validation loop

For each generated remediation, in order:

1. `ansible-lint` and `ansible-playbook --syntax-check`
2. for a high-risk rule, `--check` first, so an operator can dry-run it before it touches a host
3. apply in a **disposable AlmaLinux 8 container**
4. **re-run the scan** and confirm the finding flipped to pass
5. apply a second time and require **zero changed tasks**

On failure, the tool output goes back to the model verbatim for **exactly one** repair attempt. Failing again marks the
rule `needs-human-review` rather than being retried — a model that cannot fix its own output given the error twice will
not manage it on a third go.

Every run stores the whole evidence bundle: lint output, apply output, before/after scan status, idempotency result, the
playbook as applied, and **which verifier produced the verdict** — a real `oscap` scan or DISA's own check command run as
a shell test. Those are not worth the same, so the report says which.

The scan is `oscap` against the SCAP Security Guide datastream in the validation image. SSG names its rules its own
way and carries the DISA id only as a reference, so the loop resolves the DISA id to the SSG rule inside the container
and evaluates just that rule under SSG's STIG profile. Where SSG has no rule, or reports the rule not applicable, the
loop falls back to running the read-only command from the rule's own check content.

Three things worth knowing about the numbers:

- **A container is not a host.** Remediation that sets a kernel parameter, enables a systemd unit, or rewrites the
  bootloader cannot apply in an unprivileged container. The loop reports that as a failed apply rather than a pass,
  which is correct, but it means the sandbox validates file, package, and config-content rules well and kernel, boot,
  and service rules poorly. The image preinstalls the packages whose configuration files the RHEL 8 STIG edits
  (sshd, audit, rsyslog, firewalld, chrony, sudo, pwquality, aide) so those edits can apply and be re-checked, but
  their services do not run. SSG makes the same call: it marks most host-configuration rules not applicable inside a
  container, so oscap-backed passes in this sandbox are mostly package-removal and file-permission rules.
- **The check-content fallback reads the check the way an assessor does.** It runs the first read-only command in
  the check and requires the compliant output the check shows to appear in the real output, so a commented default
  line does not count. Where the check shows no output and says the result would be the finding ("if the package is
  installed, this is a finding"), any output fails. Only when it has neither does a zero exit pass, and the evidence
  says which reading produced the verdict. It is still weaker than a SCAP scan; weigh it accordingly.
- **A rule that cannot be verified does not pass.** Applying cleanly proves the YAML ran, not that the finding is fixed.

## Running it

You need the .NET 10 SDK and a Docker daemon. Docker Desktop works; so does the headless route on a Mac
(`brew install colima docker docker-compose && colima start`, then register the compose plugin as brew's caveat
says). Ollama can run natively (`brew install ollama && ollama pull qwen2.5-coder:7b`) or in Docker with
`make ollama`; either way the API expects it on `localhost:11434`.

```bash
make run     # Postgres in Docker, the API on the host, browser opens http://localhost:5045/scalar
make test    # dotnet test: suites that need Docker or Ollama detect their absence and skip
make image   # once: the container the validation loop applies remediation in
make up      # the whole stack in Docker instead, at http://localhost:8080/scalar
```

`python3 tools/live_run.py` drives the whole loop over the fixture checklist against the running API and prints the
validation report. It is how the numbers in `PROGRESS.md` were produced.

Nothing validates until `stigsmith/validation:el8` exists. It is built rather than pulled because target environments
are air-gapped: build it where you have a mirror and move the image. The database schema is applied when the API
starts, so there is no migration step.

Point `Stigsmith:Generation:ConventionRole:Path` at your own Ansible role to get your own conventions. Nothing about it
is committed here (constraint 5); `examples/example-role/` is a small synthetic role for the tests, and the
Development profile points at it.

## Where things are

| Project | Holds |
|---|---|
| `Stigsmith.Checklists` | `.ckl` / `.cklb` / XCCDF / ARF parsing and export, the normalized finding model |
| `Stigsmith.Rules` | Automatability classification and high-risk tagging |
| `Stigsmith.Generation` | Convention retrieval, prompt assembly, `IRemediationProvider` |
| `Stigsmith.Validation` | The lint → apply → re-scan → idempotency loop and its evidence |
| `docker/validation/` | The container image the loop applies remediation in |
| `Stigsmith.Api` | Minimal API endpoints, persistence, job queues, SignalR hubs |

`DECISIONS.md` records what was decided and what was rejected, including the mistakes worth remembering.
`PROGRESS.md` is the current state of the work, written to be picked up cold — **including a list of what has not been
verified and why**, which is the section to read before trusting any of this.
