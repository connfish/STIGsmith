# Progress — handoff

**Stopping point:** M1–M6 complete, then a refinement pass that removed the unverified orchestration path, ran the
Docker validation path for the first time, and ran the whole product against a real model in real containers. M7
(the triage UI) was bonus-only and is **not started**.

`dotnet test` → **319 passed, 0 skipped, 0 failed** on a machine with a Docker daemon, the validation image and
Ollama. On a bare clone the Docker- and Ollama-backed suites detect their absence and skip; nothing else changes.

---

## The honest numbers

`tools/live_run.py` against the synthetic RHEL 8 checklist, `qwen2.5-coder:7b` through Ollama, fresh AlmaLinux 8
containers, on 2026-09-15. Every eligible open rule, every risk domain opted in. Eight runs were made while the
harness was being fixed; this is the last one, on the code as committed:

```
72 rules: 47 automatable, 9 manual, 16 needs-review (65% automatable). Of 45 open: 29 automatable.
29 generated: 29 produced a task list, 0 cannot-automate, 0 errors. About five seconds a rule.
29 validated: 18 passed, 11 need human review. 4 of the passes were confirmed by a real SCAP scan.
```

The first run of the same thing passed 9 and confirmed 0 by scan, and every difference is a harness defect the live
runs exposed (see `DECISIONS.md`, "What a real model and a real container found" and what follows it).

**What the 18 passes are worth.** Nine are real flips, fail to pass, where the check content's own compliant output
was absent before the remediation and present after it: the SSH banner, `PermitRootLogin`, the SSH MACs, `minclass`,
`maxrepeat`, `PASS_MIN_DAYS`, `minlen`, a package install and a modprobe blacklist line. Four are confirmed by `oscap`
against the SSG datastream (package-removal and library-permission rules), where the container already complied and
the remediation held. One went from "could not be verified" to pass. Four are check-content passes where the container
already complied (`crypt_style`, `policycoreutils`, `fs.protected_symlinks`, the audit tool modes). The report labels
which verifier produced each verdict and why.

**What the 11 are, by cause:**

| Cause | Rules | What it says |
|---|---|---|
| The model nested `changed_when` inside the `command` module | 010020 | Real model error; lint caught it, the repair did not fix it |
| The model wrote an invalid regex (`^*`) | 020024 | Real model error; caught under `--check` |
| No systemd, no SELinux, no bootloader in a container | 010561, 040180, 010800, 030063, 040286 | Container limitation; failed apply or honest failed re-scan |
| The check greps `/etc/audit/audit.rules`, which only a running auditd compiles | 030170, 030310 | Container limitation; reported as "could not be verified", not as a fail |
| Config file's package not in the image (`postfix`), or an old path (`/etc/audisp/`) | 040020, 030010 | Image gap and a STIG-revision quirk |

Two things the runs measured about the model itself. The repair attempt fixed nothing in any run: given the lint error
verbatim, the 7B model re-emitted the same mistake. And of three prompt rules added for its error classes, one worked
(it stopped inventing a module), one was ignored, and one made a rule worse by priming the model toward the shape it
warned against; only the one that measured well was kept.

---

## What was run for the first time this pass

- **`DockerValidationSandbox` against a real daemon.** It could never have run before: Testcontainers ships a fork of
  Docker.DotNet under the same assembly name, and the test process loaded the fork. The sandbox is on the fork now.
- **The API against real PostgreSQL**, all four suites. Four tests were order-dependent and three named fixture rules
  that were not open; one endpoint returned a 500 from a query EF Core cannot translate.
- **The live Ollama call**, and the full product loop end to end through the API.
- **`oscap` producing a verdict.** The rule-id and profile the verifier used did not exist in the SSG datastream, and
  once that was fixed the parser dropped the verdict on a carriage return. Both fixed; a real-container test pins it.

## What is stubbed, and what is simply not there

- **M7 triage UI — not started.**
- **`examples/example-role/` is synthetic**, 21 tasks. Point `Stigsmith:Generation:ConventionRole:Path` at a real role.
- **No authentication or authorization on the API.** Not in scope and not faked.
- **The convention index does not watch the filesystem.** `POST /api/conventions/reindex` is explicit.
- **A cloud provider is not implemented.** `IRemediationProvider` is the seam.
- **Enums serialize as integers** in API responses (`outcome`, `verifiedBy`, `status`). Fine for the tests, unfriendly
  for a UI; a `JsonStringEnumConverter` on the HTTP JSON options is the fix, and the test clients would need the
  same converter.

## What I am uncertain about

1. **`.cklb` has no published schema.** Derived from observed STIG Viewer 3 output; the whole source document is
   re-emitted on export so a misunderstood key survives a round trip. Still the most likely place M2 breaks.
2. **The M3 answer key was corrected five times while the heuristics were written.** The held-out cases in
   `RuleClassifierTests` are the stronger evidence, not the 100% agreement figure.
3. **BM25 retrieval drifts at ranks 2–3** on a 21-task role. The top hit is right; embeddings are the upgrade path.
4. **The check-content verifier reads DISA prose.** It now requires the compliant output the check shows and infers
   polarity from the "this is a finding" sentence, which turned twelve "pass to pass" results into nine real flips and
   three honest unknowns. It is still a reading of prose: a check whose shown output is only an example falls back to
   the exit code, and the evidence says so.
5. **A container is not a host, measured.** Systemd, auditd and sysctl rules cannot apply, and SSG marks most
   host-configuration rules not applicable inside a container, so `oscap` judges only package-removal and
   file-permission rules there. A VM sandbox is what changes this.
6. **The verifier's allow-list is a shell-word parser that must agree with `sh`.** It refuses every expansion,
   redirection and grouping outright and decodes only single quotes, double quotes and backslashes, so what it
   accepts it has parsed the same way the shell will. One residual: unquoted globs expand in the work directory,
   which only the loop writes to. A second review pass found a quoting bypass in the first version; the cases are
   in `ValidationUnitTests`.
7. **Few-shot examples are the operator's own role source.** If that role hardcodes a hostname, it reaches the model.

## What I would do next, in order

1. **A VM sandbox behind `IValidationSandbox`.** Seven of the eleven review cases and every SSG `machine` rule are
   waiting on it. It is the difference between validating file rules and validating most of a checklist.
2. **Add `postfix` to the validation image**, and accept that `/etc/audisp/` is the older STIG revision's path.
3. **A stronger model, or a corrective example in the few-shot block**, for the two error classes the 7B model
   repeats. Negative instructions in the system prompt measurably do not work on it.
4. **Then M7.** The API now returns string enums and the validation report carries a reason per verdict, which is
   what a triage UI needs to show.

## Running it

```bash
make run                     # Postgres in Docker, API on the host at http://localhost:5045/scalar
make image                   # once, before validation does anything
make test
python3 tools/live_run.py    # the whole loop over the fixture checklist; writes report.json and prints the table
```

Ollama runs natively or via `make ollama`. Point `Stigsmith:Generation:ConventionRole:Path` at your own Ansible role.
