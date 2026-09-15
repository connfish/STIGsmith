#!/usr/bin/env python3
"""Run the whole product against the synthetic checklist and print the validation report.

This is how the numbers in PROGRESS.md were produced. It needs the API up (`make run`), a model behind it, and the
validation image built (`make image`). Standard library only.

    python3 tools/live_run.py [--api http://localhost:5045] [--out DIR]
"""
import argparse, json, mimetypes, os, sys, time, urllib.error, urllib.request, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "..", "fixtures", "ckl", "rhel8-host-alpha.ckl")
OUTCOMES = {0: "Pending", 1: "Passed", 2: "Failed", 3: "NeedsHumanReview", 4: "Skipped"}
VERIFIERS = {0: "none", 1: "oscap", 2: "check-content"}
ALL_DOMAINS = ["sshd", "pam", "selinux", "firewall", "authentication", "network"]


def main():
    args = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    args.add_argument("--api", default="http://localhost:5045")
    args.add_argument("--out", default=".", help="where to write generations.json, validations.json and report.json")
    opts = args.parse_args()

    def req(method, path, body=None, ctype="application/json"):
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        r = urllib.request.Request(opts.api + path, data=data, method=method,
                                   headers={"Content-Type": ctype} if data is not None else {})
        try:
            with urllib.request.urlopen(r, timeout=120) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def log(*a):
        print(time.strftime("%H:%M:%S"), *a, flush=True)

    def wait_all(ids, path, done, label, minutes):
        finished, deadline = {}, time.time() + 60 * minutes
        while len(finished) < len(ids) and time.time() < deadline:
            for id_, name in ids.items():
                if id_ in finished:
                    continue
                status, d = req("GET", path.format(id_))
                if status == 200 and done(d):
                    finished[id_] = d
                    log(f"  {label} {name:16} {describe(d)}")
            time.sleep(5)
        return finished

    def describe(d):
        if "outcome" in d:
            return (f"{OUTCOMES.get(d['outcome'], d['outcome']):18} {d['scanStatusBefore'] or '-':>7}->"
                    f"{d['scanStatusAfter'] or '-':<7} stage={d['failedStage'] or '-'} attempt={d['repairAttempt']}")
        return f"yaml={'yes' if d['yaml'] else 'no ':3} tokens={d['completionTokens']:4} {d['error'] or ''}"

    boundary = uuid.uuid4().hex
    with open(FIXTURE, "rb") as f:
        ckl = f.read()
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"rhel8-host-alpha.ckl\"\r\n"
            f"Content-Type: application/xml\r\n\r\n").encode() + ckl + f"\r\n--{boundary}--\r\n".encode()
    status, imported = req("POST", "/api/checklists/import", body, f"multipart/form-data; boundary={boundary}")
    if status != 201:
        sys.exit(f"import failed: {status} {imported}")
    log("imported:", imported["coverageSummary"])
    checklist = imported["id"]

    status, queued = req("POST", f"/api/checklists/{checklist}/generate", {"optInRiskDomains": ALL_DOMAINS})
    if status != 200:
        sys.exit(f"generate failed: {status} {queued}")
    log(f"generation: {queued['candidates']} candidates, {queued['queued']} queued, {queued['skipped']} skipped")
    generations = wait_all({g["generationId"]: g["ruleVersion"] for g in queued["queuedItems"]},
                           "/api/generations/{}", lambda d: d["rawResponse"] or d["error"], "generated", 60)
    json.dump(generations, open(os.path.join(opts.out, "generations.json"), "w"), indent=1)

    status, queued = req("POST", f"/api/checklists/{checklist}/validate", {})
    if status != 200:
        sys.exit(f"validate failed: {status} {queued}")
    log(f"validation: {queued['queued']} queued, {queued['skipped']} skipped")
    for s in queued["skippedItems"]:
        log("  skipped", s["ruleVersion"], s["reason"])
    validations = wait_all({r["validationRunId"]: r["ruleVersion"] for r in queued["queuedItems"]},
                           "/api/validations/{}", lambda d: d["completedAt"], "validated", 120)
    json.dump(validations, open(os.path.join(opts.out, "validations.json"), "w"), indent=1)

    status, report = req("GET", f"/api/checklists/{checklist}/validation-report")
    json.dump(report, open(os.path.join(opts.out, "report.json"), "w"), indent=1)
    log("REPORT:", report["summary"])
    for r in report["rows"]:
        log(f"  {r['ruleVersion']:16} {OUTCOMES.get(r['outcome'], r['outcome']):18} "
            f"{r['scanStatusBefore'] or '-':>7}->{r['scanStatusAfter'] or '-':<7} "
            f"by={VERIFIERS.get(r['verifiedBy'], r['verifiedBy']):13} attempts={r['attempts']} "
            f"stage={r['failedStage'] or '-':11} {r['summary'][:100]}")


if __name__ == "__main__":
    main()
