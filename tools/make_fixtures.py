#!/usr/bin/env python3
"""Generates the synthetic checklist fixtures under fixtures/.

Constraint 2: nothing here comes from a real system. Hosts are *.example.test and every address is
from an RFC 5737 documentation range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). The host field
values are deliberately distinctive so the prompt-hygiene test can search generated prompts for them
and fail if any appears.

Run:  python3 tools/make_fixtures.py
Fixtures are committed; regenerate only when the catalog or a format changes, and review the diff.
"""

from __future__ import annotations

import json
import pathlib
import uuid
import xml.etree.ElementTree as ET

from rule_catalog import CATALOG

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

STIG_TITLE = "Red Hat Enterprise Linux 8 Security Technical Implementation Guide"
STIG_ID = "RHEL_8_STIG"
STIG_VERSION = "1"
RELEASE_INFO = "Release: 14 Benchmark Date: 24 Jul 2099"
STIG_REF = f"{STIG_TITLE} :: Version {STIG_VERSION}, {RELEASE_INFO}"
STIG_UUID = "8f0c2a64-5d7e-4a1b-9c3f-0e6d5b4a3c21"

# Deterministic UUID namespace so regenerating fixtures does not churn every id.
NS = uuid.UUID("b3e1f0c2-7a54-4d8e-9b21-6f0c5d4e3a12")


def indent_xml(root: ET.Element, space: str = "\t") -> str:
    """Indents element structure only.

    minidom's toprettyxml reflows text content, which silently collapses the blank lines that
    separate paragraphs in DISA check content and fix text. ET.indent only adds whitespace to
    elements that have element children, so multi-line and whitespace-only text survives verbatim.
    """
    ET.indent(root, space=space)
    return ET.tostring(root, encoding="unicode") + "\n"


def det_uuid(*parts: str) -> str:
    return str(uuid.uuid5(NS, "|".join(parts)))


HOSTS = {
    "alpha": dict(
        host_name="host-alpha.example.test", ip="192.0.2.10", mac="00:53:00:AA:10:01",
        fqdn="host-alpha.example.test", comment="Synthetic fixture host ALPHA-CANARY-STRING",
        role="Member Server", tech_area="", target_key="2777"),
    "bravo": dict(
        host_name="host-bravo.example.test", ip="192.0.2.11", mac="00:53:00:AA:11:02",
        fqdn="host-bravo.example.test", comment="Synthetic fixture host BRAVO-CANARY-STRING",
        role="Member Server", tech_area="", target_key="2777"),
    "charlie": dict(
        host_name="host-charlie.example.test", ip="198.51.100.20", mac="00:53:00:AA:20:03",
        fqdn="host-charlie.example.test", comment="Synthetic fixture host CHARLIE-CANARY-STRING",
        role="Domain Controller", tech_area="Other Review", target_key="2777"),
    "delta": dict(
        host_name="host-delta.example.test", ip="203.0.113.30", mac="00:53:00:AA:30:04",
        fqdn="host-delta.example.test", comment="Synthetic fixture host DELTA-CANARY-STRING",
        role="Member Server", tech_area="", target_key="2777"),
}

# Most findings are Open -- an all-clean checklist gives this tool nothing to do. The pattern is
# index-based so fixtures are byte-stable across runs.
STATUS_CYCLE_CKL = ["Open", "Open", "Open", "NotAFinding", "Open", "Not_Reviewed", "Open", "Not_Applicable"]
CKL_TO_CKLB = {
    "Open": "open", "NotAFinding": "not_a_finding",
    "Not_Reviewed": "not_reviewed", "Not_Applicable": "not_applicable",
}
CKL_TO_XCCDF = {
    "Open": "fail", "NotAFinding": "pass",
    "Not_Reviewed": "notchecked", "Not_Applicable": "notapplicable",
}


def status_for(i: int, offset: int = 0) -> str:
    return STATUS_CYCLE_CKL[(i + offset) % len(STATUS_CYCLE_CKL)]


def cci_for(vuln: str) -> list[str]:
    n = int(vuln.split("-")[1])
    first = f"CCI-{(n % 900) + 100:06d}"
    return [first] if n % 3 else [first, "CCI-000366"]


def legacy_for(vuln: str) -> list[str]:
    n = int(vuln.split("-")[1])
    return [f"SV-{n - 143000}r792904_rule", f"V-{n - 143000}"] if n % 4 == 0 else []


def details_for(status: str, version: str) -> str:
    if status == "Open":
        return f"Scanned by synthetic fixture generator. {version} did not match the required value."
    if status == "NotAFinding":
        return f"Scanned by synthetic fixture generator. {version} matched the required value."
    if status == "Not_Applicable":
        return "Not applicable to this platform configuration."
    return ""


def comment_for(status: str) -> str:
    return "Queued for remediation." if status == "Open" else ""


# --------------------------------------------------------------------------- .ckl

CKL_ATTRS = [
    "Vuln_Num", "Severity", "Group_Title", "Rule_ID", "Rule_Ver", "Rule_Title", "Vuln_Discuss",
    "IA_Controls", "Check_Content", "Fix_Text", "False_Positives", "False_Negatives",
    "Documentable", "Mitigations", "Potential_Impact", "Third_Party_Tools", "Mitigation_Control",
    "Responsibility", "Security_Override_Guidance", "Check_Content_Ref", "Weight", "Class",
    "STIGRef", "TargetKey", "STIG_UUID",
]


def rule_id_for(vuln: str) -> str:
    n = int(vuln.split("-")[1])
    return f"SV-{n}r{900000 + n}_rule"


def ckl_vuln(entry, i: int, offset: int) -> ET.Element:
    vuln_num, version, severity, title, discussion, check, fix, _cls, _tags = entry
    el = ET.Element("VULN")
    values = {
        "Vuln_Num": vuln_num,
        "Severity": severity,
        "Group_Title": f"SRG-OS-{(int(vuln_num.split('-')[1]) % 900) + 100:06d}-GPOS-{i + 1:05d}",
        "Rule_ID": rule_id_for(vuln_num),
        "Rule_Ver": version,
        "Rule_Title": title,
        "Vuln_Discuss": discussion,
        "IA_Controls": "",
        "Check_Content": check,
        "Fix_Text": fix,
        "False_Positives": "",
        "False_Negatives": "",
        "Documentable": "false",
        "Mitigations": "",
        "Potential_Impact": "",
        "Third_Party_Tools": "",
        "Mitigation_Control": "",
        "Responsibility": "",
        "Security_Override_Guidance": "",
        "Check_Content_Ref": "M",
        "Weight": "10.0",
        "Class": "Unclass",
        "STIGRef": STIG_REF,
        "TargetKey": "2777",
        "STIG_UUID": STIG_UUID,
    }
    for attr in CKL_ATTRS:
        sd = ET.SubElement(el, "STIG_DATA")
        ET.SubElement(sd, "VULN_ATTRIBUTE").text = attr
        ET.SubElement(sd, "ATTRIBUTE_DATA").text = values[attr]
    for legacy in legacy_for(vuln_num):
        sd = ET.SubElement(el, "STIG_DATA")
        ET.SubElement(sd, "VULN_ATTRIBUTE").text = "LEGACY_ID"
        ET.SubElement(sd, "ATTRIBUTE_DATA").text = legacy
    for cci in cci_for(vuln_num):
        sd = ET.SubElement(el, "STIG_DATA")
        ET.SubElement(sd, "VULN_ATTRIBUTE").text = "CCI_REF"
        ET.SubElement(sd, "ATTRIBUTE_DATA").text = cci

    status = status_for(i, offset)
    ET.SubElement(el, "STATUS").text = status
    ET.SubElement(el, "FINDING_DETAILS").text = details_for(status, version)
    ET.SubElement(el, "COMMENTS").text = comment_for(status)
    ET.SubElement(el, "SEVERITY_OVERRIDE").text = ""
    ET.SubElement(el, "SEVERITY_JUSTIFICATION").text = ""
    return el


def write_ckl(path: pathlib.Path, host_key: str, entries, offset: int = 0) -> None:
    h = HOSTS[host_key]
    root = ET.Element("CHECKLIST")
    asset = ET.SubElement(root, "ASSET")
    for tag, val in [
        ("ROLE", h["role"]), ("ASSET_TYPE", "Computing"), ("HOST_NAME", h["host_name"]),
        ("HOST_IP", h["ip"]), ("HOST_MAC", h["mac"]), ("HOST_FQDN", h["fqdn"]),
        ("TARGET_COMMENT", h["comment"]), ("TECH_AREA", h["tech_area"]),
        ("TARGET_KEY", h["target_key"]), ("WEB_OR_DATABASE", "false"),
        ("WEB_DB_SITE", ""), ("WEB_DB_INSTANCE", ""),
    ]:
        ET.SubElement(asset, tag).text = val

    stigs = ET.SubElement(root, "STIGS")
    istig = ET.SubElement(stigs, "iSTIG")
    info = ET.SubElement(istig, "STIG_INFO")
    for name, data in [
        ("version", STIG_VERSION), ("classification", "UNCLASSIFIED"), ("customname", ""),
        ("stigid", STIG_ID), ("description", "This STIG provides guidance for RHEL 8."),
        ("filename", "U_RHEL_8_STIG_V1R14_Manual-xccdf.xml"), ("releaseinfo", RELEASE_INFO),
        ("title", STIG_TITLE), ("uuid", STIG_UUID), ("notice", "terms-of-use"),
        ("source", "STIG.DOD.MIL"),
    ]:
        si = ET.SubElement(info, "SI_DATA")
        ET.SubElement(si, "SID_NAME").text = name
        ET.SubElement(si, "SID_DATA").text = data

    for i, entry in enumerate(entries):
        istig.append(ckl_vuln(entry, i, offset))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 3.x-->\n' + indent_xml(root))


# --------------------------------------------------------------------------- .cklb


def cklb_rule(entry, i: int, offset: int) -> dict:
    vuln_num, version, severity, title, discussion, check, fix, _cls, _tags = entry
    status = status_for(i, offset)
    return {
        "uuid": det_uuid("rule", vuln_num),
        "stig_uuid": STIG_UUID,
        "target_key": None,
        "stig_ref": None,
        "group_id_src": vuln_num,
        "group_tree": [{"id": vuln_num, "title": title, "description": f"<GroupDescription>{discussion}</GroupDescription>"}],
        "group_id": vuln_num,
        "severity": severity,
        "group_title": f"SRG-OS-{(int(vuln_num.split('-')[1]) % 900) + 100:06d}-GPOS-{i + 1:05d}",
        "rule_id_src": rule_id_for(vuln_num),
        "rule_id": rule_id_for(vuln_num),
        "rule_version": version,
        "rule_title": title,
        "fix_text": fix,
        "weight": "10.0",
        "check_content": check,
        "check_content_ref": {"href": "", "name": "M"},
        "classification": "Unclass",
        "discussion": discussion,
        "false_positives": "",
        "false_negatives": "",
        "documentable": False,
        "security_override_guidance": "",
        "mitigations": "",
        "potential_impacts": "",
        "third_party_tools": "",
        "mitigation_control": "",
        "responsibility": "",
        "ia_controls": "",
        "legacy_ids": legacy_for(vuln_num),
        "ccis": cci_for(vuln_num),
        "status": CKL_TO_CKLB[status],
        "overrides": {},
        "comments": comment_for(status),
        "finding_details": details_for(status, version),
    }


def write_cklb(path: pathlib.Path, host_key: str, entries, offset: int = 0) -> None:
    h = HOSTS[host_key]
    doc = {
        "title": f"{h['host_name']} — RHEL 8 STIG",
        "id": det_uuid("checklist", host_key),
        "stigs": [{
            "stig_name": STIG_TITLE,
            "display_name": "RHEL 8",
            "stig_id": STIG_ID,
            "version": STIG_VERSION,
            "release_info": RELEASE_INFO,
            "uuid": STIG_UUID,
            "reference_identifier": "2777",
            "size": len(entries),
            "rules": [cklb_rule(e, i, offset) for i, e in enumerate(entries)],
        }],
        "active": False,
        "mode": 1,
        "has_path": True,
        "target_data": {
            "target_type": "Computing",
            "host_name": h["host_name"],
            "ip_address": h["ip"],
            "mac_address": h["mac"],
            "fqdn": h["fqdn"],
            "comments": h["comment"],
            "role": h["role"],
            "is_web_database": False,
            "technology_area": h["tech_area"],
            "web_db_site": "",
            "web_db_instance": "",
        },
        "cklb_version": "1.0",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n")


# --------------------------------------------------------------------------- XCCDF / ARF

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
ARF_NS = "http://scap.nist.gov/schema/asset-reporting-format/1.1"
CORE_NS = "http://scap.nist.gov/schema/reporting-core/1.1"
AI_NS = "http://scap.nist.gov/schema/asset-identification/1.1"


def disa_description(discussion: str) -> str:
    return (f"<VulnDiscussion>{discussion}</VulnDiscussion><FalsePositives></FalsePositives>"
            "<FalseNegatives></FalseNegatives><Documentable>false</Documentable>"
            "<Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance>"
            "<PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools>"
            "<MitigationControl></MitigationControl><Responsibility></Responsibility>"
            "<IAControls></IAControls>")


def build_benchmark(entries) -> ET.Element:
    bm = ET.Element(f"{{{XCCDF_NS}}}Benchmark", {"id": f"xccdf_mil.disa.stig_benchmark_{STIG_ID}"})
    ET.SubElement(bm, f"{{{XCCDF_NS}}}status", {"date": "2099-07-24"}).text = "accepted"
    ET.SubElement(bm, f"{{{XCCDF_NS}}}title").text = STIG_TITLE
    ET.SubElement(bm, f"{{{XCCDF_NS}}}description").text = "This STIG provides guidance for RHEL 8."
    ET.SubElement(bm, f"{{{XCCDF_NS}}}version", {"time": "2099-07-24T00:00:00"}).text = STIG_VERSION

    for entry in entries:
        vuln_num, version, severity, title, discussion, check, fix, _cls, _tags = entry
        grp = ET.SubElement(bm, f"{{{XCCDF_NS}}}Group", {"id": f"xccdf_mil.disa.stig_group_{vuln_num}"})
        ET.SubElement(grp, f"{{{XCCDF_NS}}}title").text = vuln_num
        rule = ET.SubElement(grp, f"{{{XCCDF_NS}}}Rule", {
            "id": f"xccdf_mil.disa.stig_rule_{rule_id_for(vuln_num)}",
            "severity": severity,
            "weight": "10.0",
        })
        ET.SubElement(rule, f"{{{XCCDF_NS}}}version").text = version
        ET.SubElement(rule, f"{{{XCCDF_NS}}}title").text = title
        ET.SubElement(rule, f"{{{XCCDF_NS}}}description").text = disa_description(discussion)
        for cci in cci_for(vuln_num):
            ET.SubElement(rule, f"{{{XCCDF_NS}}}ident", {"system": "http://cyber.mil/cci"}).text = cci
        ET.SubElement(rule, f"{{{XCCDF_NS}}}fixtext", {"fixref": f"F-{vuln_num[2:]}r1_fix"}).text = fix
        chk = ET.SubElement(rule, f"{{{XCCDF_NS}}}check", {"system": "C-" + vuln_num[2:] + "r1_chk"})
        ET.SubElement(chk, f"{{{XCCDF_NS}}}check-content").text = check
    return bm


def build_test_result(entries, host_key: str, offset: int) -> ET.Element:
    h = HOSTS[host_key]
    tr = ET.Element(f"{{{XCCDF_NS}}}TestResult", {
        "id": f"xccdf_org.open-scap_testresult_xccdf_mil.disa.stig_benchmark_{STIG_ID}",
        "start-time": "2099-08-01T10:00:00+00:00",
        "end-time": "2099-08-01T10:07:33+00:00",
        "version": STIG_VERSION,
    })
    ET.SubElement(tr, f"{{{XCCDF_NS}}}benchmark", {"id": f"xccdf_mil.disa.stig_benchmark_{STIG_ID}"})
    ET.SubElement(tr, f"{{{XCCDF_NS}}}title").text = f"OSCAP Scan Result for {h['host_name']}"
    ET.SubElement(tr, f"{{{XCCDF_NS}}}target").text = h["host_name"]
    ET.SubElement(tr, f"{{{XCCDF_NS}}}target-address").text = "127.0.0.1"
    ET.SubElement(tr, f"{{{XCCDF_NS}}}target-address").text = h["ip"]
    facts = ET.SubElement(tr, f"{{{XCCDF_NS}}}target-facts")
    for name, typ, val in [
        ("urn:xccdf:fact:asset:identifier:mac", "string", h["mac"]),
        ("urn:xccdf:fact:asset:identifier:ipv4", "string", h["ip"]),
        ("urn:xccdf:fact:asset:identifier:fqdn", "string", h["fqdn"]),
    ]:
        ET.SubElement(facts, f"{{{XCCDF_NS}}}fact", {"name": name, "type": typ}).text = val

    for i, entry in enumerate(entries):
        vuln_num, version, severity = entry[0], entry[1], entry[2]
        status = status_for(i, offset)
        rr = ET.SubElement(tr, f"{{{XCCDF_NS}}}rule-result", {
            "idref": f"xccdf_mil.disa.stig_rule_{rule_id_for(vuln_num)}",
            "severity": severity,
            "time": "2099-08-01T10:03:12+00:00",
            "weight": "10.0",
        })
        ET.SubElement(rr, f"{{{XCCDF_NS}}}result").text = CKL_TO_XCCDF[status]
        if status == "Open":
            ET.SubElement(rr, f"{{{XCCDF_NS}}}message", {"severity": "info"}).text = \
                f"{version}: required value not present."
    score = ET.SubElement(tr, f"{{{XCCDF_NS}}}score", {"system": "urn:xccdf:scoring:default", "maximum": "100.0"})
    passed = sum(1 for i in range(len(entries)) if status_for(i, offset) == "NotAFinding")
    score.text = f"{100.0 * passed / max(len(entries), 1):.6f}"
    return tr


def serialize(el: ET.Element, extra_ns: dict[str, str] | None = None) -> str:
    ET.register_namespace("xccdf", XCCDF_NS)
    for prefix, uri in (extra_ns or {}).items():
        ET.register_namespace(prefix, uri)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + indent_xml(el, "  ")


def write_xccdf(path: pathlib.Path, entries, host_key: str, offset: int) -> None:
    bm = build_benchmark(entries)
    bm.append(build_test_result(entries, host_key, offset))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialize(bm))


def write_arf(path: pathlib.Path, entries, host_key: str, offset: int) -> None:
    """ARF wraps the benchmark in report-requests and the results in reports."""
    h = HOSTS[host_key]
    coll = ET.Element(f"{{{ARF_NS}}}asset-report-collection")

    requests = ET.SubElement(coll, f"{{{ARF_NS}}}report-requests")
    req = ET.SubElement(requests, f"{{{ARF_NS}}}report-request", {"id": "collection1"})
    content = ET.SubElement(req, f"{{{CORE_NS}}}content")
    content.append(build_benchmark(entries))

    assets = ET.SubElement(coll, f"{{{ARF_NS}}}assets")
    asset_el = ET.SubElement(assets, f"{{{ARF_NS}}}asset", {"id": "asset0"})
    computing = ET.SubElement(asset_el, f"{{{AI_NS}}}computing-device")
    conn = ET.SubElement(computing, f"{{{AI_NS}}}connections")
    c = ET.SubElement(conn, f"{{{AI_NS}}}connection")
    ET.SubElement(c, f"{{{AI_NS}}}ip-address").text = h["ip"]
    ET.SubElement(c, f"{{{AI_NS}}}mac-address").text = h["mac"]
    ET.SubElement(computing, f"{{{AI_NS}}}fqdn").text = h["fqdn"]

    reports = ET.SubElement(coll, f"{{{ARF_NS}}}reports")
    report = ET.SubElement(reports, f"{{{ARF_NS}}}report", {"id": "xccdf1"})
    rcontent = ET.SubElement(report, f"{{{CORE_NS}}}content")
    rcontent.append(build_test_result(entries, host_key, offset))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialize(coll, {"arf": ARF_NS, "core": CORE_NS, "ai": AI_NS}))


# --------------------------------------------------------------------------- edge cases


def write_edge_case_ckl(path: pathlib.Path) -> None:
    """
    A small .ckl exercising the things that break naive parsers: repeated attributes, empty and
    whitespace-only elements, a rule with no Fix_Text at all, non-ASCII text, XML-escaped markup
    inside Check_Content, and a STIG_DATA attribute this tool does not model.
    """
    root = ET.Element("CHECKLIST")
    asset = ET.SubElement(root, "ASSET")
    for tag, val in [
        ("ROLE", "None"), ("ASSET_TYPE", "Computing"), ("HOST_NAME", "host-edge.example.test"),
        ("HOST_IP", "203.0.113.99"), ("HOST_MAC", ""), ("HOST_FQDN", ""),
        ("TARGET_COMMENT", ""), ("TECH_AREA", ""), ("TARGET_KEY", ""),
        ("WEB_OR_DATABASE", "true"), ("WEB_DB_SITE", "edge-site"), ("WEB_DB_INSTANCE", ""),
    ]:
        ET.SubElement(asset, tag).text = val

    stigs = ET.SubElement(root, "STIGS")
    istig = ET.SubElement(stigs, "iSTIG")
    info = ET.SubElement(istig, "STIG_INFO")
    for name, data in [("version", "1"), ("stigid", "EDGE_CASES"), ("title", "Edge case fixture"),
                       ("releaseinfo", "Release: 1"), ("uuid", det_uuid("stig", "edge"))]:
        si = ET.SubElement(info, "SI_DATA")
        ET.SubElement(si, "SID_NAME").text = name
        ET.SubElement(si, "SID_DATA").text = data

    cases = [
        ("V-999001", "EDGE-00-000001", "high", "Rule with three CCI references and two legacy ids.",
         "Discussion.", "Check content.", "Fix text.",
         ["CCI-000366", "CCI-001764", "CCI-002235"], ["V-77777", "SV-77777r1_rule"], "Open"),
        ("V-999002", "EDGE-00-000002", "low", "Rule with no fix text at all.",
         "", "Ask the ISSO to confirm the control is documented.", "",
         [], [], "Not_Reviewed"),
        ("V-999003", "EDGE-00-000003", "medium", "Rule with non-ASCII text — en dash, ümlaut, 日本語.",
         "Discussion with a — dash.", "Check for “smart quotes” in the banner file.",
         "Set the value to “enforcing”.", ["CCI-000366"], [], "Open"),
        ("V-999004", "EDGE-00-000004", "medium", "Rule whose check content contains escaped markup.",
         "Discussion.",
         "Verify the file contains:\n\n<Directory /var/www>\n  Require all denied\n</Directory>\n\n"
         "If it does not, this is a finding. Note the & character and the \"quoted\" value.",
         "Add the <Directory> block shown above.", ["CCI-000366"], [], "Open"),
    ]

    for vuln, version, severity, title, discussion, check, fix, ccis, legacies, status in cases:
        el = ET.SubElement(istig, "VULN")

        def add(attr: str, data: str) -> None:
            sd = ET.SubElement(el, "STIG_DATA")
            ET.SubElement(sd, "VULN_ATTRIBUTE").text = attr
            ET.SubElement(sd, "ATTRIBUTE_DATA").text = data

        add("Vuln_Num", vuln)
        add("Severity", severity)
        add("Rule_ID", rule_id_for(vuln))
        add("Rule_Ver", version)
        add("Rule_Title", title)
        add("Vuln_Discuss", discussion)
        add("Check_Content", check)
        add("Fix_Text", fix)
        add("Weight", "10.0")
        add("STIGRef", "Edge case fixture :: Version 1")
        # An attribute Stigsmith does not model; export must not drop it.
        add("Vendor_Future_Field", "preserve-me-verbatim")
        for legacy in legacies:
            add("LEGACY_ID", legacy)
        for cci in ccis:
            add("CCI_REF", cci)

        ET.SubElement(el, "STATUS").text = status
        ET.SubElement(el, "FINDING_DETAILS").text = "" if status != "Open" else "   "
        ET.SubElement(el, "COMMENTS").text = ""
        ET.SubElement(el, "SEVERITY_OVERRIDE").text = ""
        ET.SubElement(el, "SEVERITY_JUSTIFICATION").text = ""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 3.x-->\n' + indent_xml(root))


# --------------------------------------------------------------------------- expectations


def write_expectations(path: pathlib.Path, entries) -> None:
    """The graded answer key for M3. Kept beside the fixtures so the two cannot drift."""
    high_risk_domains = {"sshd", "pam", "selinux", "firewall", "authentication", "network"}
    doc = {
        "note": "Expected classification per rule. Authored with the catalog; the classifier is "
                "graded against it in ClassificationTests.",
        "highRiskDomains": sorted(high_risk_domains),
        "rules": [
            {
                "vulnId": e[0],
                "ruleId": rule_id_for(e[0]),
                "ruleVersion": e[1],
                "expectedAutomatability": e[7],
                "domains": e[8],
                "expectedHighRisk": bool(high_risk_domains & set(e[8])),
            }
            for e in entries
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n")


def main() -> None:
    entries = CATALOG

    write_ckl(FIXTURES / "ckl" / "rhel8-host-alpha.ckl", "alpha", entries, offset=0)
    write_cklb(FIXTURES / "cklb" / "rhel8-host-bravo.cklb", "bravo", entries, offset=3)

    # Multi-host set: same benchmark, three hosts, different status patterns and rule subsets.
    write_ckl(FIXTURES / "multihost" / "host-alpha.ckl", "alpha", entries[:60], offset=1)
    write_ckl(FIXTURES / "multihost" / "host-charlie.ckl", "charlie", entries[:40], offset=2)
    write_cklb(FIXTURES / "multihost" / "host-delta.cklb", "delta", entries[:55], offset=5)

    write_xccdf(FIXTURES / "xccdf" / "rhel8-host-charlie-xccdf.xml", entries, "charlie", offset=2)
    write_arf(FIXTURES / "xccdf" / "rhel8-host-delta-arf.xml", entries[:40], "delta", offset=5)

    write_edge_case_ckl(FIXTURES / "ckl" / "edge-cases.ckl")
    write_expectations(FIXTURES / "expectations" / "rhel8-classification.json", entries)

    for p in sorted(FIXTURES.rglob("*")):
        if p.is_file():
            print(f"{p.relative_to(ROOT)}  {p.stat().st_size:>8,} bytes")


if __name__ == "__main__":
    main()
