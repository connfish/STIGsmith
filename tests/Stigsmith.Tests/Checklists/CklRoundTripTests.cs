using System.Xml.Linq;
using Stigsmith.Checklists;
using Stigsmith.Checklists.Ckl;
using Stigsmith.Checklists.Model;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests.Checklists;

public class CklRoundTripTests
{
    private static Checklist Alpha() => CklReader.Read(TestEnvironment.ReadFixture("ckl", "rhel8-host-alpha.ckl"));

    [Fact]
    public void Reads_host_metadata()
    {
        var host = Alpha().Host;

        host.HostName.ShouldBe("host-alpha.example.test");
        host.HostIp.ShouldBe("192.0.2.10");
        host.HostMac.ShouldBe("00:53:00:AA:10:01");
        host.HostFqdn.ShouldBe("host-alpha.example.test");
        host.Role.ShouldBe("Member Server");
        host.TargetKey.ShouldBe("2777");
        host.IsWebOrDatabase.ShouldBeFalse();
        host.TechArea.ShouldBeEmpty();
    }

    [Fact]
    public void Reads_stig_info_and_all_findings()
    {
        var checklist = Alpha();

        checklist.SourceFormat.ShouldBe(ChecklistFormat.Ckl);
        checklist.Stigs.Count.ShouldBe(1);
        checklist.Stigs[0].Info.StigId.ShouldBe("RHEL_8_STIG");
        checklist.Stigs[0].Info.Version.ShouldBe("1");
        checklist.Stigs[0].Info.ReleaseInfo.ShouldStartWith("Release: 14");
        checklist.Findings.Count().ShouldBe(72);
    }

    [Fact]
    public void Reads_rule_content_including_repeated_attributes()
    {
        // V-230225 is the SSH banner rule; the generator gives every fourth rule two legacy ids.
        var finding = Alpha().Findings.Single(f => f.Rule.GroupId == "V-230296");

        finding.Rule.RuleId.ShouldBe("SV-230296r1130296_rule");
        finding.Rule.RuleVersion.ShouldBe("RHEL-08-010550");
        finding.Rule.Severity.ShouldBe(Severity.Medium);
        finding.Rule.Title.ShouldContain("direct logons to the root account");
        finding.Rule.FixText.ShouldContain("PermitRootLogin no");
        finding.Rule.CheckContent.ShouldContain("grep -i permitrootlogin");
        finding.Rule.CciRefs.ShouldNotBeEmpty();
        finding.Rule.StigRef.ShouldContain("Version 1");
        finding.Rule.NumericId.ShouldBe("230296");
    }

    [Fact]
    public void Reads_repeated_cci_and_legacy_id_attributes()
    {
        var edge = CklReader.Read(TestEnvironment.ReadFixture("ckl", "edge-cases.ckl"));
        var finding = edge.Findings.Single(f => f.Rule.GroupId == "V-999001");

        finding.Rule.CciRefs.ShouldBe(["CCI-000366", "CCI-001764", "CCI-002235"]);
        finding.Rule.LegacyIds.ShouldBe(["V-77777", "SV-77777r1_rule"]);
    }

    [Fact]
    public void Reads_statuses_details_and_comments()
    {
        var byStatus = Alpha().CountsByStatus();

        byStatus[FindingStatus.Open].ShouldBeGreaterThan(30);
        byStatus.ShouldContainKey(FindingStatus.NotAFinding);
        byStatus.ShouldContainKey(FindingStatus.NotReviewed);
        byStatus.ShouldContainKey(FindingStatus.NotApplicable);

        var open = Alpha().Findings.First(f => f.Status == FindingStatus.Open);
        open.FindingDetails.ShouldContain("did not match the required value");
        open.Comments.ShouldBe("Queued for remediation.");
    }

    /// <summary>
    /// The round trip that matters: read a real-shaped .ckl, write it back, and the result must be
    /// the same document. Asserted on bytes rather than on the parsed model, because "STIG Viewer can
    /// still open it" is the actual requirement, and the surest way to keep that true is to change
    /// nothing that was not asked to change. Only line endings and trailing whitespace are ignored.
    /// </summary>
    [Fact]
    public void Round_trips_byte_for_byte()
    {
        var original = TestEnvironment.ReadFixture("ckl", "rhel8-host-alpha.ckl");

        var written = CklWriter.Write(CklReader.Read(original));

        Canonical(written).ShouldBe(Canonical(original));
    }

    [Fact]
    public void Round_trips_edge_cases_byte_for_byte()
    {
        var original = TestEnvironment.ReadFixture("ckl", "edge-cases.ckl");

        var written = CklWriter.Write(CklReader.Read(original));

        Canonical(written).ShouldBe(Canonical(original));
    }

    [Fact]
    public void Round_trip_preserves_attributes_stigsmith_does_not_model()
    {
        var original = TestEnvironment.ReadFixture("ckl", "edge-cases.ckl");

        var written = CklWriter.Write(CklReader.Read(original));

        written.ShouldContain("Vendor_Future_Field");
        written.ShouldContain("preserve-me-verbatim");
    }

    [Fact]
    public void Round_trip_survives_three_passes()
    {
        var once = CklWriter.Write(CklReader.Read(TestEnvironment.ReadFixture("ckl", "rhel8-host-alpha.ckl")));
        var twice = CklWriter.Write(CklReader.Read(once));
        var thrice = CklWriter.Write(CklReader.Read(twice));

        twice.ShouldBe(once);
        thrice.ShouldBe(once);
    }

    [Fact]
    public void Status_and_comment_updates_are_written_back()
    {
        var checklist = Alpha();
        var target = checklist.Findings.First(f => f.Status == FindingStatus.Open);
        var updated = checklist.WithReviews(new Dictionary<string, FindingReview>
        {
            [target.Rule.RuleId] = new(
                FindingStatus.NotAFinding,
                "Remediated by Stigsmith and confirmed by re-scan.",
                "Validated: lint, apply, re-scan, idempotency all passed."),
        });

        var reread = CklReader.Read(CklWriter.Write(updated));
        var result = reread.Findings.Single(f => f.Rule.RuleId == target.Rule.RuleId);

        result.Status.ShouldBe(FindingStatus.NotAFinding);
        result.FindingDetails.ShouldBe("Remediated by Stigsmith and confirmed by re-scan.");
        result.Comments.ShouldBe("Validated: lint, apply, re-scan, idempotency all passed.");
        // Nothing else moved.
        reread.Findings.Count().ShouldBe(72);
        reread.Host.ShouldBe(checklist.Host);
    }

    [Fact]
    public void Export_is_well_formed_xml_with_the_elements_stig_viewer_requires()
    {
        var doc = XDocument.Parse(CklWriter.Write(Alpha()));

        doc.Root!.Name.LocalName.ShouldBe("CHECKLIST");
        doc.Root.Element("ASSET").ShouldNotBeNull();
        doc.Root.Element("STIGS")!.Elements("iSTIG").Count().ShouldBe(1);
        var vuln = doc.Root.Element("STIGS")!.Element("iSTIG")!.Elements("VULN").First();
        vuln.Element("STATUS").ShouldNotBeNull();
        vuln.Element("FINDING_DETAILS").ShouldNotBeNull();
        vuln.Element("COMMENTS").ShouldNotBeNull();
        vuln.Element("SEVERITY_OVERRIDE").ShouldNotBeNull();
        vuln.Element("SEVERITY_JUSTIFICATION").ShouldNotBeNull();
        vuln.Elements("STIG_DATA").ShouldNotBeEmpty();
    }

    [Fact]
    public void Detects_format_from_content_not_extension()
    {
        ChecklistIo.Detect(TestEnvironment.ReadFixture("ckl", "rhel8-host-alpha.ckl")).ShouldBe(ChecklistFormat.Ckl);
        ChecklistIo.Detect(TestEnvironment.ReadFixture("cklb", "rhel8-host-bravo.cklb")).ShouldBe(ChecklistFormat.Cklb);
        ChecklistIo.Detect(TestEnvironment.ReadFixture("xccdf", "rhel8-host-charlie-xccdf.xml")).ShouldBe(ChecklistFormat.Xccdf);
        ChecklistIo.Detect(TestEnvironment.ReadFixture("xccdf", "rhel8-host-delta-arf.xml")).ShouldBe(ChecklistFormat.Arf);
    }

    [Fact]
    public void Rejects_a_document_that_is_not_a_checklist()
    {
        Should.Throw<ChecklistFormatException>(() => ChecklistIo.Read("hostname,status\nfoo,open\n"));
        Should.Throw<ChecklistFormatException>(() => CklReader.Read("<NotAChecklist/>"));
    }

    /// <summary>
    /// The root element, parsed without preserving whitespace: indentation and the document-level
    /// comment are not compared, but every element, attribute, value, and sibling order is.
    /// </summary>
    /// <summary>Ignores line endings and trailing whitespace; everything else is compared exactly.</summary>
    private static string Canonical(string xml) =>
        string.Join("\n", xml.Replace("\r\n", "\n").TrimEnd().Split('\n').Select(l => l.TrimEnd()));
}
