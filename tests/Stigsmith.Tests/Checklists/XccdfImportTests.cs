using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;
using Stigsmith.Checklists.Xccdf;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests.Checklists;

public class XccdfImportTests
{
    private static Checklist Xccdf() => XccdfReader.Read(TestEnvironment.ReadFixture("xccdf", "rhel8-host-charlie-xccdf.xml"));

    private static Checklist Arf() => XccdfReader.Read(TestEnvironment.ReadFixture("xccdf", "rhel8-host-delta-arf.xml"));

    [Fact]
    public void Reads_target_from_xccdf_test_result()
    {
        var checklist = Xccdf();

        checklist.SourceFormat.ShouldBe(ChecklistFormat.Xccdf);
        checklist.Host.HostName.ShouldBe("host-charlie.example.test");
        checklist.Host.HostFqdn.ShouldBe("host-charlie.example.test");
        checklist.Host.HostMac.ShouldBe("00:53:00:AA:20:03");
    }

    /// <summary>
    /// target-address repeats per interface and loopback comes first in oscap output; taking the
    /// first element would record every scanned host as 127.0.0.1.
    /// </summary>
    [Fact]
    public void Skips_loopback_when_choosing_the_target_address()
    {
        Xccdf().Host.HostIp.ShouldBe("198.51.100.20");
    }

    [Fact]
    public void Reads_rule_content_from_the_embedded_benchmark()
    {
        var finding = Xccdf().Findings.Single(f => f.Rule.RuleVersion == "RHEL-08-010550");

        finding.Rule.RuleId.ShouldBe("SV-230296r1130296_rule");
        finding.Rule.GroupId.ShouldBe("V-230296");
        finding.Rule.Severity.ShouldBe(Severity.Medium);
        finding.Rule.FixText.ShouldContain("PermitRootLogin no");
        finding.Rule.CheckContent.ShouldContain("permitrootlogin");
        finding.Rule.CciRefs.ShouldNotBeEmpty();
    }

    /// <summary>
    /// DISA packs its per-rule metadata into the XCCDF description as escaped pseudo-XML. If that
    /// unpacking breaks, discussion text silently becomes a wall of tag soup.
    /// </summary>
    [Fact]
    public void Unpacks_the_disa_description_block()
    {
        var finding = Xccdf().Findings.Single(f => f.Rule.RuleVersion == "RHEL-08-010550");

        finding.Rule.Discussion.ShouldContain("additional layer of security");
        finding.Rule.Discussion.ShouldNotContain("VulnDiscussion");
        finding.Rule.Discussion.ShouldNotContain("<");
        finding.Rule.Documentable.ShouldBeFalse();
    }

    [Fact]
    public void Maps_xccdf_results_to_finding_statuses()
    {
        var counts = Xccdf().CountsByStatus();

        // fail -> Open, pass -> NotAFinding, notapplicable -> NotApplicable, notchecked -> NotReviewed.
        counts[FindingStatus.Open].ShouldBeGreaterThan(30);
        counts[FindingStatus.NotAFinding].ShouldBeGreaterThan(0);
        counts[FindingStatus.NotApplicable].ShouldBeGreaterThan(0);
        counts[FindingStatus.NotReviewed].ShouldBeGreaterThan(0);
        Xccdf().Findings.Count().ShouldBe(72);
    }

    [Fact]
    public void Records_the_scanner_result_and_messages_as_finding_details()
    {
        var open = Xccdf().Findings.First(f => f.Status == FindingStatus.Open);

        open.FindingDetails.ShouldContain("SCAP result: fail");
        open.FindingDetails.ShouldContain("required value not present");
    }

    [Fact]
    public void Reads_an_arf_collection()
    {
        var checklist = Arf();

        checklist.SourceFormat.ShouldBe(ChecklistFormat.Arf);
        checklist.Host.HostName.ShouldBe("host-delta.example.test");
        checklist.Host.HostIp.ShouldBe("203.0.113.30");
        checklist.Findings.Count().ShouldBe(40);
        checklist.Findings.ShouldAllBe(f => f.Rule.FixText.Length > 0);
    }

    /// <summary>
    /// A results-only XCCDF file (the benchmark was not inlined) still has to import: the rules are
    /// named, just not described. Dropping them would hide findings from triage, so they come through
    /// with a title that says why they are bare. Documented as UNCERTAIN on the reader.
    /// </summary>
    [Fact]
    public void Imports_results_with_no_benchmark_present()
    {
        const string xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.open-scap_testresult_1">
          <title>Results only</title>
          <target>host-echo.example.test</target>
          <target-address>192.0.2.77</target-address>
          <rule-result idref="xccdf_mil.disa.stig_rule_SV-230296r1130296_rule" severity="medium">
            <result>fail</result>
          </rule-result>
        </TestResult>
        """;

        var checklist = XccdfReader.Read(xml);
        var finding = checklist.Findings.Single();

        checklist.Host.HostName.ShouldBe("host-echo.example.test");
        finding.Rule.RuleId.ShouldBe("SV-230296r1130296_rule");
        finding.Rule.GroupId.ShouldBe("V-230296");
        finding.Rule.Severity.ShouldBe(Severity.Medium);
        finding.Status.ShouldBe(FindingStatus.Open);
        finding.Rule.FixText.ShouldBeEmpty();
        finding.Rule.Title.ShouldContain("rule content not present");
    }

    [Fact]
    public void Rejects_xml_that_is_neither_benchmark_nor_results()
    {
        Should.Throw<ChecklistFormatException>(() => XccdfReader.Read("<oval_results xmlns='x'/>"));
    }

    [Fact]
    public void Reads_oval_backed_checks_without_losing_the_reference()
    {
        const string xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_mil.disa.stig_benchmark_X">
          <title>Automated benchmark</title>
          <version>1</version>
          <Group id="xccdf_mil.disa.stig_group_V-230296">
            <title>V-230296</title>
            <Rule id="xccdf_mil.disa.stig_rule_SV-230296r1_rule" severity="medium">
              <title>Root SSH logon</title>
              <fixtext>Set PermitRootLogin no.</fixtext>
              <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
                <check-content-ref href="U_RHEL_8_STIG.xml" name="oval:mil.disa.stig.rhel8:def:296"/>
              </check>
            </Rule>
          </Group>
          <TestResult id="tr1">
            <target>host-foxtrot.example.test</target>
            <rule-result idref="xccdf_mil.disa.stig_rule_SV-230296r1_rule"><result>fail</result></rule-result>
          </TestResult>
        </Benchmark>
        """;

        var finding = XccdfReader.Read(xml).Findings.Single();

        finding.Rule.CheckContent.ShouldBe("Automated check via OVAL definition oval:mil.disa.stig.rhel8:def:296.");
        finding.Rule.FixText.ShouldBe("Set PermitRootLogin no.");
    }
}
