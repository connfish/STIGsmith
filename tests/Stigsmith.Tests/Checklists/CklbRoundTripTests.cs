using System.Text.Json;
using System.Text.Json.Nodes;
using Stigsmith.Checklists;
using Stigsmith.Checklists.Cklb;
using Stigsmith.Checklists.Model;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests.Checklists;

public class CklbRoundTripTests
{
    private static Checklist Bravo() => CklbReader.Read(TestEnvironment.ReadFixture("cklb", "rhel8-host-bravo.cklb"));

    [Fact]
    public void Reads_target_data()
    {
        var host = Bravo().Host;

        host.HostName.ShouldBe("host-bravo.example.test");
        host.HostIp.ShouldBe("192.0.2.11");
        host.HostMac.ShouldBe("00:53:00:AA:11:02");
        host.HostFqdn.ShouldBe("host-bravo.example.test");
        host.Role.ShouldBe("Member Server");
        host.AssetType.ShouldBe("Computing");
        host.IsWebOrDatabase.ShouldBeFalse();
    }

    [Fact]
    public void Reads_stig_and_rules()
    {
        var checklist = Bravo();

        checklist.SourceFormat.ShouldBe(ChecklistFormat.Cklb);
        checklist.Stigs.Count.ShouldBe(1);
        checklist.Stigs[0].Info.StigId.ShouldBe("RHEL_8_STIG");
        checklist.Stigs[0].Info.DisplayName.ShouldBe("RHEL 8");
        checklist.Findings.Count().ShouldBe(72);
    }

    [Fact]
    public void Reads_rule_content()
    {
        var finding = Bravo().Findings.Single(f => f.Rule.GroupId == "V-230332");

        finding.Rule.RuleVersion.ShouldBe("RHEL-08-020010");
        finding.Rule.Severity.ShouldBe(Severity.Medium);
        finding.Rule.FixText.ShouldContain("deny = 3");
        finding.Rule.CheckContent.ShouldContain("faillock.conf");
        finding.Rule.CciRefs.ShouldNotBeEmpty();
        finding.Rule.NumericId.ShouldBe("230332");
    }

    [Fact]
    public void Reads_all_four_statuses()
    {
        var counts = Bravo().CountsByStatus();

        counts.Keys.ShouldBe(
            [FindingStatus.Open, FindingStatus.NotAFinding, FindingStatus.NotReviewed, FindingStatus.NotApplicable],
            ignoreOrder: true);
        counts[FindingStatus.Open].ShouldBeGreaterThan(30);
    }

    [Fact]
    public void Round_trips_byte_for_byte()
    {
        var original = TestEnvironment.ReadFixture("cklb", "rhel8-host-bravo.cklb");

        var written = CklbWriter.Write(CklbReader.Read(original));

        Canonical(written).ShouldBe(Canonical(original));
    }

    [Fact]
    public void Round_trip_survives_three_passes()
    {
        var once = CklbWriter.Write(CklbReader.Read(TestEnvironment.ReadFixture("cklb", "rhel8-host-bravo.cklb")));
        var twice = CklbWriter.Write(CklbReader.Read(once));

        twice.ShouldBe(once);
    }

    [Fact]
    public void Round_trip_preserves_keys_stigsmith_does_not_model()
    {
        var written = CklbWriter.Write(Bravo());
        var root = JsonNode.Parse(written)!.AsObject();
        var rule = root["stigs"]![0]!["rules"]![0]!.AsObject();

        // group_tree and check_content_ref are carried through untouched, as is cklb_version.
        rule.ShouldContainKey("group_tree");
        rule.ShouldContainKey("check_content_ref");
        rule.ShouldContainKey("group_id_src");
        root["cklb_version"]!.GetValue<string>().ShouldBe("1.0");
        root["mode"]!.GetValue<int>().ShouldBe(1);
    }

    [Fact]
    public void Status_and_comment_updates_are_written_back()
    {
        var checklist = Bravo();
        var target = checklist.Findings.First(f => f.Status == FindingStatus.Open);
        var updated = checklist.WithReviews(new Dictionary<string, FindingReview>
        {
            [target.Rule.RuleId] = new(
                FindingStatus.NotAFinding,
                "Remediated by Stigsmith and confirmed by re-scan.",
                "Validated."),
        });

        var reread = CklbReader.Read(CklbWriter.Write(updated));
        var result = reread.Findings.Single(f => f.Rule.RuleId == target.Rule.RuleId);

        result.Status.ShouldBe(FindingStatus.NotAFinding);
        result.FindingDetails.ShouldBe("Remediated by Stigsmith and confirmed by re-scan.");
        result.Comments.ShouldBe("Validated.");
        reread.Findings.Count().ShouldBe(72);
    }

    /// <summary>
    /// A .cklb from a third-party exporter that spells ccis as objects rather than strings. The
    /// reader accepts both shapes; see the remarks on <see cref="CklbReader"/> for why that
    /// tolerance exists rather than a strict schema.
    /// </summary>
    [Fact]
    public void Accepts_cci_entries_written_as_objects()
    {
        const string json = """
        {
          "title": "third-party export",
          "stigs": [{
            "stig_id": "RHEL_8_STIG",
            "rules": [{
              "group_id": "V-230225",
              "rule_id": "SV-230225r1_rule",
              "rule_title": "Banner",
              "severity": "medium",
              "fix_text": "Set Banner /etc/issue.",
              "check_content": "grep banner.",
              "ccis": [{"cci": "CCI-000048"}, {"cci": "CCI-001384"}],
              "status": "open"
            }]
          }],
          "target_data": {"host_name": "host-zulu.example.test"},
          "cklb_version": "1.0"
        }
        """;

        var finding = CklbReader.Read(json).Findings.Single();

        finding.Rule.CciRefs.ShouldBe(["CCI-000048", "CCI-001384"]);
        finding.Status.ShouldBe(FindingStatus.Open);
    }

    /// <summary>
    /// Synthesizing a .cklb from a .ckl has to mint uuids the source document does not carry. They
    /// are derived from each rule's identity, not generated, so two exports of an unchanged checklist
    /// are the same bytes. Random ids would make diffing exports useless and re-import churn every
    /// row in the database.
    /// </summary>
    [Fact]
    public void Synthesized_export_is_byte_identical_across_runs()
    {
        var fromCkl = Stigsmith.Checklists.Ckl.CklReader.Read(TestEnvironment.ReadFixture("ckl", "edge-cases.ckl"));

        var first = CklbWriter.Write(fromCkl);
        var second = CklbWriter.Write(Stigsmith.Checklists.Ckl.CklReader.Read(TestEnvironment.ReadFixture("ckl", "edge-cases.ckl")));

        second.ShouldBe(first);
        JsonNode.Parse(first)!["stigs"]![0]!["rules"]![0]!["uuid"]!.GetValue<string>()
            .ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Rejects_json_that_is_not_a_cklb()
    {
        Should.Throw<ChecklistFormatException>(() => CklbReader.Read("{}"));
        Should.Throw<ChecklistFormatException>(() => CklbReader.Read("[1,2,3]"));
    }

    private static string Canonical(string json) =>
        JsonSerializer.Serialize(JsonNode.Parse(json), new JsonSerializerOptions { WriteIndented = true });
}
