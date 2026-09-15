using System.Reflection;
using Stigsmith.Api.Persistence;
using Stigsmith.Checklists;
using Stigsmith.Checklists.Model;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests.Checklists;

public class ChecklistMapperTests
{
    private static (Checklist Parsed, string Source) Alpha()
    {
        var source = TestEnvironment.ReadFixture("ckl", "rhel8-host-alpha.ckl");
        return (ChecklistIo.Read(source), source);
    }

    [Fact]
    public void Maps_host_metadata_onto_the_checklist_row()
    {
        var (parsed, source) = Alpha();

        var record = ChecklistMapper.ToRecord(parsed, "rhel8-host-alpha.ckl", source);

        record.HostName.ShouldBe("host-alpha.example.test");
        record.HostIp.ShouldBe("192.0.2.10");
        record.StigId.ShouldBe("RHEL_8_STIG");
        record.SourceFormat.ShouldBe(ChecklistFormat.Ckl);
        record.Findings.Count.ShouldBe(72);
        record.OriginalDocument.ShouldBe(source);
    }

    /// <summary>
    /// Constraint 3 at the schema level: a finding row carries no host field. If one were ever added,
    /// a query that assembles generation input would be one careless projection away from a prompt
    /// leak, so the absence is asserted rather than trusted.
    /// </summary>
    [Fact]
    public void Finding_rows_carry_no_host_identifying_columns()
    {
        string[] forbidden = ["host", "ipaddress", "ip", "fqdn", "mac", "hostname", "targetkey", "asset"];

        var offenders = typeof(FindingRecord).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => forbidden.Any(f => p.Name.Replace("_", "").Contains(f, StringComparison.OrdinalIgnoreCase)))
            .Select(p => p.Name)
            .ToArray();

        offenders.ShouldBeEmpty(
            $"FindingRecord gained host-identifying columns: {string.Join(", ", offenders)}. " +
            "Host metadata belongs on ChecklistRecord only — see constraint 3 in the README.");
    }

    /// <summary>
    /// The same guarantee one level up, on the type prompt assembly actually receives.
    /// </summary>
    [Fact]
    public void Rule_content_carries_no_host_identifying_properties()
    {
        string[] forbidden = ["host", "ipaddress", "fqdn", "mac", "targetkey", "asset", "target"];

        var offenders = typeof(RuleContent).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => forbidden.Any(f => p.Name.Contains(f, StringComparison.OrdinalIgnoreCase)))
            .Select(p => p.Name)
            .ToArray();

        offenders.ShouldBeEmpty($"RuleContent gained host-identifying properties: {string.Join(", ", offenders)}.");
    }

    /// <summary>
    /// Export re-parses the stored source document and applies the database's reviews to it. This is
    /// the path an operator's file actually takes through the tool, so it gets the same lossless
    /// guarantee the parser round-trip has.
    /// </summary>
    [Fact]
    public void Export_from_a_record_is_lossless_and_carries_review_changes()
    {
        var (parsed, source) = Alpha();
        var record = ChecklistMapper.ToRecord(parsed, "rhel8-host-alpha.ckl", source);

        var target = record.Findings.First(f => f.Status == FindingStatus.Open);
        target.Status = FindingStatus.NotAFinding;
        target.FindingDetails = "Remediated by Stigsmith; re-scan confirms pass.";
        target.Comments = "Evidence: lint, apply, re-scan, idempotency.";

        var exported = ChecklistIo.Write(
            ChecklistIo.Read(record.OriginalDocument).WithReviews(ChecklistMapper.ToReviews(record)),
            ChecklistFormat.Ckl);

        var reread = ChecklistIo.Read(exported);
        var updated = reread.Findings.Single(f => f.Rule.RuleId == target.RuleId);

        updated.Status.ShouldBe(FindingStatus.NotAFinding);
        updated.FindingDetails.ShouldBe("Remediated by Stigsmith; re-scan confirms pass.");
        updated.Comments.ShouldBe("Evidence: lint, apply, re-scan, idempotency.");

        // Everything else is untouched, including rule content the database does not store in full.
        reread.Findings.Count().ShouldBe(72);
        reread.Host.ShouldBe(parsed.Host);
        updated.Rule.FixText.ShouldBe(parsed.Findings.Single(f => f.Rule.RuleId == target.RuleId).Rule.FixText);
    }

    [Fact]
    public void Reviews_are_keyed_case_insensitively_on_rule_id()
    {
        var (parsed, source) = Alpha();
        var record = ChecklistMapper.ToRecord(parsed, "x.ckl", source);

        var reviews = ChecklistMapper.ToReviews(record);

        var id = record.Findings[0].RuleId;
        reviews.ShouldContainKey(id.ToUpperInvariant());
        reviews.ShouldContainKey(id.ToLowerInvariant());
    }
}
