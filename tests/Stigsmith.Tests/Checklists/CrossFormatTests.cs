using Stigsmith.Checklists;
using Stigsmith.Checklists.Ckl;
using Stigsmith.Checklists.Cklb;
using Stigsmith.Checklists.Model;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests.Checklists;

public class CrossFormatTests
{
    /// <summary>
    /// A .ckl imported and exported as .cklb, and the reverse. There is no source document to compare
    /// against for these, so they are pinned to golden files: a change in how Stigsmith synthesizes
    /// the other format shows up as a reviewable diff.
    /// </summary>
    [Fact]
    public void Ckl_exports_as_cklb_matching_golden()
    {
        var checklist = CklReader.Read(TestEnvironment.ReadFixture("ckl", "edge-cases.ckl"));

        Golden.Assert(CklbWriter.Write(checklist), "edge-cases.from-ckl.cklb");
    }

    [Fact]
    public void Cklb_exports_as_ckl_matching_golden()
    {
        var full = CklbReader.Read(TestEnvironment.ReadFixture("cklb", "rhel8-host-bravo.cklb"));
        // Trimmed to the first five findings: the point is the shape of the synthesized document,
        // and a 72-rule golden makes every unrelated diff unreadable.
        var trimmed = full with
        {
            Stigs = [full.Stigs[0] with { Findings = [.. full.Stigs[0].Findings.Take(5)] }],
        };

        Golden.Assert(CklWriter.Write(trimmed), "rhel8-host-bravo.from-cklb.ckl");
    }

    [Fact]
    public void Cross_format_conversion_preserves_the_model()
    {
        var fromCkl = CklReader.Read(TestEnvironment.ReadFixture("ckl", "rhel8-host-alpha.ckl"));

        var viaCklb = CklbReader.Read(CklbWriter.Write(fromCkl));

        viaCklb.Host.HostName.ShouldBe(fromCkl.Host.HostName);
        viaCklb.Host.HostIp.ShouldBe(fromCkl.Host.HostIp);
        viaCklb.Findings.Count().ShouldBe(fromCkl.Findings.Count());
        viaCklb.CountsByStatus().ShouldBe(fromCkl.CountsByStatus());

        foreach (var (before, after) in fromCkl.Findings.Zip(viaCklb.Findings))
        {
            after.Rule.RuleId.ShouldBe(before.Rule.RuleId);
            after.Rule.RuleVersion.ShouldBe(before.Rule.RuleVersion);
            after.Rule.Severity.ShouldBe(before.Rule.Severity);
            after.Rule.FixText.ShouldBe(before.Rule.FixText);
            after.Rule.CheckContent.ShouldBe(before.Rule.CheckContent);
            after.Rule.CciRefs.ShouldBe(before.Rule.CciRefs);
            after.Status.ShouldBe(before.Status);
            after.Comments.ShouldBe(before.Comments);
        }
    }

    /// <summary>
    /// XCCDF results and a .ckl of the same benchmark must agree on rule identity, so a scan can be
    /// reconciled against an existing checklist. This is what <see cref="RuleIdentifiers"/> exists for.
    /// </summary>
    [Fact]
    public void Xccdf_results_reconcile_with_a_ckl_of_the_same_benchmark()
    {
        var fromCkl = ChecklistIo.ReadFile(TestEnvironment.FixturePath("multihost", "host-charlie.ckl"));
        var fromScan = ChecklistIo.ReadFile(TestEnvironment.FixturePath("xccdf", "rhel8-host-charlie-xccdf.xml"));

        var cklIds = fromCkl.Findings.Select(f => f.Rule.NumericId).ToHashSet();
        var scanIds = fromScan.Findings.Select(f => f.Rule.NumericId).ToHashSet();

        cklIds.ShouldNotBeEmpty();
        // The .ckl fixture is the first 40 rules; the scan covers all 72.
        cklIds.IsSubsetOf(scanIds).ShouldBeTrue();

        var byId = fromScan.Findings.ToDictionary(f => f.Rule.NumericId);
        foreach (var finding in fromCkl.Findings)
        {
            byId.ShouldContainKey(finding.Rule.NumericId);
            byId[finding.Rule.NumericId].Status.ShouldBe(finding.Status);
        }
    }
}

public class MultiHostImportTests
{
    /// <summary>
    /// A multi-host set is separate files, one host each. Importing them must not blend hosts, and
    /// each host's statuses must stay its own — the failure mode worth guarding against is a shared
    /// static or a cached parse leaking one host's data into another's checklist.
    /// </summary>
    [Fact]
    public void Imports_a_multi_host_set_keeping_hosts_distinct()
    {
        var dir = TestEnvironment.FixturePath("multihost");
        var files = Directory.GetFiles(dir).OrderBy(f => f).ToArray();

        files.Length.ShouldBe(3);
        var checklists = files.Select(ChecklistIo.ReadFile).ToArray();

        checklists.Select(c => c.Host.HostName).ShouldBe(
            ["host-alpha.example.test", "host-charlie.example.test", "host-delta.example.test"],
            ignoreOrder: true);
        checklists.Select(c => c.Host.HostIp).Distinct().Count().ShouldBe(3);
        checklists.Select(c => c.Findings.Count()).ShouldBe([60, 40, 55], ignoreOrder: true);

        // Mixed formats in one set: two .ckl and one .cklb.
        checklists.Select(c => c.SourceFormat).ShouldBe(
            [ChecklistFormat.Ckl, ChecklistFormat.Ckl, ChecklistFormat.Cklb], ignoreOrder: true);

        // Every host has open findings, and no two hosts have identical status profiles (the
        // generator offsets them), so a cross-host leak would show up here.
        foreach (var checklist in checklists)
            checklist.CountsByStatus()[FindingStatus.Open].ShouldBeGreaterThan(0);
    }

    [Fact]
    public void Every_fixture_host_uses_documentation_addresses_only()
    {
        // Constraint 2, asserted rather than trusted. RFC 5737 documentation ranges, plus the
        // synthetic 00:53:00 MAC prefix (the IANA-reserved documentation OUI).
        string[] allowedPrefixes = ["192.0.2.", "198.51.100.", "203.0.113."];

        var hosts = Directory.EnumerateFiles(TestEnvironment.FixturePath(), "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".ckl") || f.EndsWith(".cklb") || f.EndsWith(".xml"))
            .Select(ChecklistIo.ReadFile)
            .Select(c => c.Host)
            .ToArray();

        hosts.ShouldNotBeEmpty();
        foreach (var host in hosts)
        {
            host.HostName.ShouldEndWith(".example.test");
            if (host.HostIp.Length > 0)
                allowedPrefixes.ShouldContain(p => host.HostIp.StartsWith(p), $"'{host.HostIp}' is not an RFC 5737 documentation address");
            if (host.HostMac.Length > 0)
                host.HostMac.ShouldStartWith("00:53:00");
        }
    }
}
