using System.Text.Json;
using System.Text.Json.Serialization;
using Stigsmith.Rules;

namespace Stigsmith.Tests.Support;

/// <summary>
/// The answer key in <c>fixtures/expectations/rhel8-classification.json</c>, authored alongside the
/// rule catalog in <c>tools/rule_catalog.py</c> so the two cannot drift.
/// </summary>
public sealed record ClassificationExpectations(
    [property: JsonPropertyName("highRiskDomains")] string[] HighRiskDomains,
    [property: JsonPropertyName("rules")] ExpectedRule[] Rules)
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    public static ClassificationExpectations Load() =>
        JsonSerializer.Deserialize<ClassificationExpectations>(
            TestEnvironment.ReadFixture("expectations", "rhel8-classification.json"), Options)
        ?? throw new InvalidOperationException("The classification expectations fixture is empty.");

    public IReadOnlyDictionary<string, ExpectedRule> ByRuleId =>
        Rules.ToDictionary(r => r.RuleId, StringComparer.OrdinalIgnoreCase);
}

public sealed record ExpectedRule(
    [property: JsonPropertyName("vulnId")] string VulnId,
    [property: JsonPropertyName("ruleId")] string RuleId,
    [property: JsonPropertyName("ruleVersion")] string RuleVersion,
    [property: JsonPropertyName("expectedAutomatability")] string ExpectedAutomatability,
    [property: JsonPropertyName("domains")] string[] Domains,
    [property: JsonPropertyName("expectedHighRisk")] bool ExpectedHighRisk)
{
    public Automatability Expected => ExpectedAutomatability switch
    {
        "automatable" => Automatability.Automatable,
        "manual" => Automatability.Manual,
        "needs-review" => Automatability.NeedsReview,
        _ => throw new InvalidOperationException($"Unknown expected automatability '{ExpectedAutomatability}'."),
    };
}
