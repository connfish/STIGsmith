using System.Text.Json.Serialization;

namespace Stigsmith.Validation;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ValidationOutcome
{
    Pending = 0,

    /// <summary>Linted, applied, re-scanned to pass, and proven idempotent.</summary>
    Passed = 1,

    /// <summary>Failed a stage and the repair attempt is still to come.</summary>
    Failed = 2,

    /// <summary>Failed, was repaired once, and failed again. A human decides from here.</summary>
    NeedsHumanReview = 3,

    /// <summary>Not attempted — no container runtime, or the rule was excluded.</summary>
    Skipped = 4,
}

/// <summary>Stages of the validation loop, in the order they run.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ValidationStage
{
    Lint = 0,
    SyntaxCheck = 1,
    Apply = 2,
    Rescan = 3,
    Idempotency = 4,

    /// <summary>The verifier run before anything is applied, so the re-scan has a baseline to be compared with.</summary>
    Baseline = 5,

    /// <summary>The <c>--check</c> dry run a high-risk rule gets before it is applied.</summary>
    CheckMode = 6,
}
