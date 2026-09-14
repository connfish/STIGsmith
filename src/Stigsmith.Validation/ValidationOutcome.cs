namespace Stigsmith.Validation;

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
public enum ValidationStage
{
    Lint = 0,
    SyntaxCheck = 1,
    Apply = 2,
    Rescan = 3,
    Idempotency = 4,
}
