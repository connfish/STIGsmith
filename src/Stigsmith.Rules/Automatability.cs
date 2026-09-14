namespace Stigsmith.Rules;

/// <summary>
/// Whether a rule's prescribed fix is something Ansible can carry out. The three buckets are the
/// ones the milestone spec names, and the distinction that matters operationally is between
/// <see cref="Manual"/> (no automation is possible or appropriate) and <see cref="NeedsReview"/>
/// (automation might be possible but a human has to decide).
/// </summary>
public enum Automatability
{
    Unclassified = 0,

    /// <summary>A configuration change Ansible can make and verify.</summary>
    Automatable = 1,

    /// <summary>A policy, documentation, or physical check. "The ISSO will verify..."</summary>
    Manual = 2,

    /// <summary>Ambiguous, or the correct fix depends on site context this tool does not have.</summary>
    NeedsReview = 3,
}
