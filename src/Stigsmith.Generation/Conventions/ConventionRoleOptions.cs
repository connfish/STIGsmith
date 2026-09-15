namespace Stigsmith.Generation.Conventions;

/// <summary>
/// Where the operator's Ansible role lives. A path, supplied at runtime.
/// </summary>
/// <remarks>
/// Constraint 5: Stigsmith never vendors someone else's role. The path is configuration, the role stays
/// wherever the operator keeps it, and nothing about it is committed here. <c>examples/example-role</c>
/// is a synthetic role that exists only so the indexer and the retrieval tests have something to read.
/// </remarks>
public sealed class ConventionRoleOptions
{
    public const string SectionName = "Stigsmith:Generation:ConventionRole";

    /// <summary>Absolute or relative path to the role directory. Null disables convention retrieval.</summary>
    public string? Path { get; set; }

    /// <summary>How many existing tasks to include as few-shot examples. Three is enough to establish a pattern without crowding out the rule.</summary>
    public int ExampleCount { get; set; } = 3;

    /// <summary>
    /// Subdirectories of the role that hold tasks. Roles vary; <c>tasks</c> and <c>handlers</c> cover
    /// the common layout, and a role that puts tasks elsewhere adds it here rather than needing code.
    /// Configuration binding appends to this default rather than replacing it, and the indexer ignores
    /// duplicates and directories that do not exist, so listing a default again is harmless.
    /// </summary>
    public string[] TaskDirectories { get; set; } = ["tasks", "handlers"];

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Path);
}
