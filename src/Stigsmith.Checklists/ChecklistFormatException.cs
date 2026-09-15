namespace Stigsmith.Checklists;

/// <summary>
/// The input is not a checklist Stigsmith can read, or is malformed in a way that cannot be
/// recovered from. Thrown by every reader, so callers handle one exception type per import.
/// </summary>
public sealed class ChecklistFormatException(string message) : Exception(message);
