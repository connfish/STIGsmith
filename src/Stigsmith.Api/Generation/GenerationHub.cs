using Microsoft.AspNetCore.SignalR;

namespace Stigsmith.Api.Generation;

/// <summary>
/// Streams generation output and validation progress to connected clients.
/// </summary>
/// <remarks>
/// Clients subscribe per checklist rather than per generation: an operator triaging a checklist wants to watch
/// whatever is currently being generated for it, and a subscription per rule would mean hundreds of group joins
/// to follow a batch.
/// </remarks>
public sealed class GenerationHub : Hub
{
    public static string GroupFor(Guid checklistId) => $"checklist:{checklistId}";

    public Task Subscribe(Guid checklistId) => Groups.AddToGroupAsync(Context.ConnectionId, GroupFor(checklistId));

    public Task Unsubscribe(Guid checklistId) => Groups.RemoveFromGroupAsync(Context.ConnectionId, GroupFor(checklistId));
}

/// <summary>Events pushed to subscribers. Named so a client can switch on them without parsing free text.</summary>
public static class GenerationEvents
{
    public const string Started = "generationStarted";
    public const string Chunk = "generationChunk";
    public const string Completed = "generationCompleted";
    public const string Failed = "generationFailed";
}

public sealed record GenerationStarted(Guid GenerationId, Guid FindingId, string RuleVersion, string Provider, string Model);

public sealed record GenerationChunkEvent(Guid GenerationId, string Text);

public sealed record GenerationCompleted(
    Guid GenerationId,
    Guid FindingId,
    string RuleVersion,
    string Outcome,
    string Message,
    int TaskCount,
    int PromptTokens,
    int CompletionTokens);

public sealed record GenerationFailed(Guid GenerationId, Guid FindingId, string RuleVersion, string Error);
