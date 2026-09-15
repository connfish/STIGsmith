using System.Net;
using System.Text;

namespace Stigsmith.Tests.Support;

/// <summary>
/// Serves canned HTTP responses and records what was sent.
/// </summary>
/// <remarks>
/// Used to test the real <c>OllamaRemediationProvider</c> rather than a mock of it. What matters about that
/// class is how it builds the request body and how it parses newline-delimited JSON off a stream, and both are
/// only actually tested by driving the real code with real bytes.
/// </remarks>
public sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, string, HttpResponseMessage> _respond;

    public StubHttpMessageHandler(Func<HttpRequestMessage, string, HttpResponseMessage> respond) => _respond = respond;

    /// <summary>Streams the given newline-delimited JSON lines back from POST /api/chat.</summary>
    public static StubHttpMessageHandler Streaming(params string[] ndjsonLines) => new((request, _) =>
        new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Join('\n', ndjsonLines) + "\n", Encoding.UTF8, "application/x-ndjson"),
            RequestMessage = request,
        });

    public static StubHttpMessageHandler Status(HttpStatusCode code, string body = "") => new((request, _) =>
        new HttpResponseMessage(code)
        {
            Content = new StringContent(body),
            RequestMessage = request,
        });

    public List<(string Method, string Path, string Body)> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request.Method.Method, request.RequestUri?.AbsolutePath ?? "", body));
        return _respond(request, body);
    }

    public string LastBody => Requests.Count == 0 ? "" : Requests[^1].Body;
}
