using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Ipa.Contracts.Security;

namespace Ipa.Collectors.Entra.Graph;

/// <summary>An error returned by Microsoft Graph, normalised for the diagnostic log.</summary>
public sealed class GraphRequestException : Exception
{
    public GraphRequestException(HttpStatusCode statusCode, string code, string message)
        : base(message)
    {
        StatusCode = statusCode;
        Code = code;
    }

    /// <summary>HTTP status the service returned.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>Service error code, for example <c>Authorization_RequestDenied</c>.</summary>
    public string Code { get; }

    /// <summary>True when the failure is a consent, role or licence problem rather than a fault.</summary>
    public bool IsAuthorisationFailure =>
        StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized;

    /// <summary>True when retrying the request could succeed.</summary>
    public bool IsTransient =>
        StatusCode is HttpStatusCode.TooManyRequests
            or HttpStatusCode.RequestTimeout
            or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;
}

/// <summary>
/// A minimal, strictly read-only Microsoft Graph client.
/// </summary>
/// <remarks>
/// The client exposes only GET requests: there is no method that can issue a POST, PATCH, PUT or
/// DELETE, so "no tenant write requests" is a property of the type rather than a convention. It
/// handles paging, honours the service's throttling guidance, and never writes a token or a
/// response body containing one into a log.
/// </remarks>
public sealed class GraphReadClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly Func<CancellationToken, Task<string>> _tokenProvider;
    private readonly string _endpoint;
    private readonly bool _ownsHttpClient;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public GraphReadClient(
        Func<CancellationToken, Task<string>> tokenProvider,
        string endpoint = "https://graph.microsoft.com",
        HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(tokenProvider);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpoint);

        _tokenProvider = tokenProvider;
        _endpoint = endpoint.TrimEnd('/');
        _ownsHttpClient = httpClient is null;
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
    }

    /// <summary>Graph API version used for every request.</summary>
    public string ApiVersion { get; init; } = "v1.0";

    /// <summary>Maximum retries for a throttled or transient failure.</summary>
    public int MaxRetries { get; init; } = 4;

    /// <summary>Diagnostics raised while requesting, for the collection log.</summary>
    public event Action<string>? Diagnostic;

    /// <summary>Issues one GET request and returns the parsed document.</summary>
    public async Task<JsonElement> GetAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var uri = path.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? path
            : $"{_endpoint}/{ApiVersion}/{path.TrimStart('/')}";

        var delay = TimeSpan.FromSeconds(1);

        for (var attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer",
                await _tokenProvider(cancellationToken).ConfigureAwait(false));

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await _http
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
                return document.RootElement.Clone();
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var (code, message) = ParseError(body);
            var exception = new GraphRequestException(response.StatusCode, code, Redaction.Scrub(message));

            if (!exception.IsTransient || attempt >= MaxRetries)
            {
                throw exception;
            }

            var wait = response.Headers.RetryAfter?.Delta
                       ?? (response.Headers.RetryAfter?.Date is { } date
                           ? (TimeSpan?)(date - DateTimeOffset.UtcNow)
                           : null)
                       ?? delay;

            wait = TimeSpan.FromMilliseconds(Math.Clamp(wait.TotalMilliseconds, 500, 60_000));
            Diagnostic?.Invoke($"Retrying after {response.StatusCode} in {wait.TotalSeconds:F0}s (attempt {attempt}).");

            await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
            delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 30_000));
        }
    }

    /// <summary>
    /// Enumerates a collection, following the service's paging link until the collection is
    /// exhausted or the cap is reached.
    /// </summary>
    public async IAsyncEnumerable<JsonElement> EnumerateAsync(
        string path,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken,
        int maxItems = 250_000)
    {
        var next = path;
        var returned = 0;

        while (next is not null)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var document = await GetAsync(next, cancellationToken).ConfigureAwait(false);

            if (document.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in value.EnumerateArray())
                {
                    yield return item.Clone();

                    if (++returned >= maxItems)
                    {
                        Diagnostic?.Invoke($"Stopped enumerating after the {maxItems} item cap.");
                        yield break;
                    }
                }
            }
            else if (document.ValueKind == JsonValueKind.Object)
            {
                yield return document;
                yield break;
            }

            next = document.TryGetProperty("@odata.nextLink", out var link) && link.ValueKind == JsonValueKind.String
                ? link.GetString()
                : null;
        }
    }

    /// <summary>
    /// Enumerates a collection and returns an empty list when the request is refused for consent,
    /// role or licence reasons. The caller records the reason so the rule reports as not collected.
    /// </summary>
    public async Task<(IReadOnlyList<JsonElement> Items, GraphRequestException? Failure)> TryEnumerateAsync(
        string path,
        CancellationToken cancellationToken,
        int maxItems = 250_000)
    {
        var items = new List<JsonElement>();

        try
        {
            await foreach (var item in EnumerateAsync(path, cancellationToken, maxItems).ConfigureAwait(false))
            {
                items.Add(item);
            }

            return (items, null);
        }
        catch (GraphRequestException ex)
        {
            return (items, ex);
        }
    }

    /// <summary>Issues one GET and returns null when the request is refused or the item is absent.</summary>
    public async Task<(JsonElement? Item, GraphRequestException? Failure)> TryGetAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            return (await GetAsync(path, cancellationToken).ConfigureAwait(false), null);
        }
        catch (GraphRequestException ex)
        {
            return (null, ex);
        }
    }

    private static (string Code, string Message) ParseError(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return ("Unknown", "The service returned an error with no detail.");
        }

        try
        {
            using var document = JsonDocument.Parse(body);

            if (document.RootElement.TryGetProperty("error", out var error))
            {
                var code = error.TryGetProperty("code", out var codeElement) ? codeElement.GetString() : null;
                var message = error.TryGetProperty("message", out var messageElement) ? messageElement.GetString() : null;

                return (code ?? "Unknown", message ?? "The service returned an error with no detail.");
            }
        }
        catch (JsonException)
        {
            // Fall through to the raw body, which is scrubbed by the caller.
        }

        return ("Unknown", body.Length > 500 ? body[..500] : body);
    }

    /// <summary>Deserialises a JSON element into a typed value using web naming conventions.</summary>
    public static T? Deserialise<T>(JsonElement element) => element.Deserialize<T>(SerializerOptions);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
