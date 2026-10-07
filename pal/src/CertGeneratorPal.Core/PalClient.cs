using System.Reflection;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace CertGeneratorPal.Core;

/// <summary>Signs requests with the device key (DER/RFC 3279 ECDSA-SHA256).</summary>
public interface IDeviceSigner
{
    string DeviceId { get; }

    byte[] Sign(byte[] data);

    /// <summary>The same key, raw r‖s (IEEE P1363): the relay envelope's outer signature, which the Worker checks.</summary>
    byte[] SignP1363(byte[] data);
}

/// <summary>The Pal side of the device API. LAN only: every connection is checked to land on a private address.</summary>
public sealed class PalClient : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RelayWait = TimeSpan.FromSeconds(90);
    private readonly HttpClient _http;
    private readonly Uri _server;
    private readonly RelayInfo? _relay;
    private readonly PalRoute _route;
    private HttpClient? _relayHttp;

    /// <param name="server">The server address from the pairing code.</param>
    /// <param name="rootSha256">The pinned root: lets a server whose TLS certificate comes from this CA be trusted before the root is installed.</param>
    /// <param name="relay">The server's remote relay, when this PC may use it.</param>
    /// <param name="route">Auto: the LAN, then the relay when the LAN can't be reached.</param>
    public PalClient(Uri server, string rootSha256, RelayInfo? relay = null, PalRoute route = PalRoute.Auto)
    {
        ArgumentNullException.ThrowIfNull(server);
        _server = server;
        _relay = relay is { IsUsable: true } ? relay : null;
        _route = route;
        var handler = new SocketsHttpHandler
        {
            // With a relay to fall back on, don't wait long for a LAN server that isn't there.
            ConnectTimeout = _relay is not null && route == PalRoute.Auto ? TimeSpan.FromSeconds(4) : Timeout,
            ConnectCallback = ConnectLanOnlyAsync,
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, cert, chain, errors) => TlsTrusted(cert, chain, errors, rootSha256),
            },
        };
        _http = new HttpClient(handler) { Timeout = Timeout };
        // The server records this, to show PCs running a Pal from another release.
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("CertGeneratorPal", AppVersion));
    }

    /// <summary>This Pal's version, the same as the server release it shipped in (e.g. 2.8.0-dev.1).</summary>
    public static string AppVersion { get; } = (typeof(PalClient).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0").Split('+')[0];

    /// <summary>How the last signed request reached the server.</summary>
    public PalRoute LastRoute { get; private set; } = PalRoute.Lan;

    public bool HasRelay => _relay is not null;

    public void Dispose()
    {
        _http.Dispose();
        _relayHttp?.Dispose();
    }

    /// <summary>Resolve, then connect only to a private address (so a DNS change can't point the PC at the internet).</summary>
    private static async ValueTask<Stream> ConnectLanOnlyAsync(SocketsHttpConnectionContext context, CancellationToken token)
    {
        IPAddress[] addresses = IPAddress.TryParse(context.DnsEndPoint.Host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, token).ConfigureAwait(false);
        IPAddress[] lan = addresses.Where(LanAddress.IsPrivate).ToArray();
        if (lan.Length == 0)
        {
            throw new PalException($"{context.DnsEndPoint.Host} isn't a LAN address. Cert Generator Pal only connects to servers on your local network.");
        }
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(lan, context.DnsEndPoint.Port, token).ConfigureAwait(false);
            if (socket.RemoteEndPoint is not IPEndPoint remote || !LanAddress.IsPrivate(remote.Address))
            {
                throw new PalException("The server connection didn't land on a LAN address.");
            }
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>Normal TLS validation, or a chain the server sent that ends in the pinned root.</summary>
    private static bool TlsTrusted(X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors, string rootSha256)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }
        if (cert is null || chain is null || errors != SslPolicyErrors.RemoteCertificateChainErrors)
        {
            return false;  // a name mismatch is never excused
        }
        if (chain.ChainStatus.Any(s => s.Status is not (X509ChainStatusFlags.UntrustedRoot or X509ChainStatusFlags.PartialChain or X509ChainStatusFlags.NoError)))
        {
            return false;
        }
        var last = chain.ChainElements[^1].Certificate;
        return string.Equals(Protocol.Sha256Hex(last.RawData), rootSha256, StringComparison.OrdinalIgnoreCase);
    }

    private Uri ApiUri(string relative) => new(_server, _server.AbsolutePath.TrimEnd('/') + Protocol.ApiPrefix + relative);

    // ── Pairing ─────────────────────────────────────────────────────

    public sealed record EnrollResult(DeviceInfo Device, byte[] RawBody);

    public async Task<EnrollResult> EnrollAsync(PairingCode code, byte[] deviceSpki, string hostname, string fqdn, string os, string? keyStorage = null, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(code);
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(new EnrollBody
        {
            CodeId = code.CodeId,
            DeviceKey = Convert.ToBase64String(deviceSpki),
            Hostname = hostname,
            Fqdn = fqdn,
            Os = os,
            Ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Nonce = Protocol.NewNonce(),
            KeyStorage = keyStorage,
        }, Json.Options);
        using var request = new HttpRequestMessage(HttpMethod.Post, ApiUri("enroll")) { Content = JsonContent(body) };
        request.Headers.Add("X-Pal-Proof", Protocol.EnrollProof(code.Key, body));
        using var response = await SendAsync(request, token).ConfigureAwait(false);
        byte[] reply = await response.Content.ReadAsByteArrayAsync(token).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw Failure(response.StatusCode, reply);
        }
        string? mac = response.Headers.TryGetValues("X-Pal-Mac", out var values) ? values.FirstOrDefault() : null;
        if (!Protocol.VerifyEnrolledMac(code.Key, reply, mac))
        {
            throw new PalException("The server's answer didn't prove it made this pairing code. Nothing was installed.");
        }
        var device = JsonSerializer.Deserialize<DeviceInfo>(reply, Json.Options) ?? throw new PalException("The server sent an empty answer.");
        if (!ChainCheck.RootMatches(device.Chain, code.RootSha256))
        {
            throw new PalException("The CA the server sent isn't the one in the pairing code. Nothing was installed.");
        }
        return new EnrollResult(device, reply);
    }

    // ── Signed requests ─────────────────────────────────────────────

    public async Task<DeviceInfo> GetDeviceAsync(IDeviceSigner signer, CancellationToken token = default)
    {
        var info = await SignedAsync<DeviceInfo>(signer, HttpMethod.Get, "device", null, token).ConfigureAwait(false);
        info.ArrivedVia = LastRoute;
        return info;
    }

    public async Task<List<SelfHostedCrl>> GetSelfHostedCrlsAsync(IDeviceSigner signer, CancellationToken token = default) =>
        (await SignedAsync<SelfHostedCrlsReply>(signer, HttpMethod.Get, "crls", null, token).ConfigureAwait(false)).Crls;

    public Task<RequestView> GetRequestAsync(IDeviceSigner signer, int requestId, CancellationToken token = default) =>
        SignedAsync<RequestView>(signer, HttpMethod.Get, "requests/" + requestId.ToString(CultureInfo.InvariantCulture), null, token);

    public Task<RequestView> CreateRequestAsync(IDeviceSigner signer, string useCase, Dictionary<string, object> names, string csrPem,
        int? lifetimeDays, int? renewOf, string? crlDp = null, string? keyStorage = null, string? windowsUser = null,
        string? note = null, CancellationToken token = default) =>
        SignedAsync<RequestView>(signer, HttpMethod.Post, "requests", new CreateRequestBody
        {
            UseCase = useCase,
            Names = names,
            Csr = csrPem,
            LifetimeDays = lifetimeDays,
            RenewOf = renewOf,
            CrlDp = crlDp,
            KeyStorage = keyStorage,
            WindowsUser = windowsUser,
            Note = string.IsNullOrWhiteSpace(note) ? null : note,
        }, token);

    public async Task<Dictionary<string, string>> StatusAsync(IDeviceSigner signer, IReadOnlyCollection<string> serials,
        string? deviceKeyStorage = null, Dictionary<string, string>? keys = null, string? windowsUser = null,
        Dictionary<string, List<string>>? binds = null, CancellationToken token = default)
    {
        // Sent even when empty: it is also how the server learns this PC no longer holds a certificate.
        var reply = await SignedAsync<StatusReply>(signer, HttpMethod.Post, "status", new StatusBody
            {
                Serials = [.. serials], DeviceKeyStorage = deviceKeyStorage, Keys = keys is { Count: > 0 } ? keys : null, WindowsUser = windowsUser, Binds = binds,
            }, token)
            .ConfigureAwait(false);
        return reply.Status;
    }

    /// <summary>Ask the server whether this certificate may be bound to these roles: each comes back approved or pending.</summary>
    public async Task<List<BindView>> CreateBindsAsync(IDeviceSigner signer, string serial, IReadOnlyCollection<BindAsk> binds,
        string? windowsUser = null, string? note = null, CancellationToken token = default) =>
        (await SignedAsync<BindsReply>(signer, HttpMethod.Post, "binds", new CreateBindsBody
        {
            Serial = serial, Binds = [.. binds], WindowsUser = windowsUser, Note = string.IsNullOrWhiteSpace(note) ? null : note,
        }, token).ConfigureAwait(false)).Binds;

    public Task<BindView> GetBindAsync(IDeviceSigner signer, int bindId, CancellationToken token = default) =>
        SignedAsync<BindView>(signer, HttpMethod.Get, "binds/" + bindId.ToString(CultureInfo.InvariantCulture), null, token);

    /// <summary>Revoke certificates this PC removed. The server touches only this PC's own; returns the serials it revoked.</summary>
    public async Task<List<string>> RevokeAsync(IDeviceSigner signer, IReadOnlyCollection<string> serials, CancellationToken token = default) =>
        (await SignedAsync<RevokeReply>(signer, HttpMethod.Post, "revoke", new StatusBody { Serials = [.. serials] }, token).ConfigureAwait(false)).Revoked;

    /// <summary>Have the server sign and publish the CA's CRL again now: the one it serves, and its Cloudflare Worker's.</summary>
    public Task<PublishReply> PublishCrlAsync(IDeviceSigner signer, CancellationToken token = default) =>
        SignedAsync<PublishReply>(signer, HttpMethod.Post, "crl/publish", new Dictionary<string, string>(), token);

    private async Task<T> SignedAsync<T>(IDeviceSigner signer, HttpMethod method, string relative, object? payload, CancellationToken token)
    {
        byte[] body = payload is null ? [] : JsonSerializer.SerializeToUtf8Bytes(payload, payload.GetType(), Json.Options);
        string path = Protocol.ApiPrefix + relative;  // signed without any reverse-proxy prefix in the server address
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        string nonce = Protocol.NewNonce();
        byte[] signature = signer.Sign(Protocol.RequestSigningString(method.Method, path, timestamp, nonce, body));

        var headers = new Dictionary<string, string>
        {
            ["X-Pal-Device"] = signer.DeviceId,
            ["X-Pal-Time"] = timestamp,
            ["X-Pal-Nonce"] = nonce,
            ["X-Pal-Signature"] = Protocol.B64Url(signature),
        };
        (HttpStatusCode status, byte[] reply) = await RouteAsync(signer, method, relative, path, headers, payload is null ? null : body, token)
            .ConfigureAwait(false);
        if ((int)status is < 200 or > 299)
        {
            throw Failure(status, reply);
        }
        return JsonSerializer.Deserialize<T>(reply, Json.Options) ?? throw new PalException("The server sent an empty answer.");
    }

    /// <summary>The LAN, or the relay: when forced, or when the LAN can't be reached at all. A refusal from the
    /// server (an HTTP status) is never retried through the relay.</summary>
    private async Task<(HttpStatusCode, byte[])> RouteAsync(IDeviceSigner signer, HttpMethod method, string relative, string path,
        Dictionary<string, string> headers, byte[]? body, CancellationToken token)
    {
        if (_route == PalRoute.Relay)
        {
            return await ViaRelayAsync(signer, method, path, headers, body ?? [], token).ConfigureAwait(false);
        }
        try
        {
            using var request = new HttpRequestMessage(method, ApiUri(relative));
            if (body is not null)
            {
                request.Content = JsonContent(body);
            }
            foreach (var (name, value) in headers)
            {
                request.Headers.Add(name, value);
            }
            using var response = await SendAsync(request, token).ConfigureAwait(false);
            LastRoute = PalRoute.Lan;
            return (response.StatusCode, await response.Content.ReadAsByteArrayAsync(token).ConfigureAwait(false));
        }
        catch (PalException lan) when (_route == PalRoute.Auto && _relay is not null && !token.IsCancellationRequested)
        {
            Trace?.Invoke($"LAN unreachable ({lan.Message}); trying the relay");
            return await ViaRelayAsync(signer, method, path, headers, body ?? [], token).ConfigureAwait(false);
        }
    }

    // ── Remote relay (docs/cert-generator-pal.md §8) ────────────────

    /// <summary>Seal the signed request to the server's relay key, hand it to the relay Worker and wait for the
    /// server's sealed reply. Cloudflare sees neither: only this PC and the server can open them.</summary>
    private async Task<(HttpStatusCode, byte[])> ViaRelayAsync(IDeviceSigner signer, HttpMethod method, string path,
        Dictionary<string, string> headers, byte[] body, CancellationToken token)
    {
        var relay = _relay ?? throw new PalException("No remote relay. Connect on your LAN once after your admin allows remote access.");
        var innerHeaders = new Dictionary<string, string>(headers) { ["User-Agent"] = "CertGeneratorPal/" + AppVersion };
        byte[] inner = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["method"] = method.Method, ["path"] = path, ["headers"] = innerHeaders, ["body"] = Protocol.B64Url(body),
        });
        var sealedRequest = Relay.SealRequest(signer.DeviceId, Protocol.B64UrlDecode(relay.PublicKey), inner,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Protocol.NewNonce(), signer.SignP1363);
        var http = _relayHttp ??= NewRelayHttp();
        string baseUrl = relay.Url.TrimEnd('/');
        var watch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using var send = new HttpRequestMessage(HttpMethod.Post, baseUrl + "/v1/send") { Content = JsonContent(sealedRequest.Json) };
            using var first = await http.SendAsync(send, token).ConfigureAwait(false);
            var (status, reply) = (first.StatusCode, await first.Content.ReadAsByteArrayAsync(token).ConfigureAwait(false));
            while (status is HttpStatusCode.Accepted or HttpStatusCode.NoContent)
            {
                if (watch.Elapsed > RelayWait)
                {
                    throw new PalException("Your server didn't answer through the relay. Is it running, with the remote connection set up?");
                }
                using var poll = await http.GetAsync($"{baseUrl}/v1/reply?d={signer.DeviceId}&n={sealedRequest.Nonce}", token).ConfigureAwait(false);
                (status, reply) = (poll.StatusCode, await poll.Content.ReadAsByteArrayAsync(token).ConfigureAwait(false));
            }
            if (status != HttpStatusCode.OK)
            {
                throw RelayRefusal(status);
            }
            using var opened = JsonDocument.Parse(Relay.OpenReply(sealedRequest, signer.DeviceId, reply));
            var root = opened.RootElement;
            LastRoute = PalRoute.Relay;
            Trace?.Invoke($"{method} {path} via relay → {root.GetProperty("status").GetInt32()} in {watch.ElapsedMilliseconds} ms");
            return ((HttpStatusCode)root.GetProperty("status").GetInt32(), Protocol.B64UrlDecode(root.GetProperty("body").GetString() ?? ""));
        }
        catch (HttpRequestException e)
        {
            throw new PalException($"Can't reach the remote relay ({new Uri(baseUrl).Host}): {e.Message}", e);
        }
        catch (TaskCanceledException e) when (!token.IsCancellationRequested)
        {
            throw new PalException("The remote relay didn't answer in time.", e);
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw new PalException("The relay's answer couldn't be read.", e);
        }
    }

    private static PalException RelayRefusal(HttpStatusCode status) => status switch
    {
        HttpStatusCode.Forbidden => new PalException("Remote access refused. Your admin hasn't allowed this PC to use the relay, " +
            "or your server hasn't told the relay yet (it does within a minute)."),
        HttpStatusCode.Unauthorized => new PalException("Clock wrong. This PC's clock is more than 5 minutes off. Fix the time and try again."),
        HttpStatusCode.TooManyRequests => new PalException("Too many requests waiting at the relay. Try again in a minute."),
        _ => new PalException($"The remote relay answered HTTP {(int)status}."),
    };

    private static HttpClient NewRelayHttp()
    {
        // An ordinary HTTPS client: the relay has a public certificate, and may be reached through a proxy.
        var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(40) };
        // Cloudflare blocks some default user agents (error 1010): always name ourselves.
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("CertGeneratorPal", AppVersion));
        return http;
    }

    private static ByteArrayContent JsonContent(byte[] body)
    {
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    /// <summary>Debug logging hook: one line per request (method, path, status, time). Never bodies or headers,
    /// so no signatures, codes or keys.</summary>
    public static Action<string>? Trace { get; set; }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        var trace = Trace;
        if (trace is null)
        {
            return await SendCoreAsync(request, token).ConfigureAwait(false);
        }
        string target = $"{request.Method} {request.RequestUri?.GetLeftPart(UriPartial.Path)}";
        var watch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var response = await SendCoreAsync(request, token).ConfigureAwait(false);
            trace($"{target} → {(int)response.StatusCode} in {watch.ElapsedMilliseconds} ms");
            return response;
        }
        catch (Exception e) when (Traced(trace, $"{target} failed after {watch.ElapsedMilliseconds} ms", e))
        {
            throw;  // never reached: the filter only logs
        }
    }

    private static bool Traced(Action<string> trace, string what, Exception e)
    {
        trace($"{what}: {e.GetType().Name}: {e.Message}" + (e.InnerException is { } inner ? $" ({inner.GetType().Name}: {inner.Message})" : ""));
        return false;
    }

    private async Task<HttpResponseMessage> SendCoreAsync(HttpRequestMessage request, CancellationToken token)
    {
        try
        {
            return await _http.SendAsync(request, token).ConfigureAwait(false);
        }
        catch (HttpRequestException e) when (e.InnerException is PalException inner)
        {
            throw inner;
        }
        catch (HttpRequestException e) when (e.InnerException is System.Security.Authentication.AuthenticationException)
        {
            throw new PalException($"{_server.Host}'s HTTPS certificate isn't trusted and doesn't come from the CA in the pairing code. " +
                "Use the server's http:// LAN address, or give it a certificate from this CA.", e);
        }
        catch (HttpRequestException e)
        {
            throw new PalException($"Can't reach {_server.Host}: {e.Message}", e);
        }
        catch (TaskCanceledException e) when (!token.IsCancellationRequested)
        {
            throw new PalException($"{_server.Host} didn't answer in time.", e);
        }
    }

    private static PalException Failure(HttpStatusCode status, byte[] reply)
    {
        string? message = null;
        try
        {
            message = JsonSerializer.Deserialize<ErrorReply>(reply, Json.Options)?.Error;
        }
        catch (JsonException)
        {
            // not JSON: fall through to the generic message
        }
        message ??= status switch
        {
            HttpStatusCode.NotFound => "The server doesn't offer Cert Generator Pal here. Check the address, and that it's a Docker install on your LAN.",
            (HttpStatusCode)423 => "The server is locked. Ask your admin to unlock it, then try again.",
            _ => $"The server answered {(int)status} {status}.",
        };
        if ((int)status == 423)
        {
            message = "The server is locked. Ask your admin to unlock it, then try again.";
        }
        return new PalException(message, (int)status);
    }
}

/// <summary>Chain checks against the root pinned in the pairing code.</summary>
public static class ChainCheck
{
    /// <summary>The chain is root-first, as the server sends it; its first certificate must be the pinned root.</summary>
    public static bool RootMatches(IReadOnlyList<string> chainPems, string rootSha256)
    {
        ArgumentNullException.ThrowIfNull(chainPems);
        if (chainPems.Count == 0)
        {
            return false;
        }
        try
        {
            using var root = X509Certificate2.CreateFromPem(chainPems[0]);
            return string.Equals(Protocol.Sha256Hex(root.RawData), rootSha256, StringComparison.OrdinalIgnoreCase);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
