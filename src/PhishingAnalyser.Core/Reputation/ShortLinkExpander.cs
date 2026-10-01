using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Core.Reputation;

public sealed record ExpandedLink(string ShortUrl, string Destination);

/// <summary>
/// Reveals where shortened links (bit.ly, tinyurl ...) really go, so the destination can be checked like any other link.
///
/// Security design - this is an outbound request driven by attacker-supplied input, i.e. an SSRF surface:
///   * only hosts on the shortener list are ever contacted, and following stops BEFORE the destination:
///     the attacker's server is never contacted (which would also confirm the email was opened);
///   * HEAD only, no body read, at most <see cref="MaxHops"/> hops, ports 80/443, whole expansion time-boxed;
///   * <see cref="CreateSafeHandler"/> checks the resolved IP at connect time and refuses private, loopback,
///     link-local (incl. cloud metadata 169.254.169.254), CGNAT, multicast and reserved ranges - which also
///     defeats DNS-rebinding, because the check happens on the address actually connected to.
/// </summary>
public sealed class ShortLinkExpander(HttpClient http, TimeSpan? timeout = null)
{
    public const int MaxHops = 5;
    private static readonly TimeSpan CacheFor = TimeSpan.FromHours(24);
    private readonly TimeSpan _timeout = timeout ?? TimeSpan.FromSeconds(3);
    private readonly ConcurrentDictionary<string, (string? Destination, DateTimeOffset Expires)> _cache = new();

    public async Task<IReadOnlyList<ExpandedLink>> ExpandAsync(IEnumerable<EmailLink> links, CancellationToken ct)
    {
        var shortUrls = links.Select(l => LinkAnalyser.Unwrap(l.Href))
            .Where(u => DomainUtils.GetHost(u) is { } h && LinkAnalyser.IsShortener(h))
            .Distinct()
            .Take(10)
            .ToList();
        if (shortUrls.Count == 0)
            return [];

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(_timeout);
        var results = await Task.WhenAll(shortUrls.Select(async u => (u, d: await ExpandOneAsync(u, budget.Token))));
        return results.Where(r => r.d is not null).Select(r => new ExpandedLink(r.u, r.d!)).ToList();
    }

    private async Task<string?> ExpandOneAsync(string shortUrl, CancellationToken ct)
    {
        if (_cache.TryGetValue(shortUrl, out var hit) && hit.Expires > DateTimeOffset.UtcNow)
            return hit.Destination;

        string? destination = null;
        try
        {
            // Inside the try: a malformed (attacker-written) URL must leave the link unexpanded, not fail the analysis.
            var current = new Uri(shortUrl.Contains("://") ? shortUrl : "https://" + shortUrl);
            for (var hop = 0; hop < MaxHops; hop++)
            {
                if (current.Scheme is not ("http" or "https") || current.Port is not (80 or 443) || !LinkAnalyser.IsShortener(current.IdnHost))
                    break;

                using var request = new HttpRequestMessage(HttpMethod.Head, current);
                using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                if ((int)response.StatusCode is < 300 or >= 400 || response.Headers.Location is not { } location)
                    break;

                current = location.IsAbsoluteUri ? location : new Uri(current, location);
                destination = current.ToString();
                if (!LinkAnalyser.IsShortener(current.IdnHost))
                    break; // reached the real destination - read its address, never contact it
            }
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or UriFormatException or IndexOutOfRangeException)
        {
            // Unreachable, blocked by the SSRF guard, or out of time: leave the link unexpanded.
        }

        _cache[shortUrl] = (destination, DateTimeOffset.UtcNow + CacheFor);
        return destination;
    }

    /// <summary>The production handler: no automatic redirects, and a connect-time guard against internal addresses.</summary>
    public static SocketsHttpHandler CreateSafeHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(2),
        ConnectCallback = async (context, ct) =>
        {
            var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct);
            var target = addresses.FirstOrDefault(IsPublicAddress)
                ?? throw new HttpRequestException($"Refusing to connect to non-public address for {context.DnsEndPoint.Host}");
            var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(target, context.DnsEndPoint.Port), ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        },
    };

    /// <summary>True only for globally routable unicast addresses.</summary>
    public static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address))
            return false;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] == 0 || b[0] == 10 || b[0] == 127 ||
                     (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||       // CGNAT 100.64/10
                     (b[0] == 169 && b[1] == 254) ||                     // link-local, cloud metadata
                     (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                     (b[0] == 192 && b[1] == 168) ||
                     (b[0] == 192 && b[1] == 0 && b[2] == 0) ||          // IETF protocol assignments
                     (b[0] == 198 && (b[1] == 18 || b[1] == 19)) ||      // benchmarking
                     b[0] >= 224);                                       // multicast + reserved + broadcast
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            return !(address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast ||
                     (b[0] & 0xFE) == 0xFC ||                              // unique local fc00::/7
                     address.Equals(IPAddress.IPv6None) || address.Equals(IPAddress.IPv6Any));
        }

        return false;
    }
}
