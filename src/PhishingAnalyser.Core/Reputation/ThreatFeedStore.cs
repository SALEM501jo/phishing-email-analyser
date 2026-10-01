namespace PhishingAnalyser.Core.Reputation;

public sealed record FeedMatch(string Feed, string Indicator, bool ExactUrl);

/// <summary>
/// In-memory copy of public threat feeds (URLhaus: malware URLs; OpenPhish: phishing URLs). Refreshed in the
/// background, so a lookup is a hash-set check with no network call - and no URL from the user's mail ever leaves
/// the server for these feeds.
/// </summary>
public sealed class ThreatFeedStore
{
    private sealed record Snapshot(Dictionary<string, string> Urls, Dictionary<string, string> Hosts, DateTimeOffset LoadedAt);

    private volatile Snapshot _current = new([], [], DateTimeOffset.MinValue);

    public int UrlCount => _current.Urls.Count;
    public DateTimeOffset LoadedAt => _current.LoadedAt;
    public bool IsLoaded => _current.Urls.Count > 0;

    /// <summary>Downloads every feed and swaps the snapshot atomically. If one feed fails the others still load; if all fail, the previous snapshot is kept.</summary>
    public async Task RefreshAsync(HttpClient http, IReadOnlyDictionary<string, string> feeds, Func<string, bool> hostMatchAllowed, CancellationToken ct)
    {
        var urls = new Dictionary<string, string>(StringComparer.Ordinal);
        var hosts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, url) in feeds)
        {
            string body;
            try
            {
                body = await http.GetStringAsync(url, ct);
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
            {
                continue;
            }
            Load(name, body, urls, hosts, hostMatchAllowed);
        }

        if (urls.Count > 0)
            _current = new Snapshot(urls, hosts, DateTimeOffset.UtcNow);
    }

    /// <summary>Parses a plain-text feed (one URL per line, '#' comments). Public for tests.</summary>
    public void LoadForTesting(string name, string body, Func<string, bool> hostMatchAllowed)
    {
        var urls = new Dictionary<string, string>(_current.Urls);
        var hosts = new Dictionary<string, string>(_current.Hosts);
        Load(name, body, urls, hosts, hostMatchAllowed);
        _current = new Snapshot(urls, hosts, DateTimeOffset.UtcNow);
    }

    public FeedMatch? Match(string url)
    {
        var snapshot = _current;
        var key = Normalise(url);
        if (key is null)
            return null;
        if (snapshot.Urls.TryGetValue(key, out var feed))
            return new FeedMatch(feed, url, ExactUrl: true);
        var host = HostOf(key);
        return host is not null && snapshot.Hosts.TryGetValue(host, out feed) ? new FeedMatch(feed, host, ExactUrl: false) : null;
    }

    private static void Load(string name, string body, Dictionary<string, string> urls, Dictionary<string, string> hosts, Func<string, bool> hostMatchAllowed)
    {
        foreach (var raw in body.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;
            var key = Normalise(line);
            if (key is null)
                continue;
            urls.TryAdd(key, name);
            // Host-level matching only for hosts that aren't shared platforms: attackers also abuse github.com or
            // drive.google.com, and flagging the whole host would flag every legitimate link to it.
            if (HostOf(key) is { } host && hostMatchAllowed(host))
                hosts.TryAdd(host, name);
        }
    }

    /// <summary>Scheme-less, lower-case host, no trailing slash, no fragment - so trivial variations still match.</summary>
    internal static string? Normalise(string url)
    {
        if (!Rules.DomainUtils.TryCreateUri(url.Contains("://") ? url : "http://" + url, out var uri) || uri.Scheme is not ("http" or "https"))
            return null;
        var path = uri.PathAndQuery.TrimEnd('/');
        try
        {
            return uri.IdnHost.ToLowerInvariant() + (uri.IsDefaultPort ? "" : ":" + uri.Port) + path;
        }
        catch (UriFormatException)
        {
            return null; // host with characters illegal in international domain names: unmatchable, never a crash
        }
    }

    private static string? HostOf(string normalised)
    {
        var end = normalised.IndexOfAny([':', '/', '?']);
        return end < 0 ? normalised : normalised[..end];
    }
}
