using System.Collections.Concurrent;
using System.Text.Json;

namespace PhishingAnalyser.Core.Reputation;

public sealed record DomainAge(string Domain, DateTimeOffset? Registered, bool Checked);

/// <summary>
/// Registration date via RDAP (the JSON successor of WHOIS). Newly registered domains are the single strongest
/// phishing indicator in industry reporting: phishing domains typically live for days, legitimate brands for years.
/// Uses IANA's bootstrap file (bundled, Data/rdap-dns.json) to find the registry for each TLD. Results - including
/// failures - are cached so a domain is looked up at most once a day.
/// </summary>
public sealed class DomainAgeChecker
{
    private static readonly TimeSpan CacheFor = TimeSpan.FromHours(24);
    private static readonly TimeSpan RetryFailuresAfter = TimeSpan.FromMinutes(10);
    private readonly HttpClient _http;
    private readonly Dictionary<string, string> _rdapByTld;
    private readonly ConcurrentDictionary<string, (DomainAge Age, DateTimeOffset Expires)> _cache = new();
    private readonly TimeProvider _clock;

    public DomainAgeChecker(HttpClient http, string? bootstrapPath = null, TimeProvider? clock = null)
    {
        _http = http;
        _clock = clock ?? TimeProvider.System;
        _rdapByTld = LoadBootstrap(bootstrapPath ?? Path.Combine(AppContext.BaseDirectory, "Data", "rdap-dns.json"));
    }

    public bool Supports(string registrableDomain) =>
        _rdapByTld.ContainsKey(registrableDomain[(registrableDomain.LastIndexOf('.') + 1)..]);

    public async Task<DomainAge> CheckAsync(string registrableDomain, CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        if (_cache.TryGetValue(registrableDomain, out var hit) && hit.Expires > now)
            return hit.Age;

        var age = new DomainAge(registrableDomain, null, Checked: false);
        var tld = registrableDomain[(registrableDomain.LastIndexOf('.') + 1)..];
        if (_rdapByTld.TryGetValue(tld, out var baseUrl))
        {
            try
            {
                using var response = await _http.GetAsync($"{baseUrl.TrimEnd('/')}/domain/{Uri.EscapeDataString(registrableDomain)}", ct);
                if (response.IsSuccessStatusCode)
                {
                    using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
                    age = new DomainAge(registrableDomain, RegistrationDate(doc.RootElement), Checked: true);
                }
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
            {
                // Unreachable or slow registry: report "not checked" rather than guessing.
            }
        }

        // Failures are retried after a few minutes; a momentarily slow registry mustn't hide a domain for a day.
        _cache[registrableDomain] = (age, now + (age.Checked ? CacheFor : RetryFailuresAfter));
        return age;
    }

    private static DateTimeOffset? RegistrationDate(JsonElement root)
    {
        if (!root.TryGetProperty("events", out var events))
            return null;
        foreach (var e in events.EnumerateArray())
            if (e.TryGetProperty("eventAction", out var action) && action.GetString() == "registration" &&
                e.TryGetProperty("eventDate", out var date) && DateTimeOffset.TryParse(date.GetString(), out var parsed))
                return parsed;
        return null;
    }

    private static Dictionary<string, string> LoadBootstrap(string path)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(path))
            return map;
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        foreach (var service in doc.RootElement.GetProperty("services").EnumerateArray())
        {
            var url = service[1].EnumerateArray().Select(u => u.GetString()!).FirstOrDefault(u => u.StartsWith("https://"));
            if (url is null) continue;
            foreach (var tld in service[0].EnumerateArray())
                map[tld.GetString()!] = url;
        }
        return map;
    }
}
