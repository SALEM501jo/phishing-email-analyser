using System.Net.Http.Json;
using System.Text.Json;

namespace PhishingAnalyser.Core.Reputation;

/// <summary>
/// Optional Google Safe Browsing Lookup API (v4). Only active when an API key is configured, because it sends the
/// email's URLs to Google - the README documents this trade-off.
/// </summary>
public sealed class SafeBrowsingClient(HttpClient http, string apiKey)
{
    public async Task<IReadOnlyList<(string Url, string Threat)>> CheckAsync(IReadOnlyCollection<string> urls, CancellationToken ct)
    {
        if (urls.Count == 0)
            return [];

        var request = new
        {
            client = new { clientId = "phishing-email-analyser", clientVersion = "1.0" },
            threatInfo = new
            {
                threatTypes = new[] { "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION" },
                platformTypes = new[] { "ANY_PLATFORM" },
                threatEntryTypes = new[] { "URL" },
                threatEntries = urls.Take(50).Select(u => new { url = u }),
            },
        };

        try
        {
            using var response = await http.PostAsJsonAsync($"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={Uri.EscapeDataString(apiKey)}", request, ct);
            if (!response.IsSuccessStatusCode)
                return [];
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
            if (!doc.RootElement.TryGetProperty("matches", out var matches))
                return [];
            return matches.EnumerateArray()
                .Select(m => (m.GetProperty("threat").GetProperty("url").GetString()!, m.GetProperty("threatType").GetString()!))
                .ToList();
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            return [];
        }
    }
}
