namespace PhishingAnalyser.Core.Reputation;

/// <summary>
/// Network lookups about the domains/URLs in an email. Each can be switched off: they reveal to the
/// provider WHICH domains appear in the user's mail (never any content).
/// </summary>
public sealed class ReputationOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>RDAP registration-date lookups (registries, free, no key).</summary>
    public bool DomainAge { get; set; } = true;

    /// <summary>URLhaus + OpenPhish public feeds, downloaded periodically; lookups are local.</summary>
    public bool ThreatFeeds { get; set; } = true;

    public int FeedRefreshMinutes { get; set; } = 30;

    public string UrlhausFeedUrl { get; set; } = "https://urlhaus.abuse.ch/downloads/text_online/";
    public string OpenPhishFeedUrl { get; set; } = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";

    /// <summary>Optional Google Safe Browsing (Lookup API v4) key; empty = disabled.</summary>
    public string SafeBrowsingApiKey { get; set; } = "";

    /// <summary>Per-lookup timeout; a slow registry must never hold up the verdict.</summary>
    public int LookupTimeoutMs { get; set; } = 2500;

    public int MaxDomainsPerEmail { get; set; } = 8;

    /// <summary>
    /// A sender domain registered at least this long ago (independently - not a free-mail provider, brand or hosting
    /// platform) gets the zero-weight "established-sender" finding; ScoringOptions.TrustEstablishedSenders decides what it
    /// is worth. 365 days: on 3,120 real phishing emails a 2-year bar made no difference.
    /// </summary>
    public int EstablishedSenderDays { get; set; } = 365;
}
