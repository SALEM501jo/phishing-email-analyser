using PhishingAnalyser.Core.Reputation;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Api;

/// <summary>Keeps the in-memory copy of the public threat feeds fresh (download at startup, then every N minutes).</summary>
public sealed class ThreatFeedRefresher(
    ThreatFeedStore store,
    ReputationOptions options,
    BrandCatalog brands,
    IHttpClientFactory httpFactory,
    ILogger<ThreatFeedRefresher> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Enabled || !options.ThreatFeeds)
            return;

        var feeds = new Dictionary<string, string> { ["URLhaus"] = options.UrlhausFeedUrl, ["OpenPhish"] = options.OpenPhishFeedUrl };
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(Math.Max(5, options.FeedRefreshMinutes)));
        do
        {
            try
            {
                await store.RefreshAsync(httpFactory.CreateClient("feeds"), feeds, HostMatchAllowed, stoppingToken);
                logger.LogInformation("Threat feeds refreshed: {Count} URLs", store.UrlCount);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                logger.LogWarning(e, "Threat feed refresh failed; keeping the previous copy");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    /// <summary>Whole-host matches only for hosts that aren't brands' own or shared hosting platforms.</summary>
    private bool HostMatchAllowed(string host) =>
        brands.OwnerOf(host) is null &&
        brands.UserContentPlatform(host) is null &&
        !brands.Brands.Any(b => b.Domains.Any(d => DomainUtils.IsSameOrSubdomain(DomainUtils.RegistrableDomain(host), d)));
}
