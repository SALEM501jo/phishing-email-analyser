using System.Net;
using System.Runtime.CompilerServices;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Reputation;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

internal static class TestEnvironment
{
    /// <summary>API tests must never call real registries or feeds (slow, flaky, and it would leak lookups from CI).</summary>
    [ModuleInitializer]
    internal static void DisableNetworkLookups() => Environment.SetEnvironmentVariable("Reputation__Enabled", "false");
}

/// <summary>Answers every request with a canned response (optionally after a delay) and records what was asked.</summary>
internal sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond, TimeSpan? delay = null) : HttpMessageHandler
{
    public List<Uri> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Requests.Add(request.RequestUri!);
        if (delay is { } d)
            await Task.Delay(d, ct);
        return respond(request);
    }

    public static HttpResponseMessage Json(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/rdap+json") };

    public static string Rdap(DateTimeOffset registered) =>
        $$"""{"objectClassName":"domain","events":[{"eventAction":"registration","eventDate":"{{registered:yyyy-MM-ddTHH:mm:ssZ}}"}]}""";
}

public class ReputationTests
{
    private static ReputationAnalyser Analyser(FakeHandler handler, ThreatFeedStore? feeds = null, int timeoutMs = 2500) =>
        new(BrandCatalog.Default,
            new ReputationOptions { LookupTimeoutMs = timeoutMs },
            feeds ?? new ThreatFeedStore(),
            new DomainAgeChecker(new HttpClient(handler)),
            safeBrowsing: null);

    private static EmailSubmission Email(string senderEmail, params string[] hrefs) => new()
    {
        SenderEmail = senderEmail,
        Links = hrefs.Select(h => new EmailLink("link", h)).ToList(),
    };

    [Fact]
    public async Task Three_day_old_domain_is_a_strong_signal()
    {
        var handler = new FakeHandler(_ => FakeHandler.Json(FakeHandler.Rdap(DateTimeOffset.UtcNow.AddDays(-3))));
        var result = await Analyser(handler).AnalyseAsync(Email("billing@secure-invoice-portal.com"), default);

        var finding = Assert.Single(result.Findings);
        Assert.Equal("new-domain", finding.Code);
        Assert.Contains("3 days", finding.Message);
        Assert.Contains("3 أيام", finding.MessageArabic);   // correct Arabic counted form
        Assert.Contains(handler.Requests, u => u.Host == "rdap.verisign.com" && u.AbsolutePath.EndsWith("/domain/secure-invoice-portal.com"));
    }

    [Fact]
    public async Task Established_domain_adds_nothing()
    {
        var handler = new FakeHandler(_ => FakeHandler.Json(FakeHandler.Rdap(DateTimeOffset.UtcNow.AddYears(-12))));
        var result = await Analyser(handler).AnalyseAsync(Email("news@some-old-company.com"), default);
        Assert.Empty(result.Findings);
        Assert.True(result.Evaluated);
    }

    [Fact]
    public async Task Brands_free_mail_and_hosting_platforms_are_never_looked_up()
    {
        var handler = new FakeHandler(_ => FakeHandler.Json(FakeHandler.Rdap(DateTimeOffset.UtcNow)));
        await Analyser(handler).AnalyseAsync(Email("someone@gmail.com", "https://www.paypal.com/signin", "https://x.pages.dev/", "https://sites.google.com/view/a"), default);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Slow_registry_times_out_instead_of_blocking_the_verdict()
    {
        var handler = new FakeHandler(_ => FakeHandler.Json(FakeHandler.Rdap(DateTimeOffset.UtcNow)), delay: TimeSpan.FromSeconds(10));
        var started = DateTime.UtcNow;
        var result = await Analyser(handler, timeoutMs: 200).AnalyseAsync(Email("a@slow-registry-domain.com"), default);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(3));
        Assert.Empty(result.Findings);
        Assert.False(result.Evaluated);   // reported as "not checked", not as "clean"
    }

    [Fact]
    public async Task Blocklisted_url_from_a_feed_is_flagged()
    {
        var feeds = new ThreatFeedStore();
        feeds.LoadForTesting("OpenPhish", "http://ledger-com-strts.pages.dev/\n# comment\nhttps://evil-host.example/login\n", _ => true);
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        var result = await Analyser(handler, feeds).AnalyseAsync(Email("a@b.com", "http://ledger-com-strts.pages.dev", "https://evil-host.example/other-page"), default);

        Assert.Contains(result.Findings, f => f.Code == "blocklisted-url");   // exact URL (trailing slash ignored)
        Assert.Contains(result.Findings, f => f.Code == "blocklisted-host");  // different path, same host
    }

    [Fact]
    public void Shared_platform_hosts_are_not_blocklisted_wholesale()
    {
        var feeds = new ThreatFeedStore();
        // Mirrors the API's rule: whole-host matching only for hosts that aren't brands or platforms.
        feeds.LoadForTesting("URLhaus", "https://github.com/attacker/repo/raw/main/payload.exe\n",
            host => BrandCatalog.Default.OwnerOf(host) is null);
        Assert.NotNull(feeds.Match("https://github.com/attacker/repo/raw/main/payload.exe"));
        Assert.Null(feeds.Match("https://github.com/dotnet/runtime"));
    }
}
