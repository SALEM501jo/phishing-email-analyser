using System.Net;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Reputation;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class ShortLinkTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.20.0.5")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]   // cloud metadata endpoint - the classic SSRF target
    [InlineData("100.64.0.1")]        // carrier-grade NAT
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]
    [InlineData("::ffff:127.0.0.1")]  // IPv4-mapped loopback
    public void Internal_addresses_are_refused(string ip) =>
        Assert.False(ShortLinkExpander.IsPublicAddress(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("67.199.248.10")]
    [InlineData("2606:4700:4700::1111")]
    public void Public_addresses_are_allowed(string ip) =>
        Assert.True(ShortLinkExpander.IsPublicAddress(IPAddress.Parse(ip)));

    [Fact]
    public async Task Production_handler_refuses_to_connect_to_localhost()
    {
        using var client = new HttpClient(ShortLinkExpander.CreateSafeHandler());
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("http://localhost:5080/health"));
        Assert.Contains("non-public", error.Message + error.InnerException?.Message);
    }

    [Fact]
    public async Task Reads_the_destination_without_ever_contacting_it()
    {
        var handler = new FakeHandler(req => req.RequestUri!.Host switch
        {
            "bit.ly" => Redirect("https://tinyurl.com/step2"),
            "tinyurl.com" => Redirect("https://paypa1-secure.xyz/login"),
            _ => throw new InvalidOperationException("the final destination must never be contacted"),
        });
        var expander = new ShortLinkExpander(new HttpClient(handler));

        var result = await expander.ExpandAsync([new EmailLink("Track", "https://bit.ly/abc123")], default);

        var link = Assert.Single(result);
        Assert.Equal("https://paypa1-secure.xyz/login", link.Destination);
        Assert.All(handler.Requests, u => Assert.True(LinkAnalyser.IsShortener(u.Host)));
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task Non_shortener_links_are_left_alone()
    {
        var handler = new FakeHandler(_ => throw new InvalidOperationException("must not be called"));
        var result = await new ShortLinkExpander(new HttpClient(handler)).ExpandAsync([new EmailLink("x", "https://example.com/a")], default);
        Assert.Empty(result);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Expanded_destination_goes_through_the_link_checks()
    {
        var handler = new FakeHandler(_ => Redirect("https://paypa1.com/signin"));
        var analyser = new EmailAnalyser(new PhishingAnalyser.Core.Content.UnavailableContentClassifier(),
            new HeaderAnalyser(BrandCatalog.Default), new LinkAnalyser(BrandCatalog.Default), new ScoringOptions(),
            reputationAnalyser: null, shortLinks: new ShortLinkExpander(new HttpClient(handler)));

        var result = await analyser.AnalyseAsync(new EmailSubmission
        {
            Subject = "Your account", SenderEmail = "a@b.com", Body = "See link",
            Links = [new EmailLink("Open", "https://bit.ly/xyz")],
        });

        var codes = result.Breakdown.Links.Findings.Select(f => f.Code).ToList();
        Assert.Contains("lookalike-domain", codes);        // found only via the expanded destination
        Assert.Contains("shortener-expanded", codes);
        Assert.DoesNotContain("text-href-mismatch", codes); // expansion must not create false mismatches
    }

    private static HttpResponseMessage Redirect(string location)
    {
        var response = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
        response.Headers.Location = new Uri(location);
        return response;
    }
}
