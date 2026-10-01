using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

/// <summary>
/// The analyser must return a verdict for ANY email - an exception on attacker-controlled input would let a phisher make
/// their email un-analysable. Found on real phishing: a link host with characters that are illegal in international
/// domain names made Uri.IdnHost throw.
/// </summary>
public class HostileInputTests
{
    public static TheoryData<string> IllegalIdnUrls => new()
    {
        "http://́abc.com/login",          // label starting with a combining mark
        "http://a․b.com/",                  // ONE DOT LEADER inside a label
        "http://exa‏mple.com/",             // right-to-left mark inside a host
        "https://‮paypal.com/verify",       // right-to-left override
    };

    [Theory]
    [MemberData(nameof(IllegalIdnUrls))]
    public void GetHost_never_throws(string url) => DomainUtils.GetHost(url); // returning null or a host is fine; throwing is not

    [Theory]
    [MemberData(nameof(IllegalIdnUrls))]
    public void Threat_feed_matching_never_throws(string url) => PhishingAnalyser.Core.Reputation.ThreatFeedStore.Normalise(url);

    [Theory]
    [MemberData(nameof(IllegalIdnUrls))]
    public void Analyser_returns_a_verdict_for_hostile_links_even_on_verified_brand_mail(string url)
    {
        var analyser = new EmailAnalyser(new UnavailableContentClassifier(), new HeaderAnalyser(BrandCatalog.Default),
            new LinkAnalyser(BrandCatalog.Default), new ScoringOptions { TrustVerifiedBrandSenders = true });
        var email = new EmailSubmission
        {
            Subject = "Your receipt", Body = "Thanks for your purchase.", SenderEmail = "no_reply@email.apple.com",
            RawHeaders = "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\nFrom: Apple <no_reply@email.apple.com>\n",
            Links = [new EmailLink("View receipt", url)],
        };
        var result = analyser.Analyse(email);
        Assert.NotNull(result.Verdict);
        Assert.DoesNotContain(result.Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender"); // fail closed: no trust
    }
}
