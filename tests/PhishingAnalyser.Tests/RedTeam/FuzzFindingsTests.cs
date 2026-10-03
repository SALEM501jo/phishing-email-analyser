using System.Diagnostics;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

/// <summary>Minimal reproductions of the problems found by FuzzEmailAnalyserTests and its timing probes.</summary>
[Collection(TimingSensitive.Name)]
public class FuzzFindingsTests
{
    private static EmailAnalyser Analyser() => new(new UnavailableContentClassifier(), new HeaderAnalyser(BrandCatalog.Default),
        new LinkAnalyser(BrandCatalog.Default), new ScoringOptions { TrustVerifiedBrandSenders = true });

    private static EmailSubmission VerifiedAppleMail(IReadOnlyList<EmailLink> links, IReadOnlyList<string> qr) => new()
    {
        Subject = "Your receipt", Body = "Scan the code to view your receipt.", SenderEmail = "no_reply@email.apple.com",
        RawHeaders = "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\nFrom: Apple <no_reply@email.apple.com>\n",
        Links = links, QrCodeUrls = qr,
    };

    // 1. A link whose visible text is "QR code" makes EmailAnalyser.WithQrLinks skip every QR destination.

    [Fact]
    public void Qr_destination_is_link_checked_even_when_a_link_text_is_QR_code()
    {
        var result = Analyser().Analyse(VerifiedAppleMail([new EmailLink("QR code", "https://www.apple.com/")], ["http://185.22.4.9/apple/login"]));
        Assert.Contains(result.Breakdown.Links.Findings, f => f.Code == "ip-url");
    }

    [Fact]
    public void Off_brand_qr_destination_prevents_verified_brand_sender_even_when_a_link_text_is_QR_code()
    {
        var result = Analyser().Analyse(VerifiedAppleMail([new EmailLink("QR code", "https://www.apple.com/")], ["http://185.22.4.9/apple/login"]));
        Assert.DoesNotContain(result.Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
    }

    // 2. URL spellings every browser follows (WHATWG URL parsing) but DomainUtils.GetHost can't parse: the link gets no
    //    finding at all, so a raw-IP or look-alike destination escapes every link rule.

    [Theory]
    [InlineData("//185.22.4.9/login")]            // protocol-relative: resolves against https://mail.google.com
    [InlineData("http:\\\\185.22.4.9\\login")]   // backslashes: browsers treat \ as / in http(s) URLs
    [InlineData("https:185.22.4.9/login")]        // missing slashes: browsers insert them for http(s)
    [InlineData("https:/185.22.4.9/login")]       // one slash: GetHost even returns the host "https"
    [InlineData("https://185.22.4.9\t/login")]    // tab: browsers strip ASCII tab/newline anywhere in a URL
    public void Browser_valid_url_to_an_ip_address_is_flagged(string href)
    {
        var links = new LinkAnalyser(BrandCatalog.Default).Analyse([new EmailLink("Pay now", href)]);
        Assert.Contains(links.Findings, f => f.Code == "ip-url");
    }

    // 3. BrandCatalog.DetectImpersonation is linear in the domain length but with a large constant (two Levenshtein runs per
    //    catalogued brand domain), and nothing bounds SenderEmail: 6-30 µs per character of the sender domain on this PC, so a
    //    ~500k-character sender (inside the 512 KB request limit) costs several seconds of CPU per request.

    [Fact]
    public void Long_sender_domain_is_analysed_within_500_ms()
    {
        var analyser = Analyser();
        analyser.Analyse(new EmailSubmission { SenderEmail = "warm@up.com" });
        var email = new EmailSubmission { Subject = "Invoice", SenderEmail = "billing@" + new string('a', 100_000) + ".com" };
        var sw = Stopwatch.StartNew();
        analyser.Analyse(email);
        Assert.True(sw.ElapsedMilliseconds < 500, $"{sw.ElapsedMilliseconds} ms");
    }

    // 4. The same kind of per-character cost for hosts with many labels (a Regex and a substring search over the subdomain
    //    part per catalogued brand domain, BrandCatalog.cs:109-112) plus a fixed 1-2 ms per call; a link whose text is a
    //    domain is checked twice. 200 links (the analysis cap) with DNS-legal 245-character hosts, ~100 KB in all.

    [Fact]
    // Was 1.7-1.9 s before the brand-domain precomputation; about 0.3 s now. The limit leaves headroom for loaded CI runners.
    public void Links_to_many_label_hosts_are_analysed_quickly()
    {
        var analyser = Analyser();
        analyser.Analyse(new EmailSubmission { SenderEmail = "warm@up.com", Links = [new EmailLink("a.org", "https://x.b.com/")] });
        var labels = string.Concat(Enumerable.Repeat("a.", 120));
        var email = new EmailSubmission
        {
            Subject = "Newsletter", SenderEmail = "news@example.com",
            Links = Enumerable.Range(0, 200).Select(i => new EmailLink($"{i}.{labels}org", $"https://{i}.{labels}com/")).ToList(),
        };
        var sw = Stopwatch.StartNew();
        analyser.Analyse(email);
        Assert.True(sw.ElapsedMilliseconds < 1200, $"{sw.ElapsedMilliseconds} ms");
    }
}
