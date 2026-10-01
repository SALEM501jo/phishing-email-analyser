using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class RedTeam_link_evasion_2
{
    private const string Pass =
        "Authentication-Results: mx.google.com; dkim=pass header.d=google.com; spf=pass smtp.mailfrom=google.com; dmarc=pass header.from=google.com\nFrom: Google <no-reply@google.com>\n";

    private static EmailAnalyser NewAnalyser() => new(new UnavailableContentClassifier(),
        new HeaderAnalyser(BrandCatalog.Default), new LinkAnalyser(BrandCatalog.Default),
        new ScoringOptions { TrustVerifiedBrandSenders = true });

    private static EmailSubmission Email(string href) => new()
    {
        Subject = "Security alert", SenderName = "Google", SenderEmail = "no-reply@google.com", RawHeaders = Pass,
        Body = "Your account will be closed. Verify now to keep access.",
        Links = new[] { new EmailLink("Verify", href) },
    };

    // Control: the same attack with a single (non-nested) google.com/url redirect is correctly denied trust.
    [Fact]
    public void Control_direct_google_redirect_to_attacker_is_denied_trust()
    {
        var result = NewAnalyser().Analyse(Email("https://www.google.com/url?q=https://evil.example/login"));
        Assert.DoesNotContain(result.Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
    }

    // Control: a genuine on-brand link still gets trust (so the setup itself qualifies for verified-brand-sender).
    [Fact]
    public void Control_on_brand_link_gets_trust()
    {
        var result = NewAnalyser().Analyse(Email("https://myaccount.google.com/security"));
        Assert.Contains(result.Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
    }

    [Fact]
    public void Nested_redirector_hides_the_real_destination_from_the_verified_brand_check()
    {
        const string nested =
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttps%3A%2F%2Fevil.example%2Flogin";

        // Every redirector layer is peeled, down to the real destination (it used to stop at the inner google.com/url).
        Assert.Equal("https://evil.example/login", LinkAnalyser.Unwrap(nested));

        // Outer safelinks wraps an INNER google.com/url open redirect to the attacker; peeling one layer left host
        // www.google.com (Google-owned), so the link falsely 'stayed on brand'.
        var result = NewAnalyser().Analyse(Email(nested));
        Assert.DoesNotContain(result.Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
    }

    // Downstream effect: with links/headers scoring 0, the scorer applies VerifiedBrandContentFactor (its limitation note appears).
    [Fact]
    public void Too_deeply_nested_redirectors_fail_closed()
    {
        var href = "https://evil.example/login";
        for (var i = 0; i < 8; i++)
            href = "https://www.google.com/url?q=" + Uri.EscapeDataString(href);
        Assert.Equal("", LinkAnalyser.Unwrap(href));
        Assert.DoesNotContain(NewAnalyser().Analyse(Email(href)).Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
    }

    [Fact]
    public void Nested_redirector_triggers_the_text_down_weighting()
    {
        const string nested =
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttps%3A%2F%2Fevil.example%2Flogin";
        var result = NewAnalyser().Analyse(Email(nested));
        Assert.DoesNotContain(result.Limitations, l => l.Contains("verified real domain"));
    }
}
