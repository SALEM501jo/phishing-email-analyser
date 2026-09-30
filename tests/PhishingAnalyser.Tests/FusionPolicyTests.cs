using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

/// <summary>
/// The two fusion policies for the "fake receipt vs real receipt" problem: text alone can't tell them apart,
/// so text alone shouldn't convict (corroboration), and authenticated mail from a brand's real domain shouldn't
/// be convicted by its wording (verified-brand trust) - without opening a door for attackers' own domains.
/// </summary>
public class FusionPolicyTests
{
    private const string Pass = "Authentication-Results: mx.google.com; dkim=pass header.d={0}; spf=pass smtp.mailfrom={0}; dmarc=pass header.from={0}\nFrom: {1} <{2}>\n";

    private static EmailAnalyser Analyser(double textProbability, bool corroboration, bool trustBrands) => new(
        new FixedClassifier(new ContentResult(true, textProbability, 0, [])),
        new HeaderAnalyser(BrandCatalog.Default), new LinkAnalyser(BrandCatalog.Default),
        new ScoringOptions { PhishingThreshold = 0.5, SuspiciousThreshold = 0.25, RequireCorroboration = corroboration, TrustVerifiedBrandSenders = trustBrands });

    private static EmailSubmission Receipt(string sender = "no_reply@email.apple.com", string? rawHeaders = null, List<EmailLink>? links = null) => new()
    {
        Subject = "Your receipt from Apple", Body = "Receipt. iCloud+ 50 GB, 0.99 USD. Billed to Visa ending 4242.",
        SenderName = "Apple", SenderEmail = sender, RawHeaders = rawHeaders, Links = links,
    };

    [Fact]
    public void Without_policies_confident_text_alone_convicts() =>
        Assert.Equal(Verdicts.Phishing, Analyser(0.99, false, false).Analyse(Receipt()).Verdict);

    [Fact]
    public void With_corroboration_text_alone_only_warns()
    {
        var result = Analyser(0.99, corroboration: true, trustBrands: false).Analyse(Receipt());
        Assert.Equal(Verdicts.Suspicious, result.Verdict);
        Assert.Contains(result.Limitations, l => l.Contains("Only the wording looks suspicious"));
    }

    [Fact]
    public void With_corroboration_text_plus_a_link_signal_still_convicts()
    {
        var phish = Receipt(links: [new EmailLink("https://www.apple.com/billing", "http://185.22.4.9/apple/login")]);
        Assert.Equal(Verdicts.Phishing, Analyser(0.99, corroboration: true, trustBrands: false).Analyse(phish).Verdict);
    }

    [Fact]
    public void Verified_mail_from_the_brands_real_domain_is_not_convicted_by_wording()
    {
        var real = Receipt(rawHeaders: string.Format(Pass, "email.apple.com", "Apple", "no_reply@email.apple.com"));
        var result = Analyser(0.99, corroboration: true, trustBrands: true).Analyse(real);
        Assert.Equal(Verdicts.Safe, result.Verdict);
        Assert.Contains(result.Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
    }

    [Fact]
    public void Attackers_own_authenticated_lookalike_domain_gets_no_trust()
    {
        // DMARC passes - for the attacker's own domain. 31% of real phishing looks like this.
        var fake = Receipt("billing@apple-receipts-support.com",
            string.Format(Pass, "apple-receipts-support.com", "Apple", "billing@apple-receipts-support.com"));
        var result = Analyser(0.99, corroboration: true, trustBrands: true).Analyse(fake);
        Assert.DoesNotContain(result.Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
        Assert.Equal(Verdicts.Phishing, result.Verdict);
    }

    [Fact]
    public void Unauthenticated_mail_claiming_a_brand_domain_gets_no_trust()
    {
        // No raw headers (DOM-only mode): the From address alone proves nothing.
        var result = Analyser(0.99, corroboration: false, trustBrands: true).Analyse(Receipt());
        Assert.DoesNotContain(result.Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
        Assert.Equal(Verdicts.Phishing, result.Verdict);
    }

    private sealed class FixedClassifier(ContentResult result) : IContentClassifier
    {
        public bool IsLoaded => true;
        public ModelInfo? Model => null;
        public ContentResult Classify(string? subject, string? body) => result;
    }
}
