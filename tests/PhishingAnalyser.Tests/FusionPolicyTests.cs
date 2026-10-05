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
    public void Gmail_wrapped_links_are_unwrapped_before_the_brand_check()
    {
        // In real Gmail every link is shown as https://www.google.com/url?q=<real link>.
        var wrapped = Receipt(rawHeaders: string.Format(Pass, "email.apple.com", "Apple", "no_reply@email.apple.com"),
            links: [new EmailLink("View receipt", "https://www.google.com/url?q=https://www.apple.com/receipt/123&source=gmail")]);
        Assert.Contains(Analyser(0.99, false, true).Analyse(wrapped).Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");

        var wrappedEvil = Receipt(rawHeaders: string.Format(Pass, "email.apple.com", "Apple", "no_reply@email.apple.com"),
            links: [new EmailLink("View receipt", "https://www.google.com/url?q=https://apple-billing-review.com/login&source=gmail")]);
        Assert.DoesNotContain(Analyser(0.99, false, true).Analyse(wrappedEvil).Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
    }

    [Fact]
    public void Gmail_auto_linked_addresses_and_mailto_links_do_not_break_brand_trust()
    {
        // Live test: Gmail turns a footer address into a Google Maps link; LinkedIn/GitHub mail lost its trust because of it.
        var real = Receipt(rawHeaders: string.Format(Pass, "email.apple.com", "Apple", "no_reply@email.apple.com"), links:
        [
            new EmailLink("View receipt", "https://www.apple.com/receipt/123"),
            new EmailLink("One Apple Park Way, Cupertino, CA 95014", "https://www.google.com/maps/search/One+Apple+Park+Way?entry=gmail&source=g"),
            new EmailLink("support@apple.com", "mailto:support@apple.com"),
        ]);
        Assert.Contains(Analyser(0.99, false, true).Analyse(real).Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
    }

    [Theory]
    [InlineData("https://maps-google.com.evil.example/maps/login")]      // "maps" in an attacker's host is not Google Maps
    [InlineData("https://www.google.com.evil.example/maps/search/x")]
    [InlineData("javascript:alert(1)")]                                    // unparseable/non-web schemes are NOT neutral
    public void Only_real_google_maps_and_mailto_tel_are_neutral(string href) =>
        Assert.False(LinkAnalyser.IsNeutralLink(href));

    [Fact]
    public void Free_mail_accounts_get_no_trust_even_though_the_provider_is_a_brand()
    {
        // Found on real data: 154 phishing emails from @gmail.com passed DMARC and matched "Google".
        var fromGmail = Receipt("apple.billing.team@gmail.com", string.Format(Pass, "gmail.com", "Apple", "apple.billing.team@gmail.com"));
        Assert.DoesNotContain(Analyser(0.99, false, true).Analyse(fromGmail).Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
    }

    [Fact]
    public void Genuine_brand_notification_with_a_link_elsewhere_gets_no_trust()
    {
        // e.g. a real GitHub/Google notification carrying attacker-written text and an outside link.
        var abused = Receipt(rawHeaders: string.Format(Pass, "email.apple.com", "Apple", "no_reply@email.apple.com"),
            links: [new EmailLink("View receipt", "https://apple-billing-review.com/login")]);
        Assert.DoesNotContain(Analyser(0.99, false, true).Analyse(abused).Breakdown.Headers.Findings, f => f.Code == "verified-brand-sender");
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

/// <summary>Link text vs destination: the same company's sister domains are not deception; user-content hosts always are suspect.</summary>
public class SisterDomainTests
{
    private static readonly LinkAnalyser Links = new(BrandCatalog.Default);

    private static bool Mismatch(string text, string href) =>
        Links.Analyse([new EmailLink(text, href)]).Findings.Any(f => f.Code == "text-href-mismatch");

    [Theory]
    [InlineData("facebook.com", "https://www.facebookmail.com/n/?id=1")]
    [InlineData("x.com", "https://t.co/abc123")]
    [InlineData("www.linkedin.com", "https://lnkd.in/xyz")]
    public void Same_company_sister_domains_are_not_a_mismatch(string text, string href) => Assert.False(Mismatch(text, href));

    [Theory]
    [InlineData("paypal.com", "https://paypal-account-review.com/login")]
    [InlineData("amazon.com", "https://amazon-billing.s3.amazonaws.com/login.html")] // same "owner", but anyone can host there
    [InlineData("github.com", "https://attacker.github.io/login")]
    public void Real_mismatches_and_user_content_hosts_still_fire(string text, string href) => Assert.True(Mismatch(text, href));
}

/// <summary>Click tracking and platform redirects, found on the owner's real mailbox; phishing-style uses must still fire.</summary>
public class TrackedLinkTests
{
    private static readonly LinkAnalyser Links = new(BrandCatalog.Default);

    private static string[] Codes(string sender, string text, string href) =>
        Links.Analyse([new EmailLink(text, href)], DomainUtils.GetEmailDomain(sender)).Findings.Select(f => f.Code).ToArray();

    [Fact]
    public void Platform_notification_through_its_own_redirector_is_not_deception() =>
        Assert.DoesNotContain("text-href-mismatch", Codes("notify@x.com", "youtu.be/abc123", "https://twitter.com/i/redirect?id=1"));

    [Fact]
    public void Newsletter_click_tracking_is_reported_weakly()
    {
        var codes = Codes("news@openai.com", "openai.com/blog", "https://mandrillapp.com/track/click/123");
        Assert.Contains("tracked-link", codes);
        Assert.DoesNotContain("text-href-mismatch", codes);
    }

    // Found on an independent honeypot inbox: trackers the list didn't know, and a brand's own mail domain.
    [Theory]
    [InlineData("news@tutorialsdojo.com", "portal.tutorialsdojo.com", "https://clicks.aweber.com/y/ct/?l=abc")]
    [InlineData("hello@pons.com", "account.pons.com", "https://ebggicf.r.bh.d.sendibt3.com/tr/cl/abc")]
    [InlineData("team@codepen.io", "clickclickclick.click", "https://post.spmailtechnolo.com/f/a/abc")]
    public void More_mailing_service_trackers_are_reported_weakly(string sender, string text, string href)
    {
        var codes = Codes(sender, text, href);
        Assert.Contains("tracked-link", codes);
        Assert.DoesNotContain("text-href-mismatch", codes);
    }

    [Fact]
    public void A_brands_own_mail_domain_is_not_a_mismatch() =>
        Assert.DoesNotContain("text-href-mismatch", Codes("noreply@mail.bloombergbusiness.com", "bloomberg.com", "https://link.mail.bloombergbusiness.com/click/abc"));

    [Fact]
    public void Another_brand_shown_through_a_newly_listed_tracker_stays_a_full_mismatch() =>
        Assert.Contains("text-href-mismatch", Codes("news@tutorialsdojo.com", "www.paypal.com", "https://clicks.aweber.com/y/ct/?l=abc"));

    [Fact]
    public void Brand_text_through_a_tracker_from_someone_else_stays_a_full_mismatch() =>
        Assert.Contains("text-href-mismatch", Codes("billing@random-shop.com", "www.paypal.com", "https://u123.ct.sendgrid.net/ls/click?x=1"));

    [Fact]
    public void Only_the_platform_itself_may_route_through_its_redirector() =>
        Assert.Contains("text-href-mismatch", Codes("alerts@evil-notify.com", "youtu.be/abc123", "https://twitter.com/i/redirect?id=1"));
}

/// <summary>Found in the live Gmail test: a file name in link text was reported as a deceptive link.</summary>
public class FileNameLinkTextTests
{
    private static readonly LinkAnalyser Links = new(BrandCatalog.Default);

    [Theory]
    [InlineData("quarterly-chart-data.csv", "https://files.example-portal.com/files/123")]
    [InlineData("annual_sales_report.pdf", "https://drive.example-cdn.com/f/9")]
    [InlineData("photo.png", "https://cdn.example.org/p.png")]
    [InlineData("score.py", "https://files.example-portal.com/files/9")]     // .py is Paraguay's TLD - still a file name here
    [InlineData("README.md", "https://github.com/x/y/blob/main/README.md")]
    public void File_names_are_not_websites(string text, string href) =>
        Assert.DoesNotContain(Links.Analyse([new EmailLink(text, href)]).Findings, f => f.Code == "text-href-mismatch");

    [Theory]
    [InlineData("www.paypal.com", "https://evil.example.org/login")]
    [InlineData("invoice.zip", "https://evil.example.org/x")]   // .zip is a real TLD - and a known lure
    public void Real_domains_in_link_text_still_count(string text, string href) =>
        Assert.Contains(Links.Analyse([new EmailLink(text, href)]).Findings, f => f.Code == "text-href-mismatch");

    [Theory]
    [InlineData("paypal.com", true)]
    [InlineData("login.example.co.uk", true)]
    [InlineData("quarterly-chart-data.csv", false)]
    [InlineData("report.pdf", false)]
    public void Known_tlds_come_from_the_public_suffix_list(string host, bool expected) =>
        Assert.Equal(expected, DomainUtils.HasKnownTld(host));
}
