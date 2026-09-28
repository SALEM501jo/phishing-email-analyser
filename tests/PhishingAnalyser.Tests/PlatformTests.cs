using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class PublicSuffixTests
{
    [Theory]
    [InlineData("paypal-login.pages.dev", "paypal-login.pages.dev")]   // PSL private section: each site is its own domain
    [InlineData("someone.github.io", "someone.github.io")]
    [InlineData("shop.example.com.sa", "example.com.sa")]
    [InlineData("www.bbc.co.uk", "bbc.co.uk")]
    [InlineData("login.secure.paypal.com", "paypal.com")]
    public void Registrable_domain_uses_the_full_public_suffix_list(string host, string expected) =>
        Assert.Equal(expected, DomainUtils.RegistrableDomain(host));

    [Theory]
    [InlineData("someone.github.io", "github.io")]
    [InlineData("x.web.app", "web.app")]
    [InlineData("github.com", null)]
    [InlineData("example.com", null)]
    public void Detects_hosting_platform_suffixes(string host, string? platform) =>
        Assert.Equal(platform, DomainUtils.PrivatePlatformSuffix(host));
}

public class ReasonMergingTests
{
    [Fact]
    public void Same_lookalike_domain_in_sender_and_links_is_one_reason()
    {
        var analyser = new EmailAnalyser(new PhishingAnalyser.Core.Content.UnavailableContentClassifier(),
            new HeaderAnalyser(BrandCatalog.Default), new LinkAnalyser(BrandCatalog.Default), new ScoringOptions());
        var result = analyser.Analyse(new EmailSubmission
        {
            Subject = "Your parcel is on hold",
            SenderName = "Express Delivery",
            SenderEmail = "noreply@dhl-parcel-track.info",
            Body = "Pay the customs fee.",
            Links = [new EmailLink("Pay now", "http://dhl-parcel-track.info/pay")],
        });

        var lookalikeReasons = result.Reasons.Where(r => r.Contains("dhl-parcel-track.info") && r.Contains("impersonates")).ToList();
        var reason = Assert.Single(lookalikeReasons);
        Assert.EndsWith("the links use the same domain", reason);
    }
}

public class UserContentHostTests
{
    private readonly BrandCatalog _brands = BrandCatalog.Default;
    private readonly LinkAnalyser _links = new(BrandCatalog.Default);

    [Fact]
    public void Brand_catalogue_loads_from_json() =>
        Assert.Contains(_brands.Brands, b => b.Name == "Arab Bank" && b.Keywords.Contains("البنك العربي"));

    [Theory]
    [InlineData("attacker.github.io")]
    [InlineData("contoso.sharepoint.com")]
    [InlineData("sites.google.com")]
    public void Published_content_never_inherits_the_platform_brand(string host) =>
        Assert.Null(_brands.OwnerOf(host));

    [Fact]
    public void Platform_itself_is_still_owned() => Assert.Equal("GitHub", _brands.OwnerOf("docs.github.com")?.Name);

    [Fact]
    public void Live_openphish_example_on_pages_dev_is_impersonation()
    {
        // Real entry from the OpenPhish public feed while this was written.
        var codes = _links.Analyse([new EmailLink("Ledger Live update", "http://ledger-com-strts.pages.dev/")]).Findings.Select(f => f.Code);
        Assert.Contains("lookalike-domain", codes);
        Assert.Contains("user-content-host", codes);
    }

    [Fact]
    public void Brand_page_published_on_google_sites_is_flagged()
    {
        var result = _links.Analyse([new EmailLink("Review your account", "https://sites.google.com/view/paypal-account-review")]);
        Assert.Contains(result.Findings, f => f.Code == "brand-on-user-content");
        Assert.DoesNotContain(result.Findings, f => f.Code == "lookalike-domain"); // sites.google.com is Google's own host
    }

    [Fact]
    public void Plain_form_link_is_only_a_weak_signal()
    {
        var result = _links.Analyse([new EmailLink("Register for the workshop", "https://forms.gle/AbC123xyz")]);
        var finding = Assert.Single(result.Findings);
        Assert.Equal("user-content-host", finding.Code);
        Assert.True(result.Score < 0.25);
    }

    [Fact]
    public void Official_platform_links_are_clean() =>
        Assert.Empty(_links.Analyse([new EmailLink("Docs", "https://docs.github.com/en/pages")]).Findings);
}
