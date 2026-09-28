using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class DomainUtilsTests
{
    [Theory]
    [InlineData("login.secure.paypal.com", "paypal.com")]
    [InlineData("www.amazon.co.uk", "amazon.co.uk")]
    [InlineData("portal.gov.jo", "portal.gov.jo")]
    [InlineData("evil.xyz", "evil.xyz")]
    public void RegistrableDomain_handles_multi_label_suffixes(string host, string expected) =>
        Assert.Equal(expected, DomainUtils.RegistrableDomain(host));

    [Theory]
    [InlineData("paypal", "paypal", 0)]
    [InlineData("paypa1", "paypal", 1)]
    [InlineData("kitten", "sitting", 3)]
    public void Levenshtein_distance(string a, string b, int expected) =>
        Assert.Equal(expected, DomainUtils.Levenshtein(a, b));

    [Fact]
    public void GetHost_accepts_scheme_less_urls() =>
        Assert.Equal("example.com", DomainUtils.GetHost("example.com/path"));
}

public class BrandCatalogTests
{
    private readonly BrandCatalog _brands = BrandCatalog.Default;

    [Theory]
    [InlineData("paypa1.com", "homoglyph")]
    [InlineData("rnicrosoft.com", "homoglyph")]
    [InlineData("amazom.com", "typosquat")]
    [InlineData("paypal-secure-login.com", "brand-in-domain")]
    [InlineData("paypal.com.account-verify.xyz", "brand-in-subdomain")]
    [InlineData("dhl-parcel.info", "brand-in-domain")]
    public void Detects_impersonation(string host, string kind) =>
        Assert.Equal(kind, _brands.DetectImpersonation(host)?.Kind);

    [Theory]
    [InlineData("paypal.com")]
    [InlineData("www.paypal.com")]
    [InlineData("accounts.google.com")]
    [InlineData("purchase.com")]     // contains "chase" - must not trip
    [InlineData("pineapple.com")]    // contains "apple"
    [InlineData("me.example.com")]   // "me" is Apple's me.com label
    [InlineData("github.io")]
    [InlineData("stackoverflow.com")]
    public void Does_not_flag_legitimate_or_unrelated_domains(string host) =>
        Assert.Null(_brands.DetectImpersonation(host));

    [Theory]
    [InlineData("PayPal Security Team", "PayPal")]
    [InlineData("Bank Of America Alerts", "Bank of America")]
    [InlineData("Microsoft 365", "Microsoft")]
    public void Finds_brand_in_display_name(string name, string brand) =>
        Assert.Equal(brand, _brands.MentionedIn(name)?.Name);

    [Theory]
    [InlineData("Sarah Ahmad")]
    [InlineData("Groups of friends")]  // "ups" only as a whole word
    public void No_brand_in_ordinary_names(string name) =>
        Assert.Null(_brands.MentionedIn(name));
}

public class LinkAnalyserTests
{
    private readonly LinkAnalyser _analyser = new(BrandCatalog.Default);

    private ComponentResult Analyse(params EmailLink[] links) => _analyser.Analyse(links);

    [Fact]
    public void Flags_ip_address_url() =>
        Assert.Contains(Analyse(new EmailLink("Login", "http://192.168.10.5/login")).Findings, f => f.Code == "ip-url");

    [Fact]
    public void Flags_text_that_shows_a_different_domain()
    {
        var result = Analyse(new EmailLink("https://www.paypal.com/signin", "https://secure-update.xyz/pp"));
        Assert.Contains(result.Findings, f => f.Code == "text-href-mismatch");
        Assert.Contains(result.Findings, f => f.Code == "suspicious-tld");
    }

    [Fact]
    public void Unwraps_google_redirects_before_judging()
    {
        var wrapped = "https://www.google.com/url?q=https://paypa1.com/login&sa=D";
        Assert.Contains(Analyse(new EmailLink("Sign in", wrapped)).Findings, f => f.Code == "lookalike-domain");
    }

    [Fact]
    public void Clean_links_score_zero()
    {
        var result = Analyse(
            new EmailLink("View on GitHub", "https://github.com/dotnet/machinelearning"),
            new EmailLink("docs.microsoft.com", "https://docs.microsoft.com/dotnet"),
            new EmailLink("Unsubscribe", "mailto:unsubscribe@example.com"));
        Assert.Empty(result.Findings);
        Assert.Equal(0, result.Score);
    }

    [Fact]
    public void Repeated_findings_of_the_same_kind_do_not_stack()
    {
        var links = Enumerable.Range(0, 20).Select(i => new EmailLink("track", $"https://bit.ly/abc{i}")).ToArray();
        var result = Analyse(links);
        Assert.Single(result.Findings);
        Assert.Equal(0.15, result.Score, 3);
    }
}

public class HeaderAnalyserTests
{
    private readonly HeaderAnalyser _analyser = new(BrandCatalog.Default);

    [Fact]
    public void Brand_display_name_from_freemail_is_flagged()
    {
        var result = _analyser.Analyse(new EmailSubmission { SenderName = "PayPal Support", SenderEmail = "paypal.support.team@gmail.com" });
        Assert.Contains(result.Findings, f => f.Code == "brand-display-freemail");
    }

    [Fact]
    public void Reply_to_divergence_is_flagged()
    {
        var result = _analyser.Analyse(new EmailSubmission { SenderEmail = "billing@company.com", ReplyTo = "company.billing@outlook.com" });
        Assert.Contains(result.Findings, f => f.Code == "reply-to-freemail");
    }

    [Fact]
    public void Genuine_brand_sender_is_clean()
    {
        var result = _analyser.Analyse(new EmailSubmission { SenderName = "PayPal", SenderEmail = "service@paypal.com" });
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void Reads_authentication_results_from_raw_headers()
    {
        const string raw = """
            Delivered-To: me@gmail.com
            Authentication-Results: mx.google.com;
                   dkim=fail header.i=@paypal.com;
                   spf=softfail (google.com: domain of transitioning x@paypal.com does not designate 1.2.3.4 as permitted sender) smtp.mailfrom=x@paypal.com;
                   dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
            From: "PayPal" <service@paypal.com>
            Reply-To: refunds.desk@proton.me
            Subject: Your account

            body starts here
            """;
        var result = _analyser.Analyse(new EmailSubmission { RawHeaders = raw });

        Assert.Contains(result.Findings, f => f.Code == "dmarc-fail");
        Assert.Contains(result.Findings, f => f.Code == "spf-fail");
        Assert.Contains(result.Findings, f => f.Code == "dkim-fail");
        Assert.Contains(result.Findings, f => f.Code == "reply-to-freemail");
        Assert.True(result.Score > 0.8);
    }

    [Fact]
    public void Microsoft_compauth_failure_is_flagged()
    {
        // Real shape of an Outlook/Office 365 verdict on a spoofed sender.
        const string raw = "Authentication-Results: spf=temperror (sender IP is 137.184.34.4) smtp.mailfrom=vps-06; dkim=none (message not signed) header.d=none;dmarc=temperror action=none header.from=atendimento.com.br;compauth=fail reason=001\n";
        var result = _analyser.Analyse(new EmailSubmission { RawHeaders = raw });
        Assert.Contains(result.Findings, f => f.Code == "compauth-fail");
    }

    [Fact]
    public void Passing_authentication_is_reported_as_positive_evidence()
    {
        const string raw = "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\nFrom: GitHub <noreply@github.com>\n";
        var result = _analyser.Analyse(new EmailSubmission { RawHeaders = raw });
        Assert.Contains(result.Findings, f => f.Code == "auth-pass" && f.Weight == 0);
        Assert.Equal(0, result.Score);
    }
}

public class ScoringTests
{
    [Fact]
    public void NoisyOr_combines_independent_evidence()
    {
        Assert.Equal(0, Scoring.NoisyOr(Array.Empty<double>()));
        Assert.Equal(0.5, Scoring.NoisyOr([0.5]), 6);
        Assert.Equal(0.75, Scoring.NoisyOr([0.5, 0.5]), 6);
        Assert.True(Scoring.NoisyOr([0.9, 0.9, 0.9]) < 1);
    }
}
