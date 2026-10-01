using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Rules;
using Xunit;

namespace PhishingAnalyser.Tests;

/// <summary>
/// Red-team finding: the bare-file-name exemption ("score.py") swallowed deceptive link text on real country TLDs
/// ("mojbank.pl" shown, attacker site linked) - no finding at all.
/// </summary>
public class RedTeam_link_evasion_0
{
    private static readonly LinkAnalyser Links = new(BrandCatalog.Default);

    private static string[] Codes(string text, string href) =>
        Links.Analyse([new EmailLink(text, href)]).Findings.Select(f => f.Code).ToArray();

    // .pl (Poland), .so, .ml, .sc host many real sites: never treated as a file name.
    [Theory]
    [InlineData("mojbank.pl")]
    [InlineData("shop.so")]
    [InlineData("pay.sc")]
    [InlineData("portal.ml")]
    public void Real_country_domains_in_link_text_are_a_full_mismatch(string shownText) =>
        Assert.Contains("text-href-mismatch", Codes(shownText, "https://account-verify-login.com/login"));

    // .py/.md/.sh/.rs are ambiguous ("README.md" vs a Moldovan site). Accepted trade-off: the live Gmail test showed file-name
    // links as real false alarms, so these are reported weakly - but they are always reported, never silently dropped.
    [Theory]
    [InlineData("company.rs")]
    [InlineData("bank.sh")]
    [InlineData("moldbank.md")]
    [InlineData("score.py")]
    public void Ambiguous_code_file_names_are_still_reported(string shownText)
    {
        var codes = Codes(shownText, "https://account-verify-login.com/login");
        Assert.Contains("filename-link-text", codes);
        Assert.DoesNotContain("text-href-mismatch", codes);
    }

    // A look-alike of a brand is never a file name, whatever its TLD.
    [Theory]
    [InlineData("paypa1.md")]
    [InlineData("paypal-secure.sh")]
    public void Brand_lookalikes_on_code_file_tlds_are_a_full_mismatch(string shownText) =>
        Assert.Contains("text-href-mismatch", Codes(shownText, "https://account-verify-login.com/login"));

    // Controls: a scheme, www. or a path makes it a site.
    [Theory]
    [InlineData("mojbank.de")]
    [InlineData("www.mojbank.pl")]
    [InlineData("mojbank.pl/login")]
    [InlineData("www.bank.sh")]
    [InlineData("bank.sh/login")]
    public void Control_same_pair_is_caught_outside_the_file_name_exemption(string shownText) =>
        Assert.Contains("text-href-mismatch", Codes(shownText, "https://account-verify-login.com/login"));
}
