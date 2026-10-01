using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class RedTeam_link_evasion_1
{
    [Fact]
    public void Brand_lookalike_text_through_the_attackers_own_tracker_stays_a_full_mismatch()
    {
        var links = new LinkAnalyser(BrandCatalog.Default);
        // Sent from the attacker's own domain, routed through the attacker's own SendGrid tracker. The text reads as
        // paypal.com but is a look-alike host, so OwnerOf(shownHost) is null and the finding is wrongly downgraded.
        var codes = links.Analyse(
            new[] { new EmailLink("www.paypal.com.secure-login.net", "https://u123.ct.sendgrid.net/ls/click?x=evil") },
            DomainUtils.GetEmailDomain("billing@notify.attacker.com")).Findings.Select(f => f.Code).ToArray();
        Assert.Contains("text-href-mismatch", codes);
    }

    [Fact]
    public void Typosquat_brand_text_through_the_attackers_own_tracker_stays_a_full_mismatch()
    {
        var links = new LinkAnalyser(BrandCatalog.Default);
        var codes = links.Analyse(
            new[] { new EmailLink("paypa1.com", "https://u123.ct.sendgrid.net/ls/click?x=evil") },
            DomainUtils.GetEmailDomain("billing@notify.attacker.com")).Findings.Select(f => f.Code).ToArray();
        Assert.Contains("text-href-mismatch", codes);
    }
}
