using System.Text.RegularExpressions;

namespace PhishingAnalyser.Core.Rules;

/// <param name="Name">Display name used in explanations.</param>
/// <param name="Domains">Registrable domains the brand legitimately sends from / links to.</param>
/// <param name="Keywords">Lower-case words that identify the brand in a display name or hostname.</param>
public sealed record Brand(string Name, string[] Domains, string[] Keywords);

public sealed record BrandMatch(Brand Brand, string Kind, string Detail);

/// <summary>
/// The brands most commonly impersonated in phishing, plus a few regional ones (Jordan / MENA).
/// </summary>
public sealed class BrandCatalog
{
    public static BrandCatalog Default { get; } = new(
    [
        new("PayPal", ["paypal.com", "paypal.me", "paypalobjects.com"], ["paypal"]),
        new("Microsoft", ["microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com", "sharepoint.com", "onedrive.com", "msn.com"], ["microsoft", "office365", "outlook", "onedrive", "sharepoint"]),
        new("Apple", ["apple.com", "icloud.com", "me.com"], ["apple", "icloud", "itunes"]),
        new("Google", ["google.com", "gmail.com", "googlemail.com", "youtube.com", "gstatic.com", "googleusercontent.com", "withgoogle.com", "googleapis.com", "google-analytics.com", "googletagmanager.com", "doubleclick.net", "goo.gl"], ["google", "gmail"]),
        new("Amazon", ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ae", "amazon.sa", "amazonaws.com", "amazonses.com"], ["amazon"]),
        new("Netflix", ["netflix.com"], ["netflix"]),
        new("Meta", ["facebook.com", "facebookmail.com", "fb.com", "instagram.com", "meta.com", "whatsapp.com"], ["facebook", "instagram", "whatsapp"]),
        new("LinkedIn", ["linkedin.com", "lnkd.in"], ["linkedin"]),
        new("DHL", ["dhl.com", "dhl.de"], ["dhl"]),
        new("FedEx", ["fedex.com"], ["fedex"]),
        new("UPS", ["ups.com"], ["ups"]),
        new("USPS", ["usps.com"], ["usps"]),
        new("Aramex", ["aramex.com"], ["aramex"]),
        new("Chase", ["chase.com", "jpmorgan.com"], ["chase"]),
        new("Bank of America", ["bankofamerica.com", "bofa.com"], ["bankofamerica"]),
        new("Wells Fargo", ["wellsfargo.com"], ["wellsfargo"]),
        new("HSBC", ["hsbc.com", "hsbc.co.uk"], ["hsbc"]),
        new("Arab Bank", ["arabbank.com", "arabbank.jo"], ["arabbank"]),
        new("Dropbox", ["dropbox.com", "dropboxmail.com"], ["dropbox"]),
        new("DocuSign", ["docusign.com", "docusign.net"], ["docusign"]),
        new("Adobe", ["adobe.com"], ["adobe"]),
        new("GitHub", ["github.com", "githubusercontent.com", "github.io"], ["github"]),
        new("Coinbase", ["coinbase.com"], ["coinbase"]),
        new("Binance", ["binance.com"], ["binance"]),
        new("Spotify", ["spotify.com"], ["spotify"]),
        new("eBay", ["ebay.com", "ebay.co.uk"], ["ebay"]),
        new("Steam", ["steampowered.com", "steamcommunity.com"], ["steam"]),
        new("IRS", ["irs.gov"], ["irs"]),
        new("Zain", ["jo.zain.com", "zain.com"], ["zain"]),
        new("Orange", ["orange.jo", "orange.com"], ["orange"]),
    ]);

    private const int MinFuzzyLength = 5;

    public IReadOnlyList<Brand> Brands { get; }

    public BrandCatalog(IReadOnlyList<Brand> brands) => Brands = brands;

    public Brand? OwnerOf(string host) =>
        Brands.FirstOrDefault(b => b.Domains.Any(d => DomainUtils.IsSameOrSubdomain(host, d)));

    /// <summary>
    /// Checks whether a host that is NOT owned by a brand is dressed up as one:
    /// look-alike spelling, brand name inside the domain, or brand domain used as a subdomain.
    /// </summary>
    public BrandMatch? DetectImpersonation(string host)
    {
        host = host.ToLowerInvariant();
        if (DomainUtils.IsIpAddress(host) || OwnerOf(host) is not null)
            return null;

        var registrable = DomainUtils.RegistrableDomain(host);
        var label = DomainUtils.SecondLevelLabel(DomainUtils.ToUnicode(registrable));
        var folded = DomainUtils.FoldHomoglyphs(label);
        var subdomainPart = host.Length > registrable.Length ? host[..^(registrable.Length + 1)] : "";

        foreach (var brand in Brands)
        {
            foreach (var brandDomain in brand.Domains)
            {
                var brandLabel = DomainUtils.SecondLevelLabel(DomainUtils.RegistrableDomain(brandDomain));

                // "paypal.com.account-verify.xyz", "apple.id-check.net"
                if (subdomainPart.Length > 0 &&
                    (subdomainPart.Contains(brandDomain, StringComparison.Ordinal) ||
                     (brandLabel.Length >= 4 &&
                      Regex.IsMatch(subdomainPart, $@"(^|[.\-]){Regex.Escape(brandLabel)}([.\-]|$)"))))
                    return new(brand, "brand-in-subdomain", $"'{host}' puts \"{brandLabel}\" in the subdomain but is really {registrable}");

                // "paypal-secure-login.com", "dhl-parcel.info"
                if (label.Split('-').Contains(brandLabel) ||
                    (brandLabel.Length >= MinFuzzyLength + 1 && folded.Contains(brandLabel, StringComparison.Ordinal) && folded != brandLabel))
                    return new(brand, "brand-in-domain", $"'{registrable}' contains \"{brandLabel}\" but is not a {brand.Name} domain");

                if (brandLabel.Length < MinFuzzyLength)
                    continue;

                // "paypa1.com", "rnicrosoft.com", Cyrillic "аpple.com"
                if (folded == brandLabel && label != brandLabel)
                    return new(brand, "homoglyph", $"'{registrable}' imitates {brandDomain} using look-alike characters");

                // "paypall.com", "amazom.com" - only for longer names, short ones collide with real words
                if (brandLabel.Length > MinFuzzyLength)
                {
                    var distance = Math.Min(DomainUtils.Levenshtein(label, brandLabel), DomainUtils.Levenshtein(folded, brandLabel));
                    if (distance > 0 && distance <= (brandLabel.Length >= 8 ? 2 : 1))
                        return new(brand, "typosquat", $"'{registrable}' is {distance} character(s) away from {brandDomain}");
                }
            }
        }

        return null;
    }

    /// <summary>Finds a brand named in free text such as an email display name ("PayPal Security Team").</summary>
    public Brand? MentionedIn(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        var squashed = Regex.Replace(text.ToLowerInvariant(), @"[^\p{L}\p{N} ]", " ");
        var joined = squashed.Replace(" ", "");
        foreach (var brand in Brands)
        {
            foreach (var keyword in brand.Keywords)
            {
                // Short/ambiguous keywords ("ups", "orange", "apple") must appear as a whole word;
                // longer ones may also match when spaces are removed ("Bank Of America" -> "bankofamerica").
                if (Regex.IsMatch(squashed, $@"\b{Regex.Escape(keyword)}\b") ||
                    (keyword.Length >= 8 && joined.Contains(keyword, StringComparison.Ordinal)))
                    return brand;
            }
        }

        return null;
    }
}
