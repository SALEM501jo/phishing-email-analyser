using System.Text.RegularExpressions;

namespace PhishingAnalyser.Core.Rules;

/// <param name="Name">Display name used in explanations.</param>
/// <param name="Domains">Registrable domains the brand legitimately sends from / links to.</param>
/// <param name="Keywords">Words that identify the brand in a display name, in English and Arabic (matched after Arabic normalisation).</param>
/// <param name="MatchLabelInDomains">False for brands whose domain label is also a common word ("cab", "stc"), so "cab-booking.com" isn't called impersonation.</param>
public sealed record Brand(string Name, string[] Domains, string[] Keywords, bool MatchLabelInDomains = true);

/// <param name="Kind">brand-in-subdomain, brand-in-domain, homoglyph or typosquat.</param>
/// <param name="Host">The suspicious host as seen.</param>
/// <param name="Registrable">What that host really is (e.g. "account-verify.xyz").</param>
/// <param name="BrandDomain">The genuine domain being imitated.</param>
/// <param name="Distance">Edit distance, for typosquats.</param>
public sealed record BrandMatch(Brand Brand, string Kind, string Host, string Registrable, string BrandDomain, int Distance = 0)
{
    private string BrandLabel => DomainUtils.SecondLevelLabel(DomainUtils.RegistrableDomain(BrandDomain));

    public string Detail => Kind switch
    {
        "brand-in-subdomain" => $"'{Host}' puts \"{BrandLabel}\" in the subdomain but is really {Registrable}",
        "brand-in-domain" => $"'{Registrable}' contains \"{BrandLabel}\" but is not a {Brand.Name} domain",
        "homoglyph" => $"'{Registrable}' imitates {BrandDomain} using look-alike characters",
        _ => $"'{Registrable}' is {Distance} character(s) away from {BrandDomain}",
    };

    public string DetailArabic => Kind switch
    {
        "brand-in-subdomain" => $"النطاق '{Host}' يضع \"{BrandLabel}\" في النطاق الفرعي لكنه في الحقيقة {Registrable}",
        "brand-in-domain" => $"النطاق '{Registrable}' يحتوي على \"{BrandLabel}\" لكنه ليس نطاقًا تابعًا لـ {Brand.Name}",
        "homoglyph" => $"النطاق '{Registrable}' يقلّد {BrandDomain} باستخدام أحرف متشابهة الشكل",
        _ => $"النطاق '{Registrable}' يختلف عن {BrandDomain} بـ {Distance} حرف فقط",
    };
}

/// <summary>
/// The brands most commonly impersonated in phishing, plus regional ones (Jordan / Gulf) with their Arabic names.
/// Arabic keywords that are also everyday words or common first names (e.g. زين "fine"/Zain, اتصالات "communications",
/// كريم Kareem) are deliberately left out or qualified, so a person's name isn't mistaken for a brand.
/// </summary>
public sealed class BrandCatalog
{
    public static BrandCatalog Default { get; } = new(
    [
        new("PayPal", ["paypal.com", "paypal.me", "paypalobjects.com"], ["paypal", "باي بال", "بايبال"]),
        new("Microsoft", ["microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com", "sharepoint.com", "onedrive.com", "msn.com"], ["microsoft", "office365", "outlook", "onedrive", "sharepoint", "مايكروسوفت", "اوتلوك"]),
        new("Apple", ["apple.com", "icloud.com", "me.com"], ["apple", "icloud", "itunes", "ابل ايدي", "اي كلاود"]),
        new("Google", ["google.com", "gmail.com", "googlemail.com", "youtube.com", "gstatic.com", "googleusercontent.com", "withgoogle.com", "googleapis.com", "google-analytics.com", "googletagmanager.com", "doubleclick.net", "goo.gl"], ["google", "gmail", "جوجل", "غوغل", "جيميل"]),
        new("Amazon", ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ae", "amazon.sa", "amazonaws.com", "amazonses.com"], ["amazon", "امازون"]),
        new("Netflix", ["netflix.com"], ["netflix", "نتفلكس", "نتفليكس"]),
        new("Meta", ["facebook.com", "facebookmail.com", "fb.com", "instagram.com", "meta.com", "whatsapp.com"], ["facebook", "instagram", "whatsapp", "فيسبوك", "فيس بوك", "انستغرام", "انستجرام", "واتساب", "واتس اب"]),
        new("LinkedIn", ["linkedin.com", "lnkd.in"], ["linkedin", "لينكد ان"]),
        new("DHL", ["dhl.com", "dhl.de"], ["dhl", "دي اتش ال"]),
        new("FedEx", ["fedex.com"], ["fedex", "فيدكس", "فيديكس"]),
        new("UPS", ["ups.com"], ["ups"]),
        new("USPS", ["usps.com"], ["usps"]),
        new("Aramex", ["aramex.com"], ["aramex", "ارامكس"]),
        new("Chase", ["chase.com", "jpmorgan.com"], ["chase"]),
        new("Bank of America", ["bankofamerica.com", "bofa.com"], ["bankofamerica"]),
        new("Wells Fargo", ["wellsfargo.com"], ["wellsfargo"]),
        new("HSBC", ["hsbc.com", "hsbc.co.uk"], ["hsbc"]),
        new("Arab Bank", ["arabbank.com", "arabbank.jo"], ["arabbank", "arab bank", "البنك العربي"]),
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
        new("Zain", ["jo.zain.com", "zain.com"], ["zain jordan", "zain jo", "زين الاردن", "زين للاتصالات"]),
        new("Orange", ["orange.jo", "orange.com"], ["orange jordan", "orange jo", "اورنج"]),

        // Jordan
        new("Umniah", ["umniah.com"], ["umniah", "امنيه"]),
        new("Jordan Post", ["jopost.com.jo"], ["jordan post", "البريد الاردني"]),
        new("eFAWATEERcom", ["efawateercom.jo"], ["efawateercom", "e fawateercom", "اي فواتيركم", "فواتيركم"]),
        new("CliQ (JoPACC)", ["jopacc.com"], ["jopacc", "cliq", "كليك"]),
        new("Housing Bank", ["hbtf.com"], ["housing bank", "بنك الاسكان"]),
        new("Jordan Islamic Bank", ["jordanislamicbank.com"], ["jordan islamic bank", "البنك الاسلامي الاردني"]),
        new("Cairo Amman Bank", ["cab.jo"], ["cairo amman bank", "بنك القاهره عمان"], MatchLabelInDomains: false),
        new("Capital Bank", ["capitalbank.jo"], ["capital bank", "كابيتال بنك"]),
        new("Bank al Etihad", ["bankaletihad.com"], ["bank al etihad", "بنك الاتحاد"]),

        // Gulf
        new("Al Rajhi Bank", ["alrajhibank.com.sa"], ["al rajhi", "alrajhi", "الراجحي"]),
        new("STC", ["stc.com.sa"], ["stc pay", "اس تي سي"], MatchLabelInDomains: false),
        new("Saudi Post (SPL)", ["splonline.com.sa"], ["saudi post", "البريد السعودي", "سبل"]),
        new("Emirates NBD", ["emiratesnbd.com"], ["emirates nbd", "الامارات دبي الوطني"]),
        new("e& (Etisalat)", ["etisalat.ae", "eand.com"], ["etisalat"]),
        new("noon", ["noon.com"], []),
        new("Careem", ["careem.com"], ["careem"]),
        new("Talabat", ["talabat.com"], ["talabat"]),
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
                     (brand.MatchLabelInDomains && brandLabel.Length >= 4 &&
                      Regex.IsMatch(subdomainPart, $@"(^|[.\-]){Regex.Escape(brandLabel)}([.\-]|$)"))))
                    return new(brand, "brand-in-subdomain", host, registrable, brandDomain);

                if (!brand.MatchLabelInDomains)
                    continue;

                // "paypal-secure-login.com", "dhl-parcel.info"
                if (label.Split('-').Contains(brandLabel) ||
                    (brandLabel.Length >= MinFuzzyLength + 1 && folded.Contains(brandLabel, StringComparison.Ordinal) && folded != brandLabel))
                    return new(brand, "brand-in-domain", host, registrable, brandDomain);

                if (brandLabel.Length < MinFuzzyLength)
                    continue;

                // "paypa1.com", "rnicrosoft.com", Cyrillic "аpple.com"
                if (folded == brandLabel && label != brandLabel)
                    return new(brand, "homoglyph", host, registrable, brandDomain);

                // "paypall.com", "amazom.com" - only for longer names, short ones collide with real words
                if (brandLabel.Length > MinFuzzyLength)
                {
                    var distance = Math.Min(DomainUtils.Levenshtein(label, brandLabel), DomainUtils.Levenshtein(folded, brandLabel));
                    if (distance > 0 && distance <= (brandLabel.Length >= 8 ? 2 : 1))
                        return new(brand, "typosquat", host, registrable, brandDomain, distance);
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

        var squashed = Squash(text);
        var joined = squashed.Replace(" ", "");
        foreach (var brand in Brands)
        {
            foreach (var raw in brand.Keywords)
            {
                var keyword = Squash(raw);
                var keywordJoined = keyword.Replace(" ", "");
                // Short/ambiguous keywords ("ups", "orange", "apple") must appear as whole words;
                // longer ones may also match when spaces are removed ("Bank Of America" -> "bankofamerica").
                if (Regex.IsMatch(squashed, $@"\b{Regex.Escape(keyword)}\b") ||
                    (keywordJoined.Length >= 8 && joined.Contains(keywordJoined, StringComparison.Ordinal)))
                    return brand;
            }
        }

        return null;
    }

    /// <summary>Lower-case, Arabic-normalised, punctuation to spaces, single-spaced.</summary>
    private static string Squash(string text) =>
        Regex.Replace(Regex.Replace(PhishingAnalyser.Core.Content.ArabicText.Normalize(text.ToLowerInvariant()), @"[^\p{L}\p{N} ]", " "), @"\s+", " ").Trim();
}
