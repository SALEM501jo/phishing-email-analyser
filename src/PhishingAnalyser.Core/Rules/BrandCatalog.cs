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
/// The brands most commonly impersonated in phishing (global + Jordan/Gulf, English + Arabic names) and the
/// "user-content" hosts where anyone can publish under a platform's domain. Loaded from Data/brands.json so the
/// list can be extended (local banks, a university, an employer) without recompiling.
/// </summary>
public sealed class BrandCatalog
{
    private sealed record CatalogFile(List<Brand> Brands, List<string> UserContentHosts);

    public static string DefaultPath => Path.Combine(AppContext.BaseDirectory, "Data", "brands.json");

    public static BrandCatalog Default { get; } = Load(DefaultPath);

    public static BrandCatalog Load(string path)
    {
        var file = System.Text.Json.JsonSerializer.Deserialize<CatalogFile>(File.ReadAllText(path),
            new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))
            ?? throw new InvalidDataException($"Empty brand catalogue: {path}");
        return new BrandCatalog(file.Brands, file.UserContentHosts);
    }

    private const int MinFuzzyLength = 5;

    public IReadOnlyList<Brand> Brands { get; }
    public IReadOnlyList<string> UserContentHosts { get; }

    public BrandCatalog(IReadOnlyList<Brand> brands, IReadOnlyList<string>? userContentHosts = null)
    {
        Brands = brands;
        UserContentHosts = userContentHosts ?? [];
    }

    /// <summary>
    /// The platform a host belongs to when anyone can publish there (someone.github.io, x.pages.dev,
    /// sites.google.com/...). Content on these hosts is not the platform's own, so it gets no brand trust.
    /// </summary>
    public string? UserContentPlatform(string host) =>
        DomainUtils.PrivatePlatformSuffix(host)
        ?? UserContentHosts.FirstOrDefault(h => DomainUtils.IsSameOrSubdomain(host, h));

    /// <summary>The brand that genuinely owns this host - never for user-published content on a platform.</summary>
    public Brand? OwnerOf(string host) =>
        UserContentPlatform(host) is not null
            ? null
            : Brands.FirstOrDefault(b => b.Domains.Any(d => DomainUtils.IsSameOrSubdomain(host, d)));

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
        // e.g. sites.google.com: the host really is Google's, so it can't imitate Google - but what's published
        // there is anyone's; LinkAnalyser checks that part (path) separately.
        if (Brands.Any(b => b.Domains.Any(d => DomainUtils.IsSameOrSubdomain(registrable, d))))
            return null;
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

    /// <summary>
    /// A brand named inside a URL's user-controlled part (path, query or the site name on a hosting platform),
    /// e.g. "sites.google.com/view/paypal-account-review" or "forms.office.com/r/arabbank-verify".
    /// Only distinctive names (5+ characters or matchLabelInDomains) to avoid matching ordinary words.
    /// </summary>
    public Brand? MentionedInUrlPart(string urlPart)
    {
        var tokens = Regex.Split(urlPart.ToLowerInvariant(), @"[^a-z0-9]+").Where(t => t.Length > 0).ToArray();
        var joined = string.Concat(tokens);
        foreach (var brand in Brands)
        {
            foreach (var domain in brand.Domains)
            {
                var label = DomainUtils.SecondLevelLabel(DomainUtils.RegistrableDomain(domain));
                if (label.Length < 5 || !brand.MatchLabelInDomains)
                    continue;
                if (tokens.Contains(label) || (label.Length >= 7 && joined.Contains(label, StringComparison.Ordinal)))
                    return brand;
            }
        }
        return null;
    }

    /// <summary>Lower-case, Arabic-normalised, punctuation to spaces, single-spaced.</summary>
    private static string Squash(string text) =>
        Regex.Replace(Regex.Replace(PhishingAnalyser.Core.Content.ArabicText.Normalize(text.ToLowerInvariant()), @"[^\p{L}\p{N} ]", " "), @"\s+", " ").Trim();
}
