using System.Text.RegularExpressions;
using System.Web;

namespace PhishingAnalyser.Core.Rules;

/// <summary>Rule-based checks on every hyperlink in the email.</summary>
public sealed partial class LinkAnalyser(BrandCatalog brands)
{
    public const string Source = "links";
    private const int MaxLinks = 200;

    private static readonly HashSet<string> Shorteners = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
        "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "bl.ink", "s.id", "v.gd", "shorte.st", "adf.ly", "qrco.de",
    };

    // TLDs heavily over-represented in phishing/abuse feeds (Spamhaus, Interisle reports).
    private static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "support",
        "rest", "fit", "cam", "quest", "sbs", "cfd", "icu", "buzz", "monster", "lol", "live", "online", "shop",
    };

    // Gmail and other providers wrap links in redirectors; unwrap to judge the real destination.
    private static readonly (string Host, string Param)[] Redirectors =
    [
        ("www.google.com", "q"), ("google.com", "q"), ("safelinks.protection.outlook.com", "url"),
    ];

    [GeneratedRegex(@"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", RegexOptions.IgnoreCase)]
    private static partial Regex LooksLikeUrl();

    public ComponentResult Analyse(IReadOnlyList<EmailLink>? links)
    {
        if (links is null || links.Count == 0)
            return new ComponentResult(Source, 0, true, []);

        var findings = new List<Finding>();
        foreach (var link in links.Take(MaxLinks))
            findings.AddRange(AnalyseLink(link));

        // One strong signal per rule type is enough; 30 tracking links through the same shortener shouldn't add up.
        var distinct = findings
            .GroupBy(f => f.Code)
            .Select(g => g.OrderByDescending(f => f.Weight).First())
            .OrderByDescending(f => f.Weight)
            .ToList();

        return new ComponentResult(Source, Scoring.NoisyOr(distinct), true, distinct);
    }

    private IEnumerable<Finding> AnalyseLink(EmailLink link)
    {
        var href = Unwrap(link.Href);
        if (href.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ||
            href.StartsWith("tel:", StringComparison.OrdinalIgnoreCase) ||
            href.StartsWith('#'))
            yield break;

        var host = DomainUtils.GetHost(href);
        if (host is null)
            yield break;

        if (DomainUtils.IsIpAddress(host))
        {
            yield return new(Source, "ip-url", $"Link points at a raw IP address ({host}) instead of a domain", 0.45);
            yield break;
        }

        if (host.Contains("xn--", StringComparison.Ordinal))
            yield return new(Source, "punycode", $"Link uses an internationalised (punycode) domain that renders as '{DomainUtils.ToUnicode(host)}'", 0.3);

        if (brands.DetectImpersonation(host) is { } match)
            yield return new(Source, "lookalike-domain", $"Link domain impersonates {match.Brand.Name}: {match.Detail}", 0.6);

        if (Shorteners.Contains(host))
            yield return new(Source, "shortener", $"Link hides its destination behind a URL shortener ({host})", 0.15);

        if (SuspiciousTlds.Contains(DomainUtils.Tld(host)))
            yield return new(Source, "suspicious-tld", $"Link uses a TLD frequently abused for phishing (.{DomainUtils.Tld(host)})", 0.12);

        if (href.Contains('@') && Uri.TryCreate(href, UriKind.Absolute, out var uri) && uri.UserInfo.Length > 0)
            yield return new(Source, "userinfo-url", $"Link hides its real host after an '@' ({host})", 0.4);

        if (TextDomainMismatch(link.Text, host) is { } shownHost)
            yield return new(Source, "text-href-mismatch", $"Link text shows '{shownHost}' but actually goes to '{host}'", 0.45);
    }

    /// <summary>If the visible link text is itself a URL/domain, returns it when it doesn't match the real host.</summary>
    private static string? TextDomainMismatch(string? text, string actualHost)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        text = text.Trim();
        if (text.Contains(' ') || !LooksLikeUrl().IsMatch(text))
            return null;

        var shownHost = DomainUtils.GetHost(text);
        if (shownHost is null)
            return null;

        return DomainUtils.RegistrableDomain(shownHost) == DomainUtils.RegistrableDomain(actualHost) ? null : shownHost;
    }

    internal static string Unwrap(string href)
    {
        href = href.Trim();
        if (!Uri.TryCreate(href, UriKind.Absolute, out var uri))
            return href;

        foreach (var (host, param) in Redirectors)
        {
            if (!DomainUtils.IsSameOrSubdomain(uri.Host, host))
                continue;
            if (host.StartsWith("www.google", StringComparison.Ordinal) || host == "google.com")
            {
                if (!uri.AbsolutePath.Equals("/url", StringComparison.Ordinal))
                    continue;
            }

            var target = HttpUtility.ParseQueryString(uri.Query)[param];
            if (!string.IsNullOrEmpty(target))
                return target;
        }

        return href;
    }
}
