using System.Text.RegularExpressions;
using System.Web;

namespace PhishingAnalyser.Core.Rules;

/// <summary>Rule-based checks on every hyperlink in the email.</summary>
public sealed partial class LinkAnalyser(BrandCatalog brands)
{
    public const string Source = "links";
    private const int MaxLinks = 200;

    public static bool IsShortener(string host) => Shorteners.Contains(host);

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

    // Mailing services and security gateways rewrite every link for click tracking or scanning, so the destination
    // can't be seen - on the owner's real mailbox these caused most "text shows X, goes to Y" false alarms.
    // Phishers use the same services, so a tracked link is still reported, just weakly - unless its text claims a
    // brand the sender isn't (then it stays a full mismatch).
    private static readonly string[] ClickTrackers =
    [
        "mandrillapp.com", "sendgrid.net", "awstrack.me", "list-manage.com", "mcsv.net", "mailchi.mp", "hubspotlinks.com",
        "mailgun.org", "sparkpostmail.com", "klaviyomail.com", "cmail19.com", "cmail20.com", "exacttarget.com", "rs6.net",
        "fireeye.com", "urldefense.com", "urldefense.proofpoint.com", "mimecastprotect.com", "cudasvc.com",
    ];

    [GeneratedRegex(@"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", RegexOptions.IgnoreCase)]
    private static partial Regex LooksLikeUrl();

    /// <param name="senderDomain">The From domain, when known: a platform's own notification routing links through its own
    /// redirector (an X notification via twitter.com) is not deception.</param>
    public ComponentResult Analyse(IReadOnlyList<EmailLink>? links, string? senderDomain = null)
    {
        if (links is null || links.Count == 0)
            return new ComponentResult(Source, 0, true, []);

        var findings = new List<Finding>();
        foreach (var link in links.Take(MaxLinks))
            findings.AddRange(AnalyseLink(link, senderDomain));

        // One strong signal per rule type is enough; 30 tracking links through the same shortener shouldn't add up.
        var distinct = findings
            .GroupBy(f => f.Code)
            .Select(g => g.OrderByDescending(f => f.Weight).First())
            .OrderByDescending(f => f.Weight)
            .ToList();

        return new ComponentResult(Source, Scoring.NoisyOr(distinct), true, distinct);
    }

    private IEnumerable<Finding> AnalyseLink(EmailLink link, string? senderDomain)
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
            yield return new(Source, "ip-url", $"Link points at a raw IP address ({host}) instead of a domain", 0.45,
                $"الرابط يشير إلى عنوان IP مباشر ({host}) بدلًا من اسم نطاق");
            yield break;
        }

        if (host.Contains("xn--", StringComparison.Ordinal))
            yield return new(Source, "punycode", $"Link uses an internationalised (punycode) domain that renders as '{DomainUtils.ToUnicode(host)}'", 0.3,
                $"الرابط يستخدم نطاقًا دوليًا (punycode) يظهر بالشكل '{DomainUtils.ToUnicode(host)}'");

        var impersonation = brands.DetectImpersonation(host);
        if (impersonation is { } match)
            yield return new(Source, "lookalike-domain", $"Link domain impersonates {match.Brand.Name}: {match.Detail}", 0.6,
                $"نطاق الرابط ينتحل صفة {match.Brand.Name}: {match.DetailArabic}", match.Registrable);

        // Free hosting / form / file-sharing platforms: legitimate services, but anyone can publish there -
        // attackers use them precisely because their domains look trustworthy and aren't on blocklists.
        if (brands.UserContentPlatform(host) is { } platform)
        {
            yield return new(Source, "user-content-host", $"Link leads to a page anyone can publish on {platform} ({host}), not an official site", 0.15,
                $"الرابط يؤدي إلى صفحة يمكن لأي شخص نشرها على {platform} ({host}) وليس إلى موقع رسمي");

            var platformOwner = brands.OwnerOf(DomainUtils.RegistrableDomain(platform));
            var userPart = Uri.TryCreate(href, UriKind.Absolute, out var parsed)
                ? host[..Math.Max(0, host.Length - platform.Length)] + parsed.PathAndQuery
                : href;
            if (impersonation is null && brands.MentionedInUrlPart(userPart) is { } named && named != platformOwner)
                yield return new(Source, "brand-on-user-content", $"A page on {platform} presents itself as {named.Name} - brands don't host their sign-in or payment pages there", 0.5,
                    $"صفحة على {platform} تقدّم نفسها على أنها {named.Name} - الجهات الرسمية لا تستضيف صفحات الدخول أو الدفع هناك");
        }

        if (Shorteners.Contains(host))
            yield return new(Source, "shortener", $"Link hides its destination behind a URL shortener ({host})", 0.15,
                $"الرابط يخفي وجهته الحقيقية خلف خدمة تقصير روابط ({host})");

        if (SuspiciousTlds.Contains(DomainUtils.Tld(host)))
            yield return new(Source, "suspicious-tld", $"Link uses a TLD frequently abused for phishing (.{DomainUtils.Tld(host)})", 0.12,
                $"الرابط يستخدم امتداد نطاق شائع الاستخدام في التصيّد (.{DomainUtils.Tld(host)})");

        if (href.Contains('@') && Uri.TryCreate(href, UriKind.Absolute, out var uri) && uri.UserInfo.Length > 0)
            yield return new(Source, "userinfo-url", $"Link hides its real host after an '@' ({host})", 0.4,
                $"الرابط يخفي النطاق الحقيقي بعد الرمز '@' ({host})");

        if (TextDomainMismatch(link.Text, host) is { } shownHost && !SameOwner(shownHost, host))
        {
            var senderBrand = senderDomain is null ? null : brands.OwnerOf(senderDomain);
            var shownBrand = brands.OwnerOf(shownHost);
            var platformRedirect = senderBrand is not null && brands.OwnerOf(host) == senderBrand && brands.UserContentPlatform(host) is null;
            var tracked = ClickTrackers.Any(t => DomainUtils.IsSameOrSubdomain(host, t));
            if (platformRedirect)
            {
                // e.g. an X notification showing a posted youtu.be link, routed through twitter.com - the platform's own redirector.
            }
            else if (tracked && (shownBrand is null || shownBrand == senderBrand))
                yield return new(Source, "tracked-link", $"Link text shows '{shownHost}' but the click goes through the tracking service {host}", 0.1,
                    $"نص الرابط يعرض '{shownHost}' لكن النقرة تمر عبر خدمة التتبع {host}");
            else
                yield return new(Source, "text-href-mismatch", $"Link text shows '{shownHost}' but actually goes to '{host}'", 0.45,
                    $"نص الرابط يعرض '{shownHost}' لكنه في الحقيقة يذهب إلى '{host}'");
        }
    }

    /// <summary>If the visible link text is itself a URL/domain, returns it when it doesn't match the real host.</summary>
    /// <summary>
    /// "facebook.com" text linking to facebookmail.com, or "x.com" to t.co, is the same company, not deception.
    /// Never for user-content hosts (amazonaws.com, github.io...): anyone can publish there under the brand's domain.
    /// </summary>
    private bool SameOwner(string shownHost, string actualHost) =>
        brands.UserContentPlatform(actualHost) is null
        && brands.OwnerOf(shownHost) is { } owner && brands.OwnerOf(actualHost) == owner;

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
