using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Mail;
using System.Text;
using Nager.PublicSuffix;
using Nager.PublicSuffix.Models;
using Nager.PublicSuffix.RuleProviders;

namespace PhishingAnalyser.Core.Rules;

public static class DomainUtils
{
    // Fallback only (if the bundled Public Suffix List can't be loaded): the multi-label suffixes that matter most here.
    private static readonly HashSet<string> MultiLabelSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.jp", "com.br", "com.cn",
        "com.jo", "gov.jo", "edu.jo", "net.jo", "org.jo", "com.sa", "gov.sa", "com.eg", "co.in", "co.za",
        "com.tr", "com.mx", "ae.org", "co.il",
    };

    /// <summary>
    /// The full Public Suffix List (bundled, ~10k rules incl. its PRIVATE section of hosting platforms), so
    /// "x.pages.dev" is correctly a site of its own and exotic suffixes like "gov.jo" or "com.sa" parse right.
    /// </summary>
    private static readonly Lazy<DomainParser?> Psl = new(() =>
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Data", "public_suffix_list.dat");
        if (!File.Exists(path))
            return null;
        var provider = new LocalFileRuleProvider(path);
        provider.BuildAsync().GetAwaiter().GetResult();
        return new DomainParser(provider);
    });

    private static readonly HashSet<string> FreeMailDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
        "ymail.com", "aol.com", "icloud.com", "me.com", "mail.com", "gmx.com", "gmx.net", "proton.me",
        "protonmail.com", "yandex.com", "yandex.ru", "zoho.com", "mail.ru",
    };

    public static bool IsFreeMail(string? domain) => domain is not null && FreeMailDomains.Contains(domain);

    /// <summary>
    /// Uri.TryCreate that never throws. .NET 8's own TryCreate throws IndexOutOfRangeException (instead of returning false)
    /// for implicit-file/UNC strings whose only host character is a bidi mark ("file://" + U+200F, "//" + U+200F) - found
    /// by the red-team review. Every URL here is attacker-written, so a parse failure means "not a URL", never a crash.
    /// </summary>
    public static bool TryCreateUri(string? value, [NotNullWhen(true)] out Uri? uri)
    {
        try
        {
            return Uri.TryCreate(value, UriKind.Absolute, out uri);
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentException or UriFormatException)
        {
            uri = null;
            return false;
        }
    }

    /// <summary>The Public Suffix List parse, or null. Nager validates with Uri.TryCreate, so it inherits that throw.</summary>
    private static DomainInfo? ParseDomain(string host)
    {
        if (Psl.Value is not { } parser)
            return null;
        try
        {
            return parser.TryParse(host, out var info) ? info : null;
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentException or UriFormatException)
        {
            return null;
        }
    }

    /// <summary>Extracts the host from a URL, tolerating scheme-less "www.example.com/..." values.</summary>
    public static string? GetHost(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return null;

        url = BrowserForm(url.Trim());
        if (!url.Contains("://", StringComparison.Ordinal))
            url = "http://" + url;

        if (!TryCreateUri(url, out var uri))
            return null;
        if (uri.Scheme is not ("http" or "https"))
            return null;

        try
        {
            return uri.IdnHost.TrimEnd('.').ToLowerInvariant();
        }
        catch (UriFormatException)
        {
            // Characters that are illegal in international domain names (found in real phishing). Treated as
            // unparseable - which fails closed everywhere (no trust, no brand match) - instead of crashing the verdict.
            return null;
        }
    }

    /// <summary>
    /// Rewrites the forms browsers accept but .NET's Uri reads differently: tabs/newlines inside (browsers drop them),
    /// backslashes ("http:\\host\path"), protocol-relative "//host" and "https:host" / "https:/host". Without this,
    /// a raw-IP link written that way got no finding at all (found by the fuzzer).
    /// </summary>
    private static string BrowserForm(string url)
    {
        url = url.Replace("\t", "").Replace("\r", "").Replace("\n", "");
        var queryAt = url.IndexOfAny(['?', '#']);
        url = queryAt < 0 ? url.Replace('\\', '/') : url[..queryAt].Replace('\\', '/') + url[queryAt..];
        if (url.StartsWith("//", StringComparison.Ordinal))
            return "https:" + url;
        foreach (var scheme in (string[])["https:", "http:"])
            if (url.StartsWith(scheme, StringComparison.OrdinalIgnoreCase) && !url.AsSpan(scheme.Length).StartsWith("//"))
                return scheme + "//" + url[scheme.Length..].TrimStart('/');
        return url;
    }

    public static string? GetEmailDomain(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;
        try
        {
            return new MailAddress(email.Trim()).Host.ToLowerInvariant();
        }
        catch (FormatException)
        {
            var at = email.LastIndexOf('@');
            return at >= 0 && at < email.Length - 1 ? email[(at + 1)..].Trim().Trim('>').ToLowerInvariant() : null;
        }
    }

    public static bool IsIpAddress(string host) =>
        IPAddress.TryParse(host.Trim('[', ']'), out _);

    /// <summary>
    /// True when the host ends in a real top-level domain from the Public Suffix List. "december-chart-inputs.csv"
    /// looks like a domain but isn't - found live, where a file name in link text was reported as a deceptive link.
    /// (".zip" and ".mov" ARE real TLDs, so "invoice.zip" still counts - correctly, it's a known lure.)
    /// </summary>
    public static bool HasKnownTld(string host)
    {
        if (IsIpAddress(host))
            return false;
        if (Psl.Value is null)
            return true; // without the list, keep the old behaviour rather than silently disabling the rule
        return ParseDomain(host)?.TopLevelDomainRule is { } rule && rule.Name != "*";
    }

    /// <summary>"login.secure.paypal.co.uk" -> "paypal.co.uk"; "paypal-login.pages.dev" -> itself (pages.dev is a hosting platform).</summary>
    public static string RegistrableDomain(string host)
    {
        if (IsIpAddress(host))
            return host;

        if (ParseDomain(host) is { } info && !string.IsNullOrEmpty(info.RegistrableDomain))
            return info.RegistrableDomain;

        var labels = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length <= 2)
            return host;

        var lastTwo = $"{labels[^2]}.{labels[^1]}";
        return MultiLabelSuffixes.Contains(lastTwo)
            ? $"{labels[^3]}.{lastTwo}"
            : lastTwo;
    }

    /// <summary>
    /// The hosting-platform suffix when <paramref name="host"/> is a site published on a platform from the PSL's
    /// PRIVATE section (e.g. "github.io" for "someone.github.io"); null otherwise.
    /// </summary>
    public static string? PrivatePlatformSuffix(string host)
    {
        if (IsIpAddress(host) || ParseDomain(host) is not { TopLevelDomainRule: not null } info)
            return null;
        return info.TopLevelDomainRule.Division == TldRuleDivision.Private && !string.IsNullOrEmpty(info.RegistrableDomain)
            ? info.TopLevelDomain
            : null;
    }

    /// <summary>The label people actually read: "paypal" for "paypal.co.uk".</summary>
    public static string SecondLevelLabel(string registrableDomain) =>
        registrableDomain.Split('.')[0];

    public static string Tld(string host) => host[(host.LastIndexOf('.') + 1)..];

    public static bool IsSameOrSubdomain(string host, string domain) =>
        host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);

    /// <summary>Decodes punycode (xn--) hosts so homoglyph domains can be shown to the user.</summary>
    public static string ToUnicode(string host)
    {
        try
        {
            return new IdnMapping().GetUnicode(host);
        }
        catch (ArgumentException)
        {
            return host;
        }
    }

    /// <summary>Folds common visual substitutions: paypa1 -> paypal, rnicrosoft -> microsoft, g00gle -> google.</summary>
    public static string FoldHomoglyphs(string label)
    {
        var sb = new StringBuilder(label.ToLowerInvariant())
            .Replace("rn", "m").Replace("vv", "w")
            .Replace('0', 'o').Replace('1', 'l').Replace('3', 'e').Replace('5', 's')
            .Replace('4', 'a').Replace('7', 't').Replace('@', 'a').Replace("-", "");
        // Latin look-alikes from Cyrillic/Greek that survive IDN decoding.
        return sb.Replace('а', 'a').Replace('е', 'e').Replace('о', 'o').Replace('р', 'p')
                 .Replace('с', 'c').Replace('х', 'x').Replace('у', 'y').Replace('і', 'i')
                 .Replace('ο', 'o').Replace('ν', 'v').ToString();
    }

    public static int Levenshtein(string a, string b)
    {
        if (a.Length == 0) return b.Length;
        if (b.Length == 0) return a.Length;

        var previous = new int[b.Length + 1];
        var current = new int[b.Length + 1];
        for (var j = 0; j <= b.Length; j++)
            previous[j] = j;

        for (var i = 1; i <= a.Length; i++)
        {
            current[0] = i;
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                current[j] = Math.Min(Math.Min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost);
            }
            (previous, current) = (current, previous);
        }

        return previous[b.Length];
    }
}
