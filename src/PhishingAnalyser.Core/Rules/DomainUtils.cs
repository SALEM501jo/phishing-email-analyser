using System.Globalization;
using System.Net;
using System.Net.Mail;
using System.Text;

namespace PhishingAnalyser.Core.Rules;

public static class DomainUtils
{
    // A small subset of the Public Suffix List - enough for the brands and regions this demo cares about.
    // A production build would use the full PSL (e.g. the Nager.PublicSuffix package).
    private static readonly HashSet<string> MultiLabelSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.jp", "com.br", "com.cn",
        "com.jo", "gov.jo", "edu.jo", "net.jo", "org.jo", "com.sa", "gov.sa", "com.eg", "co.in", "co.za",
        "com.tr", "com.mx", "ae.org", "co.il",
    };

    private static readonly HashSet<string> FreeMailDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
        "ymail.com", "aol.com", "icloud.com", "me.com", "mail.com", "gmx.com", "gmx.net", "proton.me",
        "protonmail.com", "yandex.com", "yandex.ru", "zoho.com", "mail.ru",
    };

    public static bool IsFreeMail(string? domain) => domain is not null && FreeMailDomains.Contains(domain);

    /// <summary>Extracts the host from a URL, tolerating scheme-less "www.example.com/..." values.</summary>
    public static string? GetHost(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return null;

        url = url.Trim();
        if (!url.Contains("://", StringComparison.Ordinal))
            url = "http://" + url;

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return null;
        if (uri.Scheme is not ("http" or "https"))
            return null;

        return uri.IdnHost.TrimEnd('.').ToLowerInvariant();
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

    /// <summary>"login.secure.paypal.co.uk" -> "paypal.co.uk"; "evil.xyz" -> "evil.xyz".</summary>
    public static string RegistrableDomain(string host)
    {
        if (IsIpAddress(host))
            return host;

        var labels = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length <= 2)
            return host;

        var lastTwo = $"{labels[^2]}.{labels[^1]}";
        return MultiLabelSuffixes.Contains(lastTwo)
            ? $"{labels[^3]}.{lastTwo}"
            : lastTwo;
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
