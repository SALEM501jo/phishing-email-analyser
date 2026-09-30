using System.Text.RegularExpressions;

namespace PhishingAnalyser.Core.Rules;

/// <summary>
/// Rule-based checks on who the email claims to be from.
/// Sender/display-name checks always run; SPF/DKIM/DMARC only when raw headers are supplied,
/// because Gmail's rendered page doesn't expose authentication results.
/// </summary>
public sealed partial class HeaderAnalyser(BrandCatalog brands)
{
    public const string Source = "headers";

    [GeneratedRegex(@"\b(spf|dkim|dmarc|compauth)\s*=\s*([a-z]+)", RegexOptions.IgnoreCase)]
    private static partial Regex AuthMethodResult();

    [GeneratedRegex(@"[\w.+-]+@[\w-]+(\.[\w-]+)+")]
    private static partial Regex EmailInText();

    public ComponentResult Analyse(EmailSubmission email)
    {
        var headers = RawHeaders.Parse(email.RawHeaders);
        var findings = new List<Finding>();

        var senderEmail = FirstAddress(headers.Get("From")) ?? email.SenderEmail;
        var senderName = email.SenderName ?? DisplayName(headers.Get("From"));
        var replyTo = FirstAddress(headers.Get("Reply-To")) ?? email.ReplyTo;
        var senderDomain = DomainUtils.GetEmailDomain(senderEmail);

        if (senderDomain is not null)
        {
            if (brands.DetectImpersonation(senderDomain) is { } match)
                findings.Add(new(Source, "lookalike-sender", $"Sender domain impersonates {match.Brand.Name}: {match.Detail}", 0.65,
                    $"نطاق المرسل ينتحل صفة {match.Brand.Name}: {match.DetailArabic}", match.Registrable));

            if (brands.MentionedIn(senderName) is { } brand && brands.OwnerOf(senderDomain) != brand)
            {
                findings.Add(DomainUtils.IsFreeMail(senderDomain)
                    ? new(Source, "brand-display-freemail", $"Display name claims to be {brand.Name} but the message was sent from a free {senderDomain} account", 0.5,
                        $"اسم المرسل يدّعي أنه {brand.Name} لكن الرسالة أُرسلت من حساب مجاني على {senderDomain}")
                    : new(Source, "brand-display-mismatch", $"Display name claims to be {brand.Name} but the sender domain is {senderDomain}", 0.4,
                        $"اسم المرسل يدّعي أنه {brand.Name} لكن نطاق المرسل هو {senderDomain}"));
            }

            // "service@paypal.com <attacker@evil.xyz>"
            var nameEmailDomain = DomainUtils.GetEmailDomain(EmailInText().Match(senderName ?? "").Value);
            if (nameEmailDomain is not null && DomainUtils.RegistrableDomain(nameEmailDomain) != DomainUtils.RegistrableDomain(senderDomain))
                findings.Add(new(Source, "display-name-address", $"Display name shows the address @{nameEmailDomain} but the real sender is @{senderDomain}", 0.45,
                    $"اسم المرسل يعرض العنوان @{nameEmailDomain} لكن المرسل الحقيقي هو @{senderDomain}"));

            var replyDomain = DomainUtils.GetEmailDomain(replyTo);
            if (replyDomain is not null && DomainUtils.RegistrableDomain(replyDomain) != DomainUtils.RegistrableDomain(senderDomain))
            {
                findings.Add(DomainUtils.IsFreeMail(replyDomain)
                    ? new(Source, "reply-to-freemail", $"Replies are redirected to a free {replyDomain} mailbox, not the sender's domain {senderDomain}", 0.35,
                        $"الردود تُحوَّل إلى بريد مجاني على {replyDomain} وليس إلى نطاق المرسل {senderDomain}")
                    : new(Source, "reply-to-mismatch", $"Reply-To domain ({replyDomain}) differs from the sender domain ({senderDomain})", 0.2,
                        $"نطاق عنوان الرد ({replyDomain}) يختلف عن نطاق المرسل ({senderDomain})"));
            }
        }

        if (headers.IsPresent)
            findings.AddRange(AuthenticationFindings(headers));

        // Authenticated mail from a brand's OWN domain (not a look-alike): evidence for the message, weight 0 here;
        // the scorer decides what it is worth (ScoringOptions.TrustVerifiedBrandSenders).
        if (senderDomain is not null && findings.Any(f => f.Code == "auth-pass") && brands.OwnerOf(senderDomain) is { } owner)
            findings.Add(new(Source, "verified-brand-sender", $"Sent from {owner.Name}'s real domain {senderDomain} (SPF, DKIM and DMARC verified)", 0,
                $"مرسلة من النطاق الحقيقي لـ {owner.Name} ({senderDomain}) وتم التحقق منها عبر SPF وDKIM وDMARC"));

        findings.Sort((a, b) => b.Weight.CompareTo(a.Weight));
        return new ComponentResult(Source, Scoring.NoisyOr(findings), senderDomain is not null, findings);
    }

    private static IEnumerable<Finding> AuthenticationFindings(RawHeaders headers)
    {
        // Gmail stamps its own verdict as the top-most Authentication-Results header; trust only that one,
        // since any header further down could have been written by the sender.
        var authResults = headers.GetAll("Authentication-Results").FirstOrDefault();
        if (authResults is null)
        {
            yield return new(Source, "auth-missing", "No Authentication-Results header was found", 0.1,
                "لم يُعثر على ترويسة نتائج المصادقة (Authentication-Results)");
            yield break;
        }

        var results = AuthMethodResult().Matches(authResults)
            .GroupBy(m => m.Groups[1].Value.ToLowerInvariant())
            .ToDictionary(g => g.Key, g => g.First().Groups[2].Value.ToLowerInvariant());

        var spf = results.GetValueOrDefault("spf", "none");
        var dkim = results.GetValueOrDefault("dkim", "none");
        var dmarc = results.GetValueOrDefault("dmarc", "none");

        if (dmarc == "fail")
            yield return new(Source, "dmarc-fail", "DMARC failed: the sender's domain did not authorise this message", 0.5,
                "فشل فحص DMARC: نطاق المرسل لم يخوّل إرسال هذه الرسالة");
        // Microsoft's composite verdict (Outlook/Office 365 receivers) - fails when the From domain looks spoofed
        // even if the domain publishes no DMARC policy.
        if (results.GetValueOrDefault("compauth") == "fail" && dmarc != "fail")
            yield return new(Source, "compauth-fail", "The receiving server's composite authentication check failed (sender likely spoofed)", 0.35,
                "فشل فحص المصادقة المركّب لدى الخادم المستقبِل (المرسل على الأرجح منتحَل)");
        if (spf is "fail" or "softfail")
            yield return new(Source, "spf-fail", $"SPF {spf}: the sending server is not authorised by the sender's domain", spf == "fail" ? 0.35 : 0.15,
                $"نتيجة SPF هي {spf}: الخادم المرسِل غير مخوّل من نطاق المرسل");
        if (dkim == "fail")
            yield return new(Source, "dkim-fail", "DKIM signature failed verification (message may have been altered or forged)", 0.3,
                "فشل التحقق من توقيع DKIM (قد تكون الرسالة معدّلة أو مزوّرة)");
        if (dkim == "none" && spf is "none" or "neutral")
            yield return new(Source, "auth-none", "Message carries neither a DKIM signature nor an SPF pass", 0.15,
                "الرسالة لا تحمل توقيع DKIM ولم تنجح في فحص SPF");
        if (spf == "pass" && dkim == "pass" && dmarc == "pass")
            yield return new(Source, "auth-pass", "SPF, DKIM and DMARC all passed", 0,
                "نجحت فحوص SPF وDKIM وDMARC جميعها");
    }

    private static string? FirstAddress(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
            return null;
        var match = Regex.Match(headerValue, @"<([^>]+)>");
        return match.Success ? match.Groups[1].Value.Trim() : EmailInText().Match(headerValue).Value.NullIfEmpty();
    }

    private static string? DisplayName(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
            return null;
        var lt = headerValue.IndexOf('<');
        return lt > 0 ? headerValue[..lt].Trim().Trim('"').NullIfEmpty() : null;
    }
}

/// <summary>Minimal RFC 5322 header-block parser (handles folded lines and repeated fields).</summary>
public sealed class RawHeaders
{
    private readonly List<(string Name, string Value)> _fields;

    private RawHeaders(List<(string, string)> fields) => _fields = fields;

    public bool IsPresent => _fields.Count > 0;

    public static RawHeaders Parse(string? raw)
    {
        var fields = new List<(string, string)>();
        if (string.IsNullOrWhiteSpace(raw))
            return new RawHeaders(fields);

        foreach (var line in raw.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0)
                break; // end of header block
            if ((line[0] == ' ' || line[0] == '\t') && fields.Count > 0)
            {
                var (name, value) = fields[^1];
                fields[^1] = (name, value + " " + line.Trim());
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon > 0)
                fields.Add((line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }

        return new RawHeaders(fields);
    }

    public string? Get(string name) => GetAll(name).FirstOrDefault();

    public IEnumerable<string> GetAll(string name) =>
        _fields.Where(f => f.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(f => f.Value);
}

internal static class StringExtensions
{
    public static string? NullIfEmpty(this string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
