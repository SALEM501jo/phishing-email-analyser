using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Web;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;
using Xunit.Abstractions;

namespace PhishingAnalyser.Tests;

/// <summary>
/// Deterministic grammar fuzzer for <see cref="EmailAnalyser.Analyse(EmailSubmission)"/>. Every email is built from a
/// per-iteration seed (MasterSeed + iteration), so any failure printed below is reproduced by <see cref="Generate"/> with
/// that seed. Inputs stay inside the API's limits (AnalyseRequest.Validate + Kestrel's 512 KB request body): body up to
/// 100k chars, raw headers up to 64k, up to 500 links, 100 attachments (names clamped to 255 like the API), 20 QR URLs of
/// up to 2048 chars.
///
/// Invariants per email: never throws; under 1 s (bodies up to 60k, re-measured once to rule out a GC pause);
/// score in [0,1] and the verdict matches the thresholds; the same input gives the same result; and a
/// "verified-brand-sender" finding never coexists with a non-neutral link (QR destinations included) that is
/// unparseable or off the sender brand's domains.
/// </summary>
[Collection(TimingSensitive.Name)]
public class FuzzEmailAnalyserTests(ITestOutputHelper output)
{
    private const int MasterSeed = 20261003;
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(10); // ~60 s for a deep run
    private const int MaxMillis = 1000; // generous: the suite runs in parallel and CI runners are slower

    private static readonly ScoringOptions Options = new()
    {
        TrustVerifiedBrandSenders = true, RequireCorroboration = true, TrustEstablishedSenders = true,
    };

    private static EmailAnalyser NewAnalyser() => new(new UnavailableContentClassifier(), new HeaderAnalyser(BrandCatalog.Default),
        new LinkAnalyser(BrandCatalog.Default), Options);

    [Fact]
    public void Analyser_invariants_hold_for_hostile_emails()
    {
        var analyser = NewAnalyser();
        analyser.Analyse(Generate(new Random(1))); // warm-up: regex construction, PSL load, JIT

        var failures = new Dictionary<string, List<string>>();
        void Fail(string invariant, string detail)
        {
            if (!failures.TryGetValue(invariant, out var list))
                failures[invariant] = list = [];
            list.Add(detail);
        }

        var total = Stopwatch.StartNew();
        long slowestMs = 0;
        var slowestIteration = -1;
        var iterations = 0;
        var verifiedSeen = 0;
        for (; total.Elapsed < Budget; iterations++)
        {
            var seed = MasterSeed + iterations;
            var email = Generate(new Random(seed));
            AnalysisResult first, second;
            long ms;
            try
            {
                var sw = Stopwatch.StartNew();
                first = analyser.Analyse(email);
                ms = sw.ElapsedMilliseconds;
                if (ms > MaxMillis)
                {
                    sw.Restart();
                    analyser.Analyse(email);
                    ms = Math.Min(ms, sw.ElapsedMilliseconds);
                }
                second = analyser.Analyse(email);
            }
            catch (Exception e)
            {
                Fail("never throws", $"seed {seed}: {e.GetType().Name}: {e.Message}\n{Describe(email)}");
                continue;
            }

            if (ms > slowestMs)
                (slowestMs, slowestIteration) = (ms, seed);
            if ((email.Body?.Length ?? 0) <= 60_000 && ms > MaxMillis)
                Fail($"under {MaxMillis} ms", $"seed {seed}: {ms} ms\n{Describe(email)}");

            if (first.Score is < 0 or > 1 || double.IsNaN(first.Score))
                Fail("score in [0,1]", $"seed {seed}: score {first.Score}");
            var expected = first.Score >= Options.PhishingThreshold ? Verdicts.Phishing
                : first.Score >= Options.SuspiciousThreshold ? Verdicts.Suspicious : Verdicts.Safe;
            if (first.Verdict != expected)
                Fail("verdict matches thresholds", $"seed {seed}: score {first.Score} verdict {first.Verdict}");

            if (Fingerprint(first) != Fingerprint(second))
                Fail("deterministic", $"seed {seed}\n{Describe(email)}");

            if (first.Breakdown.Headers.Findings.FirstOrDefault(f => f.Code == "verified-brand-sender") is { } verified)
            {
                verifiedSeen++;
                if (OffBrandLink(email, verified) is { } bad)
                    Fail("verified brand only with on-brand links", $"seed {seed}: {verified.Message}; offending link {Escape(bad)}");
            }
        }

        output.WriteLine($"{iterations} emails in {total.Elapsed.TotalSeconds:0.0} s; {verifiedSeen} carried verified-brand-sender; " +
                         $"slowest {slowestMs} ms (seed {slowestIteration})");
        foreach (var (invariant, list) in failures)
        {
            output.WriteLine($"VIOLATED: {invariant} ({list.Count}x)");
            foreach (var d in list.Take(3))
                output.WriteLine("  " + d.Replace("\n", "\n    "));
        }
        Assert.True(failures.Count == 0, "Violated: " + string.Join(", ", failures.Select(f => $"{f.Key} ({f.Value.Count}x)")));
    }

    /// <summary>
    /// The slowest sender/reply-to domains we could construct for BrandCatalog.DetectImpersonation, timed directly and through
    /// Analyse. Reported, not asserted (the assertion lives in the minimal test FuzzFindingsTests.Long_sender_domain_*).
    /// </summary>
    [Fact]
    public void Pathological_sender_domains_timing_report()
    {
        var analyser = NewAnalyser();
        analyser.Analyse(Generate(new Random(1)));
        const int n = 60_000; // a RawHeaders From line fits this; the SenderEmail field allows ~500k (512 KB request)
        var cases = new (string Name, string Domain)[]
        {
            ("one long label", new string('a', n) + ".com"),
            ("long hyphenated label", string.Concat(Enumerable.Repeat("a-", n / 2)) + ".com"),
            ("long homoglyph label", string.Concat(Enumerable.Repeat("rn", n / 2)) + ".com"),
            ("long punycode label", "xn--" + new string('a', n) + ".com"),
            ("many labels", string.Concat(Enumerable.Repeat("a.", n / 2)) + "com"),
            ("many punycode labels", string.Concat(Enumerable.Repeat("xn--a.", n / 6)) + "com"),
            ("many Cyrillic labels", string.Concat(Enumerable.Repeat("а.", n / 2)) + "com"),
            ("many brand labels", string.Concat(Enumerable.Repeat("paypal.", n / 7)) + "evil.com"),
            ("many labels on a platform", string.Concat(Enumerable.Repeat("a.", n / 2)) + "github.io"),
            ("dots only", new string('.', n)),
        };
        foreach (var (name, domain) in cases)
        {
            var sw = Stopwatch.StartNew();
            BrandCatalog.Default.DetectImpersonation(domain);
            var direct = sw.ElapsedMilliseconds;
            sw.Restart();
            analyser.Analyse(new EmailSubmission { SenderEmail = "x@" + domain, ReplyTo = "y@" + domain });
            output.WriteLine($"{name,-28} {domain.Length,7} chars  DetectImpersonation {direct,6} ms  Analyse(sender+reply-to) {sw.ElapsedMilliseconds,6} ms");
        }
    }

    // ---------------------------------------------------------------- oracle

    /// <summary>A link (QR destinations included) that should have prevented "verified-brand-sender", or null.</summary>
    private static string? OffBrandLink(EmailSubmission email, Finding verified)
    {
        var brand = BrandCatalog.Default.Brands.FirstOrDefault(b => verified.Message.StartsWith($"Sent from {b.Name}'s ", StringComparison.Ordinal));
        if (brand is null)
            return "(could not tell the brand from: " + verified.Message + ")";
        var hrefs = (email.QrCodeUrls ?? []).Take(10).Select(u => (Kind: "QR URL", Href: u))
            .Concat((email.Links ?? []).Select(l => (Kind: $"link (text '{l.Text}')", l.Href)));
        foreach (var (kind, href) in hrefs)
        {
            if (LinkAnalyser.IsNeutralLink(href))
                continue;
            var host = DomainUtils.GetHost(LinkAnalyser.Unwrap(href));
            if (host is null || BrandCatalog.Default.UserContentPlatform(host) is not null
                || !brand.Domains.Any(d => DomainUtils.IsSameOrSubdomain(host, d)))
                return $"{kind}: {href}";
        }
        return null;
    }

    private static string Fingerprint(AnalysisResult r)
    {
        var sb = new StringBuilder();
        sb.Append(r.Verdict).Append('|').Append(r.Score.ToString("R", CultureInfo.InvariantCulture)).Append('|').Append(r.Language).Append('\n');
        foreach (var x in r.Reasons) sb.Append("R:").Append(x).Append('\n');
        foreach (var x in r.Limitations) sb.Append("L:").Append(x).Append('\n');
        foreach (var c in new[] { r.Breakdown.Headers, r.Breakdown.Links, r.Breakdown.Attachments, r.Breakdown.Obfuscation })
        {
            if (c is null) continue;
            sb.Append(c.Name).Append(c.Score.ToString("R", CultureInfo.InvariantCulture)).Append(c.Evaluated).Append('\n');
            foreach (var f in c.Findings)
                sb.Append(f.Code).Append('|').Append(f.Weight).Append('|').Append(f.Message).Append('|').Append(f.MessageArabic).Append('|').Append(f.Target).Append('\n');
        }
        return sb.ToString();
    }

    // ---------------------------------------------------------------- grammar

    private static string U(params int[] codes) => new(codes.Select(c => (char)c).ToArray());

    private static readonly string[] UnicodeNasties =
    [
        U(0x202E), U(0x202D), U(0x202A), U(0x2066), U(0x2067), U(0x2068), U(0x2069), U(0x200E), U(0x200F), U(0x061C), U(0x200B), U(0x200D),
        U(0xFEFF), U(0x00AD), U(0x034F), U(0x2060), U(0xD800), U(0xDC00), U(0xDBFF), U(0xD83D, 0xDE00), U(0xD835, 0xDC0F), U(0x0301), U(0x0301, 0x0301, 0x0301),
        U(0x0000), U(0xFFFE), U(0xFFFF), U(0xFFFD), U(0x3002), U(0xFF0E), U(0xFF61), U(0xFF0F), U(0x2044), U(0x2215), U(0xFB01), U(0xFDFA),
        "ｐａｙｐａｌ", "раураl", "аpple", "Pаypal", "micrοsoft", "البنك العربي", "بَنْك", "ـــ", "أإآٱىةؤئ", "ﻻ", "ک", "ی", "ہ",
        "\r", "\n", "\r\n", "\t", " ", "  ", U(0x2028), U(0x0085), "%", "%00", "%2e", "%2F", "%40", "%zz", "%u202E", "&#xFFFE;", "&#0;",
        "&#55296;", "&amp;", "&#x202E;", "<script>", "</script>", "<style>", "<a href=\"", "<", ">", "=?utf-8?B?", "=?utf-8?Q?", "?=",
        "@", "\\", ":", "//", ".", "-", "..", "xn--", "xn--80ak6aa92e", "xn--zz--", "xn--a-", "password: ", "pwd", "كلمة المرور",
    ];

    private static readonly string[] Words =
    [
        "verify", "account", "PayPal", "Apple", "Microsoft", "invoice", "urgent", "the", "your", "please", "click", "here",
        "حسابك", "تحديث", "البنك", "الأهلي", "مصرف", "تحقق", "numtoken", "urltoken", "de", "que", "für", "Пароль", "ελληνικά",
    ];

    private static readonly string[] BrandHosts =
    [
        "paypal.com", "www.paypal.com", "apple.com", "email.apple.com", "google.com", "www.google.com", "accounts.google.com",
        "microsoft.com", "login.microsoftonline.com", "amazon.com", "amazon.co.uk", "dhl.com", "linkedin.com", "t.co", "x.com",
        "sites.google.com", "someone.github.io", "bucket.s3.amazonaws.com", "docs.google.com", "forms.office.com",
    ];

    private static readonly string[] LookalikeHosts =
    [
        "paypa1.com", "rnicrosoft.com", "xn--pple-43d.com", "аpple.com", "paypal.com.evil.xyz", "paypal-secure.top", "amazom.com",
        "apple.id-check.net", "g00gle.com", "dhl-parcel.info", "linkedin.com.evil.co.uk",
    ];

    private static readonly string[] IpHosts =
    [
        "192.168.1.1", "3232235777", "0x7f.1", "0177.0.0.1", "127.1", "[::1]", "[fe80::1%25eth0]", "[::ffff:1.2.3.4]", "[::]",
        "[1:2:3:4:5:6:7:8]", "1.2.3.4.", "999.1.1.1", "[::1", "::1",
    ];

    private static readonly string[] Schemes =
    [
        "https://", "http://", "HTTPS://", "hTtP://", "", "//", "https:", "https:/", "https:\\\\", "http:\\/", "ftp://", "file://",
        "file:///", "javascript:", "javascript://", "data:text/html,", "data:text/html;base64,", "mailto:", "MAILTO:", "tel:", "hxxp://",
        "https:///", " https://", "\thttps://", "https ://", "ws://", "about:", "blob:https://", "view-source:https://", U(0x202E) + "https://",
    ];

    private static readonly string[] Ports = [":443", ":80", ":0", ":65535", ":65536", ":99999", ":-1", ":abc", ":", ":８０", ":00000000443"];

    private static readonly string[] Paths =
    [
        "/", "/login", "/maps", "/maps/place/x", "/url?q=", "\\a\\b", "/%2e%2e/url?q=https://paypa1.com", "/../url?q=https://evil.xyz",
        "?q=1", "#frag", "#@paypal.com", "?@paypal.com", "/@evil.com", "/path?x=%zz&y=%", "/" + U(0x202E) + "fdp.exe", "/view/paypal-account-review",
        "/r/arabbank-verify", ";jsessionid=1",
    ];

    private static readonly string[] AttachmentPieces =
    [
        "invoice", "scan", U(0x202E), "fdp.exe", "gpj.html", ".pdf", ".exe", ".html", ".svg", ".zip", ".iso", ".docm", ".lnk", ".one",
        ".", "..", ".....", " ", "    .html", ".pdf ", U(0x0000), U(0xD800), "فاتورة", U(0x200F), ".pdf.exe", ".jpg.html", ".PDF.EXE", ".tar.gz",
    ];

    internal static EmailSubmission Generate(Random r)
    {
        bool P(double p) => r.NextDouble() < p;
        string? Maybe(Func<string> make, double nullP = 0.15) => P(nullP) ? null : make();

        var brandSender = P(0.45);
        var senderHost = Pick(r, BrandHosts);
        var qr = P(0.6) ? null : Enumerable.Range(0, r.Next(0, 21)).Select(_ => Clamp(Url(r), 2048)).ToList();
        List<EmailLink>? links = r.Next(5) switch
        {
            0 => null,
            // On-brand mail with the odd hostile link mixed in: the only way to reach "verified-brand-sender" often.
            1 when brandSender => Enumerable.Range(0, r.Next(1, 6))
                .Select(_ => new EmailLink(P(0.3) ? "QR code" : LinkText(r), P(0.85) ? OnBrandUrl(r, senderHost) : Url(r))).ToList(),
            // Many distinct non-brand hosts whose text names another domain: the most work per link.
            2 when P(0.15) => Enumerable.Range(0, r.Next(150, 501))
                .Select(i => new EmailLink($"{Label(r)}{i}.org", $"https://{Label(r)}.{Label(r)}{i}.{Pick(r, ["com", "net", "co.uk"])}/x")).ToList(),
            _ => Enumerable.Range(0, LinkCount(r)).Select(_ => new EmailLink(P(0.3) ? null : (qr is not null && P(0.2) ? "QR code" : LinkText(r)), Url(r))).ToList(),
        };
        if (qr is null && links?.Any(l => l.Text == "QR code") == true && P(0.7))
            qr = [Url(r)]; // a link labelled like the analyser's own QR links, next to a real QR code
        var attachments = P(0.6) ? null : Enumerable.Range(0, r.Next(0, P(0.1) ? 101 : 6))
            .Select(_ => new EmailAttachment(Api.AnalyseRequest.ClampAttachmentName(AttachmentName(r)), P(0.5) ? null : Text(r, 20)))
            .Where(a => !string.IsNullOrWhiteSpace(a.Name)) // the API drops blank names
            .ToList();

        var senderEmail = Maybe(() => brandSender ? $"{Pick(r, ["no_reply", "service", "a.b+c"])}@{senderHost}" : Address(r));
        return new EmailSubmission
        {
            Subject = Maybe(() => Text(r, P(0.05) ? 50_000 : 200)),
            SenderName = Maybe(() => P(0.3) ? Pick(r, ["PayPal", "Apple Support", "البنك العربي", "service@paypal.com", "Pаypal"]) + Text(r, 20) : Text(r, P(0.03) ? 20_000 : 80)),
            SenderEmail = senderEmail,
            ReplyTo = Maybe(() => P(0.5) ? Address(r) : Text(r, 60), 0.6),
            Body = Maybe(() => Text(r, P(0.1) ? (P(0.2) ? 100_000 : 60_000) : 3000)),
            RawHeaders = Maybe(() => Headers(r, senderEmail, brandSender), 0.4),
            Links = links,
            Attachments = attachments,
            QrCodeUrls = qr,
        };
    }

    private static int LinkCount(Random r) => r.NextDouble() switch { < 0.05 => r.Next(200, 501), < 0.3 => 0, _ => r.Next(1, 8) };

    private static string Pick(Random r, string[] items) => items[r.Next(items.Length)];

    private static string Clamp(string s, int max) => s.Length <= max ? s : s[..max];

    /// <summary>Random text up to about <paramref name="maxLength"/> chars, from words, nasty pieces, URLs and long runs.</summary>
    private static string Text(Random r, int maxLength)
    {
        var target = r.Next(0, maxLength + 1);
        var sb = new StringBuilder();
        while (sb.Length < target)
        {
            switch (r.Next(10))
            {
                case < 4: sb.Append(Pick(r, Words)).Append(' '); break;
                case < 7: sb.Append(Pick(r, UnicodeNasties)); break;
                case 7: sb.Append(Url(r)).Append(' '); break;
                case 8: sb.Append(Address(r)).Append(' '); break;
                default: sb.Append(Pick(r, UnicodeNasties)[0], r.Next(1, Math.Max(2, Math.Min(5000, target - sb.Length)))); break;
            }
        }
        return Clamp(sb.ToString(), Math.Max(target, 0));
    }

    private static string Label(Random r) => r.Next(12) switch
    {
        0 => new string('a', r.Next(60, 301)),
        1 => "xn--" + Text(r, 12),
        2 => "xn--" + new string('z', r.Next(1, 70)),
        3 => Pick(r, UnicodeNasties),
        4 => "",
        5 => Pick(r, ["paypal", "apple", "microsoft", "google", "amazon", "arabbank"]) + Pick(r, ["", "-", "1", U(0x200B), "-secure", "rn"]),
        6 => "-a-",
        _ => Pick(r, ["mail", "login", "secure", "a", "b", "evil", "site", "cdn", "x", "مصرف"]),
    };

    private static string Host(Random r)
    {
        switch (r.Next(10))
        {
            case < 3: return Pick(r, BrandHosts);
            case 3: return Pick(r, LookalikeHosts);
            case 4: return Pick(r, IpHosts);
            case 5: return new string('a', r.Next(250, 320)) + ".com";
            case 6: return string.Join('.', Enumerable.Range(0, r.Next(1, 120)).Select(_ => r.Next(3) == 0 ? Label(r) : "a")) + ".com";
            default:
                var labels = Enumerable.Range(0, r.Next(1, 5)).Select(_ => Label(r)).ToList();
                labels.Add(r.Next(4) == 0 ? Pick(r, BrandHosts) : Pick(r, ["com", "xyz", "co.uk", "github.io", "pages.dev", "zip", "top", "com.jo", "", "*", "1"]));
                return string.Join(r.Next(10) == 0 ? Pick(r, [U(0x3002), U(0xFF0E), ".."]) : ".", labels);
        }
    }

    private static string Url(Random r)
    {
        var sb = new StringBuilder(Pick(r, Schemes));
        if (r.Next(6) == 0) sb.Append(Pick(r, ["user@", "paypal.com@", "a:b@", "@", "www.paypal.com:443@", "u%40v@", "a\\@"]));
        sb.Append(Host(r));
        if (r.Next(6) == 0) sb.Append(Pick(r, Ports));
        if (r.Next(2) == 0) sb.Append(Pick(r, Paths));
        if (r.Next(10) == 0) sb.Append('/').Append(new string('x', r.Next(100, 2000)));
        if (r.Next(10) == 0) sb.Append(Pick(r, UnicodeNasties));
        var url = sb.ToString();

        // Redirector wrapping, sometimes nested deeper than MaxRedirectorDepth, sometimes with a duplicate parameter.
        for (var depth = r.Next(5) == 0 ? r.Next(1, 8) : 0; depth > 0; depth--)
        {
            var enc = r.Next(3) == 0 ? url : HttpUtility.UrlEncode(url);
            url = r.Next(3) switch
            {
                0 => $"https://www.google.com/url?q={enc}" + (r.Next(4) == 0 ? "&q=https://www.google.com/" : "&sa=D"),
                1 => $"https://nam12.safelinks.protection.outlook.com/?url={enc}&data=x",
                _ => $"https://google.com/url?q={enc}",
            };
        }
        return url;
    }

    /// <summary>A link to the sender's own brand host, spelled in the many ways a browser or redirector may accept.</summary>
    private static string OnBrandUrl(Random r, string brandHost)
    {
        var scheme = r.Next(3) != 0 ? "https://" : Pick(r, ["http://", "HTTPS://", "", "//", "https:", "https:/", "https:\\\\"]);
        var url = scheme + Pick(r, ["", "", "www.", "a.", "user@"]) + brandHost
                  + (r.Next(8) == 0 ? Pick(r, Ports) : "") + Pick(r, Paths) + (r.Next(12) == 0 ? Pick(r, UnicodeNasties) : "");
        return r.Next(4) switch
        {
            0 => $"https://www.google.com/url?q={HttpUtility.UrlEncode(url)}&sa=D",
            1 when r.Next(2) == 0 => Pick(r, ["mailto:a@b.com", "tel:123", "https://www.google.com/maps/place/x", "https://maps.google.com/maps?q=1"]),
            _ => url,
        };
    }

    private static string LinkText(Random r) => r.Next(5) switch
    {
        0 => Pick(r, BrandHosts),
        1 => Pick(r, LookalikeHosts),
        2 => Pick(r, ["QR code", "Click here", "score.py", "report.csv", "www.paypal.com/login", "https://apple.com", "عرض الفاتورة"]),
        3 => Url(r),
        _ => Text(r, 40),
    };

    private static string Address(Random r) => r.Next(6) switch
    {
        0 => $"{Text(r, 10)}@{Host(r)}",
        1 => $"\"{Text(r, 10)}\" <a@{Host(r)}>",
        2 => Text(r, 30),
        3 => $"a@{Host(r)}@{Host(r)}",
        _ => $"a@{Host(r)}",
    };

    private static string AttachmentName(Random r)
    {
        var sb = new StringBuilder();
        for (var n = r.Next(0, 6); n > 0; n--)
            sb.Append(Pick(r, AttachmentPieces));
        if (r.Next(15) == 0) sb.Insert(0, new string('A', r.Next(200, 400)));
        if (r.Next(15) == 0) sb.Append(new string('.', r.Next(10, 300))).Append("exe");
        return sb.ToString();
    }

    private static string Headers(Random r, string? senderEmail, bool brandSender)
    {
        var nl = r.Next(3) == 0 ? "\r\n" : "\n";
        var sb = new StringBuilder();
        var budget = r.Next(10) == 0 ? 64_000 : 4_000;
        var pass = "Authentication-Results: mx.google.com; dkim=pass header.i=@x; spf=pass smtp.mailfrom=x; dmarc=pass (p=REJECT) header.from=x";
        if (brandSender && r.Next(3) != 0)
            sb.Append(pass).Append(nl);
        for (var n = r.Next(0, 12); n > 0 && sb.Length < budget; n--)
        {
            sb.Append(r.Next(12) switch
            {
                0 => pass,
                1 => "Authentication-Results: mx.google.com; " + Pick(r, ["spf=fail", "dkim=fail", "dmarc=fail", "compauth=fail", "spf=softfail", "spf=", "dkim =  pass", "SPF=PASS DKIM=PASS DMARC=PASS"]),
                2 => $"From: {Pick(r, ["=?utf-8?B?UGF5UGFs?=", "=?utf-8?B?", "=?x?Q?=ZZ?=", "\"PayPal\"", "", "<<<", "service@paypal.com"])} <{senderEmail ?? Address(r)}>",
                3 => $"Reply-To: {Address(r)}",
                4 => " folded continuation " + Text(r, 200),
                5 => "\tfolded " + Pick(r, UnicodeNasties),
                6 => "Subject: =?utf-8?B?" + Text(r, 50) + "?=",
                7 => "no colon here " + Text(r, 50),
                8 => ": empty name",
                9 => "X-Huge: " + new string('A', r.Next(1000, Math.Max(1001, budget - sb.Length))),
                10 => "",
                _ => "From: " + Text(r, 200),
            }).Append(nl);
        }
        return Clamp(sb.ToString(), 64_000);
    }

    private static string Describe(EmailSubmission e) =>
        $"subject {e.Subject?.Length} sender '{Escape(Clamp(e.SenderEmail ?? "<null>", 120))}' replyTo {e.ReplyTo?.Length} body {e.Body?.Length} headers {e.RawHeaders?.Length} " +
        $"links {e.Links?.Count} attachments {e.Attachments?.Count} qr {e.QrCodeUrls?.Count}";

    internal static string Escape(string s) =>
        string.Concat(Clamp(s, 300).Select(c => c is < ' ' or > '~' ? $"\\u{(int)c:X4}" : c.ToString()));
}
