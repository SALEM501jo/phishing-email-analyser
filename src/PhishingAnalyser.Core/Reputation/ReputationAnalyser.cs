using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Core.Reputation;

/// <summary>
/// The fourth signal: what the outside world knows about the email's domains and URLs - blocklists and domain age.
/// Rules and the classifier judge how an email LOOKS; reputation catches attacks that look perfectly normal
/// but come from a three-day-old domain or a URL already reported by other victims.
/// Every lookup is bounded by a timeout; anything that fails is simply "not checked", never a guess.
/// </summary>
public sealed class ReputationAnalyser(
    BrandCatalog brands,
    ReputationOptions options,
    ThreatFeedStore feeds,
    DomainAgeChecker? domainAge,
    SafeBrowsingClient? safeBrowsing)
{
    public const string Source = "reputation";

    public async Task<ComponentResult> AnalyseAsync(EmailSubmission email, CancellationToken ct)
    {
        if (!options.Enabled)
            return new ComponentResult(Source, 0, false, []);

        var urls = (email.Links ?? [])
            .Select(l => LinkAnalyser.Unwrap(l.Href))
            .Where(u => u.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || u.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            .Distinct()
            .Take(50)
            .ToList();

        var findings = new List<Finding>();
        var evaluated = false;

        if (options.ThreatFeeds && feeds.IsLoaded)
        {
            evaluated = true;
            foreach (var url in urls)
            {
                if (feeds.Match(url) is not { } match)
                    continue;
                findings.Add(match.ExactUrl
                    ? new(Source, "blocklisted-url", $"Link is listed on the {match.Feed} blocklist of reported phishing/malware URLs", 0.9,
                        $"الرابط مُدرج في قائمة {match.Feed} للروابط المبلَّغ عنها كتصيّد أو برمجيات خبيثة", match.Indicator)
                    : new(Source, "blocklisted-host", $"The site {match.Indicator} is listed on the {match.Feed} blocklist", 0.7,
                        $"الموقع {match.Indicator} مُدرج في قائمة الحظر {match.Feed}", match.Indicator));
            }
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(options.LookupTimeoutMs);

        var ageTask = options.DomainAge && domainAge is not null
            ? CheckAgesAsync(email, urls, timeout.Token)
            : Task.FromResult<List<DomainAge>>([]);
        // Free-mail, brand and hosting-platform senders are excluded inside CheckAgesAsync, so only an independently
        // registered sender domain can ever be "established".
        var senderDomain = DomainUtils.GetEmailDomain(email.SenderEmail) is { } sender ? DomainUtils.RegistrableDomain(sender) : null;
        var safeBrowsingTask = safeBrowsing is not null && urls.Count > 0
            ? safeBrowsing.CheckAsync(urls, timeout.Token)
            : Task.FromResult<IReadOnlyList<(string Url, string Threat)>>([]);
        await Task.WhenAll(ageTask, safeBrowsingTask);

        foreach (var (url, threat) in safeBrowsingTask.Result.DistinctBy(m => m.Url))
            findings.Add(new(Source, "safe-browsing", $"Google Safe Browsing flags a link as {Describe(threat)}", 0.9,
                $"خدمة Google Safe Browsing تصنّف أحد الروابط على أنه {DescribeArabic(threat)}", url));
        evaluated |= safeBrowsing is not null;

        foreach (var age in ageTask.Result.Where(a => a is { Checked: true, Registered: not null }))
        {
            evaluated = true;
            var days = (int)(DateTimeOffset.UtcNow - age.Registered!.Value).TotalDays;
            if (days < 30)
                findings.Add(new(Source, "new-domain", $"{age.Domain} was registered only {Days(days)} ago - phishing domains are typically days old", 0.5,
                    $"النطاق {age.Domain} سُجّل قبل {DaysArabic(days)} فقط - نطاقات التصيّد عادةً حديثة جدًا", age.Domain));
            else if (days < 180)
                findings.Add(new(Source, "young-domain", $"{age.Domain} was registered recently ({Days(days)} ago)", 0.2,
                    $"النطاق {age.Domain} سُجّل مؤخرًا (قبل {DaysArabic(days)})", age.Domain));
            else if (days >= options.EstablishedSenderDays && senderDomain == age.Domain)
                findings.Add(new(Source, "established-sender", $"The sender's domain {age.Domain} has been registered for {Days(days)}", 0,
                    $"نطاق المرسل {age.Domain} مسجّل منذ {DaysArabic(days)}", age.Domain));
        }

        findings.Sort((a, b) => b.Weight.CompareTo(a.Weight));
        return new ComponentResult(Source, Scoring.NoisyOr(findings), evaluated, findings);
    }

    /// <summary>
    /// Age is only meaningful for independently registered domains: skip big brands' own domains, free-mail
    /// providers and sites on hosting platforms (x.pages.dev is as old as pages.dev), and TLDs without RDAP.
    /// </summary>
    private async Task<List<DomainAge>> CheckAgesAsync(EmailSubmission email, List<string> urls, CancellationToken ct)
    {
        var hosts = urls.Select(DomainUtils.GetHost).Append(DomainUtils.GetEmailDomain(email.SenderEmail)).OfType<string>();
        var domains = hosts
            .Where(h => !DomainUtils.IsIpAddress(h) && brands.OwnerOf(h) is null && brands.UserContentPlatform(h) is null)
            .Select(DomainUtils.RegistrableDomain)
            .Where(d => !DomainUtils.IsFreeMail(d) && domainAge!.Supports(d) && !brands.Brands.Any(b => b.Domains.Contains(d)))
            .Distinct()
            .Take(options.MaxDomainsPerEmail)
            .ToList();
        return [.. await Task.WhenAll(domains.Select(d => domainAge!.CheckAsync(d, ct)))];
    }

    private static string Days(int days) => days <= 1 ? "1 day" : $"{days} days";
    // Arabic counted nouns: 1 يوم، 2 يومين، 3-10 أيام، 11+ يومًا
    private static string DaysArabic(int days) => days switch
    {
        <= 1 => "يوم واحد",
        2 => "يومين",
        <= 10 => $"{days} أيام",
        _ => $"{days} يومًا",
    };

    private static string Describe(string threat) => threat switch
    {
        "SOCIAL_ENGINEERING" => "phishing / social engineering",
        "MALWARE" => "malware",
        _ => "harmful",
    };

    private static string DescribeArabic(string threat) => threat switch
    {
        "SOCIAL_ENGINEERING" => "تصيّد / هندسة اجتماعية",
        "MALWARE" => "برمجية خبيثة",
        _ => "ضار",
    };
}
