using System.Text.Json;
using MimeKit;
using MimeKit.Utils;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Reputation;
using PhishingAnalyser.Core.Rules;
using PhishingAnalyser.Trainer.Corpus;

namespace PhishingAnalyser.Trainer.Evaluation;

/// <summary>
/// --established-sender-study: should authenticated mail from an OLD, independently registered domain be judged less
/// on its wording? The text model can't tell a real receipt from a fake one; the sender's history can - legitimate shops
/// send from domains registered years ago, phishing mostly from days-old ones (or from compromised old ones: the risk).
///
/// For every email whose headers show SPF+DKIM+DMARC pass, the sender domain's registration date comes from RDAP and its
/// age is taken ON THE DAY THE EMAIL WAS SENT (Date header), so years-old phishing is judged as it was when it arrived.
/// Each verdict is then recomputed from the analyser's own breakdown under several candidate rules (damping factor x
/// minimum age), for real phishing (public corpus) and for the owner's mailbox (evaluation only).
///
/// Offline limitation, and it errs on the safe side: link-domain ages and blocklists (production reputation) are not
/// available, so some phishing counted here as "trusted" would in production be stopped by a young link domain.
/// Privacy: only registrable domains are looked up; the cache and the report stay in the git-ignored data/ folder.
/// </summary>
public static class EstablishedSenderStudy
{
    private static readonly (double Factor, int MinDays)[] Candidates = [(0.5, 365), (0.35, 365), (0.2, 365), (0.35, 730), (0.2, 730)];

    public static async Task RunAsync(IEnumerable<CorpusEmail> phishing, string? mboxPath, IContentClassifier classifier, ScoringOptions scoring)
    {
        var analyser = new EmailAnalyser(classifier, new HeaderAnalyser(BrandCatalog.Default), new LinkAnalyser(BrandCatalog.Default), scoring);
        var cachePath = Path.Combine("data", "processed", "rdap-cache.json");
        var cache = File.Exists(cachePath)
            ? JsonSerializer.Deserialize<Dictionary<string, DateTimeOffset?>>(File.ReadAllText(cachePath)) ?? []
            : new Dictionary<string, DateTimeOffset?>();
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        http.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json");
        http.DefaultRequestHeaders.UserAgent.ParseAdd("PhishingAnalyser-research/1.0");
        var rdap = new DomainAgeChecker(http);

        // ---- real phishing (public corpus, genuine headers)
        var phishRows = phishing.Where(e => !string.IsNullOrEmpty(e.Submission?.RawHeaders)).Select(e => e.Submission!).ToList();
        Console.WriteLine($"Scoring {phishRows.Count} real phishing emails with genuine headers ...");
        var phishScored = phishRows.Select(s => Score(analyser, s)).ToList();
        await LookUpAsync(rdap, cache, phishScored, cachePath);
        Console.WriteLine("\nReal phishing (should stay warned):");
        Report("all phishing with headers", phishScored, scoring, positive: true);

        // ---- the owner's mailbox (evaluation only)
        if (mboxPath is null)
            return;
        var inboxCachePath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(mboxPath))!, "rdap-cache-inbox.json");
        var inboxCache = File.Exists(inboxCachePath)
            ? JsonSerializer.Deserialize<Dictionary<string, DateTimeOffset?>>(File.ReadAllText(inboxCachePath)) ?? []
            : new Dictionary<string, DateTimeOffset?>();
        var byCategory = new Dictionary<string, List<Scored>>();
        using (var stream = File.OpenRead(mboxPath))
        {
            var parser = new MimeParser(stream, MimeFormat.Mbox);
            while (!parser.IsEndOfStream)
            {
                MimeMessage message;
                try { message = parser.ParseMessage(); } catch (FormatException) { break; }
                if (InboxEvaluation.Categorise(message.Headers["X-Gmail-Labels"] ?? "") is not { } category)
                    continue;
                EmailSubmission submission;
                try { submission = InboxEvaluation.ToSubmission(message); } catch (Exception) { continue; }
                var scored = Score(analyser, submission);
                var key = $"{category} [{scored.Language}]";
                (byCategory.TryGetValue(key, out var list) ? list : byCategory[key] = []).Add(scored);
            }
        }
        await LookUpAsync(rdap, inboxCache, byCategory.Values.SelectMany(v => v).ToList(), inboxCachePath);
        Console.WriteLine("\nYour mailbox (legitimate by Gmail's categories - should become LESS warned; counts only):");
        foreach (var (category, rows) in byCategory.OrderBy(kv => kv.Key))
            Report(category, rows, scoring, positive: category.StartsWith("spam", StringComparison.Ordinal));
    }

    /// <summary>What the analyser says today, plus what the rule needs to know - no text is kept.</summary>
    private sealed record Scored(string Verdict, string Language, double ContentEvidence, double[] Other, bool VerifiedBrand,
        bool AuthPass, bool OnlyWeakFindings, string? SenderDomain, DateTimeOffset? Sent)
    {
        public DateTimeOffset? Registered { get; set; }
    }

    private static Scored Score(EmailAnalyser analyser, EmailSubmission email)
    {
        var result = analyser.Analyse(email);
        var b = result.Breakdown;
        var components = new[] { b.Headers, b.Links, b.Attachments, b.Obfuscation }.OfType<ComponentResult>().ToList();
        var findings = components.SelectMany(c => c.Findings).ToList();
        var sender = DomainUtils.GetEmailDomain(email.SenderEmail);
        var eligible = sender is not null && !DomainUtils.IsFreeMail(DomainUtils.RegistrableDomain(sender))
                       && BrandCatalog.Default.OwnerOf(sender) is null && BrandCatalog.Default.UserContentPlatform(sender) is null;
        DateTimeOffset? sent = null;
        if (RawHeaders.Parse(email.RawHeaders).Get("Date") is { } date && DateUtils.TryParse(date, out var parsed))
            sent = parsed;
        return new Scored(result.Verdict, result.Language,
            ContentEvidenceOf(b.Content), components.Select(c => c.Score).ToArray(),
            findings.Any(f => f.Code == "verified-brand-sender"),
            findings.Any(f => f.Code == "auth-pass"),
            findings.All(f => f.Weight <= 0.1),
            eligible ? DomainUtils.RegistrableDomain(sender!) : null, sent);
    }

    private static double ContentEvidenceOf(ContentResult content) => EmailAnalyser.ContentEvidence(content, new ScoringOptions());

    private static async Task LookUpAsync(DomainAgeChecker rdap, Dictionary<string, DateTimeOffset?> cache, List<Scored> rows, string cachePath)
    {
        var wanted = rows.Where(r => r.AuthPass && r.SenderDomain is not null && rdap.Supports(r.SenderDomain))
            .Select(r => r.SenderDomain!).Distinct().Where(d => !cache.ContainsKey(d)).ToList();
        Console.WriteLine($"  RDAP: {wanted.Count} new domains to look up ({cache.Count} cached)");
        using var gate = new SemaphoreSlim(4);
        var done = 0;
        await Task.WhenAll(wanted.Select(async domain =>
        {
            await gate.WaitAsync();
            try
            {
                var age = await rdap.CheckAsync(domain, CancellationToken.None);
                lock (cache)
                {
                    cache[domain] = age.Checked ? age.Registered : null;
                    if (++done % 50 == 0) Console.WriteLine($"    {done}/{wanted.Count}");
                }
                await Task.Delay(150);
            }
            finally { gate.Release(); }
        }));
        File.WriteAllText(cachePath, JsonSerializer.Serialize(cache));
        foreach (var r in rows)
            if (r.SenderDomain is not null && cache.TryGetValue(r.SenderDomain, out var registered))
                r.Registered = registered;
    }

    private static string Verdict(double score, ScoringOptions o) =>
        score >= o.PhishingThreshold ? Verdicts.Phishing : score >= o.SuspiciousThreshold ? Verdicts.Suspicious : Verdicts.Safe;

    /// <summary>Recomputes the verdict under the candidate rule from the stored breakdown (same fusion as EmailAnalyser).</summary>
    private static string WithRule(Scored s, ScoringOptions o, double factor, int minDays)
    {
        var qualifies = !s.VerifiedBrand && s.AuthPass && s.OnlyWeakFindings && s.Registered is { } reg && s.Sent is { } sent
                        && (sent - reg).TotalDays >= minDays;
        if (!qualifies)
            return s.Verdict;
        return Verdict(Scoring.NoisyOr([s.ContentEvidence * factor, .. s.Other]), o);
    }

    private static void Report(string label, List<Scored> rows, ScoringOptions o, bool positive)
    {
        static double Warned(IEnumerable<string> verdicts, int n) => verdicts.Count(v => v != Verdicts.Safe) / (double)Math.Max(1, n);
        var eligible = rows.Count(r => !r.VerifiedBrand && r.AuthPass && r.OnlyWeakFindings && r.SenderDomain is not null);
        var aged = rows.Count(r => r.Registered is not null && r.Sent is not null);
        var line = $"  {label,-24} n={rows.Count,5}  auth-pass+eligible={eligible,4}  age known={aged,4}  warned now {Warned(rows.Select(r => r.Verdict), rows.Count),6:P1}";
        foreach (var (factor, minDays) in Candidates)
        {
            var after = rows.Select(r => WithRule(r, o, factor, minDays)).ToList();
            line += $" | x{factor} >={minDays}d: {Warned(after, rows.Count):P1}";
        }
        Console.WriteLine(line);
        if (positive)
        {
            // For phishing: how many that were warned become SAFE under each candidate (the cost of the rule).
            var lost = Candidates.Select(c => rows.Count(r => r.Verdict != Verdicts.Safe && WithRule(r, o, c.Factor, c.MinDays) == Verdicts.Safe));
            Console.WriteLine($"  {"",-24} warned phishing that would become SAFE: " + string.Join(" | ", Candidates.Zip(lost, (c, n) => $"x{c.Factor} >={c.MinDays}d: {n}")));
        }
    }
}
