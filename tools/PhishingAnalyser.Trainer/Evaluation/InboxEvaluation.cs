using MimeKit;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Trainer.Corpus;

namespace PhishingAnalyser.Trainer.Evaluation;

/// <summary>
/// Measures the shipped analyser on the owner's real mailbox (a Google Takeout .mbox) - the only honest test for
/// modern newsletters, receipts and real Arabic mail. EVALUATION ONLY: nothing here is ever used for training,
/// the mailbox never leaves the machine, and the report contains only counts - no subjects, senders or text.
///
/// Reference labels come from Gmail itself (X-Gmail-Labels): Primary / Updates / Promotions / Purchases / Social
/// are treated as legitimate, the Spam folder as unwanted mail. Gmail's labels are not ground truth, but they are
/// the best independent reference available. Optionally, apply your own Gmail label "Phishing" to phishing emails
/// you know about before exporting - those become a "phishing-labelled" group with real ground truth.
///
/// Arabic emails are reported twice: as shipped, and as they would score if Arabic were promoted from preview to
/// full support - the real-mail half of the promotion decision.
/// </summary>
public static class InboxEvaluation
{
    /// <param name="mboxPath">A Takeout .mbox file, or a FOLDER of .eml files (searched recursively). In a folder, each
    /// message names its own group in an "X-Eval-Group" header (e.g. "honeypot/marketing") - used for evaluation sets
    /// collected from public sources of real legitimate mail, where there are no Gmail labels.</param>
    /// <param name="withHeaders">False blanks the raw headers, as when the extension can't fetch "Show original": no
    /// SPF/DKIM/DMARC findings and no sender trust. Needed for collected mail whose headers carry a forwarding hop.</param>
    public static object Run(string mboxPath, IContentClassifier classifier, ScoringOptions scoring, int maxEnglishPerCategory = 100_000, bool withHeaders = true)
    {
        var headers = new Core.Rules.HeaderAnalyser(Core.Rules.BrandCatalog.Default);
        var links = new Core.Rules.LinkAnalyser(Core.Rules.BrandCatalog.Default);
        var shipped = new EmailAnalyser(classifier, headers, links, scoring);
        var promoted = new EmailAnalyser(new PromotedLanguage(classifier, Languages.Arabic), headers, links, scoring);
        var trusting = new EmailAnalyser(classifier, headers, links, new ScoringOptions
        {
            ContentWeight = scoring.ContentWeight, PhishingThreshold = scoring.PhishingThreshold,
            SuspiciousThreshold = scoring.SuspiciousThreshold, TrustVerifiedBrandSenders = true,
        });

        var groups = new Dictionary<(string Category, string Language), List<Row>>();
        var parsed = 0;
        foreach (var message in Messages(mboxPath))
        {
            if (++parsed % 1000 == 0)
                Console.WriteLine($"  {parsed} messages read ...");

            var category = message.Headers["X-Eval-Group"]?.Trim() is { Length: > 0 } group ? group : Categorise(message.Headers["X-Gmail-Labels"] ?? "");
            if (category is null)
                continue;

            EmailSubmission submission;
            try { submission = ToSubmission(message); }
            catch (Exception) { continue; } // malformed MIME: skip, never crash on real mail
            if (!withHeaders)
                submission = new EmailSubmission
                {
                    Subject = submission.Subject, SenderName = submission.SenderName, SenderEmail = submission.SenderEmail,
                    ReplyTo = submission.ReplyTo, Body = submission.Body, Links = submission.Links,
                };

            var result = shipped.Analyse(submission);
            var key = (category, result.Language);
            if (result.Language != Languages.Arabic && groups.TryGetValue(key, out var existing) && existing.Count >= maxEnglishPerCategory)
                continue; // keep every Arabic email - they are the scarce ones

            // Diagnostics - rule CODES and flags only, never text: which signal drives each warning?
            var b = result.Breakdown;
            var findings = b.Headers.Findings.Concat(b.Links.Findings)
                .Concat(b.Attachments?.Findings ?? []).Concat(b.Obfuscation?.Findings ?? []).Concat(b.Reputation?.Findings ?? []).ToList();
            var otherEvidence = b.Headers.Score + b.Links.Score + (b.Attachments?.Score ?? 0) + (b.Obfuscation?.Score ?? 0) + (b.Reputation?.Score ?? 0);
            (groups.TryGetValue(key, out var list) ? list : groups[key] = []).Add(new Row(
                result.Verdict,
                result.Language == Languages.Arabic ? promoted.Analyse(submission).Verdict : result.Verdict,
                trusting.Analyse(submission).Verdict,
                TextOnly: result.Verdict != Verdicts.Safe && otherEvidence <= 0,
                VerifiedBrand: findings.Any(f => f.Code == "verified-brand-sender"),
                Codes: [.. findings.Where(f => f.Weight > 0).Select(f => f.Code).Distinct()]));
        }

        Console.WriteLine($"\nYour mailbox ({parsed} messages read; evaluation only, counts only):");
        Console.WriteLine($"  {"group",-28} {"n",5}  {"phishing",9} {"suspicious",10} {"safe",6}   any warning");
        var report = groups.OrderBy(kv => kv.Key.Language).ThenBy(kv => kv.Key.Category).ToDictionary(
            kv => $"{kv.Key.Category} [{kv.Key.Language}]",
            kv =>
            {
                var rows = kv.Value;
                var shippedCounts = Count(rows.Select(v => v.Shipped));
                var promotedCounts = Count(rows.Select(v => v.Promoted));
                var trustingCounts = Count(rows.Select(v => v.WithBrandTrust));
                Print($"{kv.Key.Category} [{kv.Key.Language}]", rows.Count, shippedCounts);
                if (kv.Key.Language == Languages.Arabic)
                    Print("  ...if Arabic promoted", rows.Count, promotedCounts);
                Print("  ...with verified-brand trust", rows.Count, trustingCounts);
                var warned = rows.Where(r => r.Shipped != Verdicts.Safe).ToList();
                var topCodes = warned.SelectMany(r => r.Codes).GroupBy(c => c).OrderByDescending(g => g.Count()).Take(6)
                    .ToDictionary(g => g.Key, g => g.Count());
                Console.WriteLine($"      warnings from text alone: {warned.Count(r => r.TextOnly)}/{warned.Count}; verified-brand mail: {rows.Count(r => r.VerifiedBrand)}; " +
                                  $"top rules on warned: {string.Join(", ", topCodes.Select(kv2 => $"{kv2.Key}={kv2.Value}"))}");
                return new
                {
                    count = rows.Count,
                    shipped = shippedCounts,
                    ifArabicPromoted = kv.Key.Language == Languages.Arabic ? promotedCounts : null,
                    withVerifiedBrandTrust = trustingCounts,
                    warningsFromTextAlone = warned.Count(r => r.TextOnly),
                    verifiedBrandMail = rows.Count(r => r.VerifiedBrand),
                    topRulesOnWarned = topCodes,
                };
            });

        return new
        {
            note = "Gmail labels used as reference (a user label 'Phishing' = known phishing); counts and rule codes only, no content stored",
            messagesRead = parsed,
            groups = report,
        };
    }

    /// <summary>Every message of an mbox file, or of every .eml file under a folder; unreadable ones are skipped.</summary>
    private static IEnumerable<MimeMessage> Messages(string path)
    {
        if (Directory.Exists(path))
        {
            foreach (var file in Directory.EnumerateFiles(path, "*.eml", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                if (file.Contains(Path.DirectorySeparatorChar + "_work" + Path.DirectorySeparatorChar))
                    continue; // collectors' scratch copies
                MimeMessage? message = null;
                try { message = MimeMessage.Load(file); }
                catch (Exception e) when (e is FormatException or IOException) { }
                if (message is not null)
                    yield return message;
            }
            yield break;
        }

        using var stream = File.OpenRead(path);
        var parser = new MimeParser(stream, MimeFormat.Mbox);
        while (!parser.IsEndOfStream)
        {
            MimeMessage message;
            try { message = parser.ParseMessage(); }
            catch (FormatException) { yield break; }
            yield return message;
        }
    }

    private sealed record Row(string Shipped, string Promoted, string WithBrandTrust, bool TextOnly, bool VerifiedBrand, string[] Codes);

    private static Dictionary<string, int> Count(IEnumerable<string> verdicts)
    {
        var counts = new[] { Verdicts.Phishing, Verdicts.Suspicious, Verdicts.Safe }.ToDictionary(v => v, _ => 0);
        foreach (var v in verdicts) counts[v]++;
        return counts;
    }

    private static void Print(string label, int n, Dictionary<string, int> c) =>
        Console.WriteLine($"  {label,-28} {n,5}  {c[Verdicts.Phishing],9} {c[Verdicts.Suspicious],10} {c[Verdicts.Safe],6}   " +
                          $"{(c[Verdicts.Phishing] + c[Verdicts.Suspicious]) / (double)Math.Max(1, n):P1}");

    // Takeout writes Gmail's system labels in the account's UI language. English and Arabic names map to one key.
    private static readonly Dictionary<string, string> LabelKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Phishing"] = "phishing", ["تصيد"] = "phishing", ["تصيّد"] = "phishing",
        ["Spam"] = "spam", ["الرسائل غير المرغوب فيها"] = "spam",
        ["Chat"] = "chat", ["الدردشة"] = "chat",
        ["Sent"] = "sent", ["تم الإرسال"] = "sent",
        ["Drafts"] = "drafts", ["مسودّات"] = "drafts", ["مسودات"] = "drafts",
        ["Inbox"] = "inbox", ["البريد الوارد"] = "inbox",
        ["Category Promotions"] = "promotions", ["الفئة العروض الترويجية"] = "promotions",
        ["Category Purchases"] = "purchases", ["الفئة عمليات الشراء"] = "purchases", ["فئة الفواتير"] = "purchases",
        ["Category Updates"] = "updates", ["الفئة تحديثات"] = "updates",
        ["Category Social"] = "social", ["الفئة اجتماعية"] = "social",
        ["Category Travel"] = "updates", ["الفئة سفر"] = "updates",
        ["Category Personal"] = "primary", ["الفئة شخصية"] = "primary",
    };

    /// <summary>Own "Phishing" label first, then the Spam folder, then Gmail's inbox categories.</summary>
    internal static string? Categorise(string labels)
    {
        var set = labels.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Replace("\"", ""))                    // Takeout quotes category names: الفئة ""تحديثات""
            .Select(l => LabelKeys.GetValueOrDefault(l, l))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (set.Contains("phishing")) return "phishing-labelled";
        if (set.Contains("spam")) return "spam-folder";
        if (set.Contains("chat") || set.Contains("drafts") || set.Contains("sent") && !set.Contains("inbox"))
            return null; // own messages, drafts and chats aren't incoming mail
        if (set.Contains("promotions")) return "promotions";
        if (set.Contains("purchases")) return "purchases";
        if (set.Contains("updates")) return "updates";
        if (set.Contains("social")) return "social";
        if (set.Contains("inbox") || set.Contains("primary")) return "primary";
        return null;
    }

    /// <summary>What the extension would send, including real headers (Takeout keeps Gmail's Authentication-Results).</summary>
    internal static EmailSubmission ToSubmission(MimeMessage message)
    {
        var s = CorpusSources.FromMime(message).Submission!;
        return new EmailSubmission
        {
            Subject = s.Subject, SenderName = s.SenderName, SenderEmail = s.SenderEmail, ReplyTo = s.ReplyTo,
            Body = TextCleaning.VisibleBody(s.Body), Links = s.Links, RawHeaders = s.RawHeaders,
        };
    }
}
