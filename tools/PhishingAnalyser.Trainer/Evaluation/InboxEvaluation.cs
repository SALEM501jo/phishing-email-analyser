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
    public static object Run(string mboxPath, IContentClassifier classifier, ScoringOptions scoring, int maxEnglishPerCategory = 1500)
    {
        var headers = new Core.Rules.HeaderAnalyser(Core.Rules.BrandCatalog.Default);
        var links = new Core.Rules.LinkAnalyser(Core.Rules.BrandCatalog.Default);
        var shipped = new EmailAnalyser(classifier, headers, links, scoring);
        var promoted = new EmailAnalyser(new PromotedLanguage(classifier, Languages.Arabic), headers, links, scoring);

        var groups = new Dictionary<(string Category, string Language), List<(string Shipped, string Promoted)>>();
        var parsed = 0;
        using var stream = File.OpenRead(mboxPath);
        var parser = new MimeParser(stream, MimeFormat.Mbox);
        while (!parser.IsEndOfStream)
        {
            MimeMessage message;
            try { message = parser.ParseMessage(); }
            catch (FormatException) { break; }
            if (++parsed % 1000 == 0)
                Console.WriteLine($"  {parsed} messages read ...");

            var category = Categorise(message.Headers["X-Gmail-Labels"] ?? "");
            if (category is null)
                continue;

            EmailSubmission submission;
            try { submission = ToSubmission(message); }
            catch (Exception) { continue; } // malformed MIME: skip, never crash on real mail

            var result = shipped.Analyse(submission);
            var key = (category, result.Language);
            if (result.Language != Languages.Arabic && groups.TryGetValue(key, out var existing) && existing.Count >= maxEnglishPerCategory)
                continue; // keep every Arabic email - they are the scarce ones
            var promotedVerdict = result.Language == Languages.Arabic ? promoted.Analyse(submission).Verdict : result.Verdict;
            (groups.TryGetValue(key, out var list) ? list : groups[key] = []).Add((result.Verdict, promotedVerdict));
        }

        Console.WriteLine($"\nYour mailbox ({parsed} messages read; evaluation only, counts only):");
        Console.WriteLine($"  {"group",-28} {"n",5}  {"phishing",9} {"suspicious",10} {"safe",6}   any warning");
        var report = groups.OrderBy(kv => kv.Key.Language).ThenBy(kv => kv.Key.Category).ToDictionary(
            kv => $"{kv.Key.Category} [{kv.Key.Language}]",
            kv =>
            {
                var shippedCounts = Count(kv.Value.Select(v => v.Shipped));
                var promotedCounts = Count(kv.Value.Select(v => v.Promoted));
                Print($"{kv.Key.Category} [{kv.Key.Language}]", kv.Value.Count, shippedCounts);
                if (kv.Key.Language == Languages.Arabic)
                    Print("  ...if Arabic promoted", kv.Value.Count, promotedCounts);
                return new
                {
                    count = kv.Value.Count,
                    shipped = shippedCounts,
                    ifArabicPromoted = kv.Key.Language == Languages.Arabic ? promotedCounts : null,
                };
            });

        return new
        {
            note = "Gmail labels used as reference (a user label 'Phishing' = known phishing); counts only, no content stored",
            messagesRead = parsed,
            groups = report,
        };
    }

    private static Dictionary<string, int> Count(IEnumerable<string> verdicts)
    {
        var counts = new[] { Verdicts.Phishing, Verdicts.Suspicious, Verdicts.Safe }.ToDictionary(v => v, _ => 0);
        foreach (var v in verdicts) counts[v]++;
        return counts;
    }

    private static void Print(string label, int n, Dictionary<string, int> c) =>
        Console.WriteLine($"  {label,-28} {n,5}  {c[Verdicts.Phishing],9} {c[Verdicts.Suspicious],10} {c[Verdicts.Safe],6}   " +
                          $"{(c[Verdicts.Phishing] + c[Verdicts.Suspicious]) / (double)Math.Max(1, n):P1}");

    /// <summary>Own "Phishing" label first, then the Spam folder, then Gmail's inbox categories.</summary>
    private static string? Categorise(string labels)
    {
        var set = labels.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (set.Contains("Phishing")) return "phishing-labelled";
        if (set.Contains("Spam")) return "spam-folder";
        if (set.Contains("Chat") || set.Contains("Sent") && !set.Contains("Inbox"))
            return null; // own messages and chats aren't incoming mail
        if (set.Contains("Category Promotions")) return "promotions";
        if (set.Contains("Category Purchases")) return "purchases";
        if (set.Contains("Category Updates")) return "updates";
        if (set.Contains("Category Social")) return "social";
        if (set.Contains("Inbox") || set.Contains("Category Personal")) return "primary";
        return null;
    }

    /// <summary>What the extension would send, including real headers (Takeout keeps Gmail's Authentication-Results).</summary>
    private static EmailSubmission ToSubmission(MimeMessage message)
    {
        var s = CorpusSources.FromMime(message).Submission!;
        return new EmailSubmission
        {
            Subject = s.Subject, SenderName = s.SenderName, SenderEmail = s.SenderEmail, ReplyTo = s.ReplyTo,
            Body = TextCleaning.VisibleBody(s.Body), Links = s.Links, RawHeaders = s.RawHeaders,
        };
    }
}
