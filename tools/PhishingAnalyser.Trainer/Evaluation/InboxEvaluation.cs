using MimeKit;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Trainer.Corpus;

namespace PhishingAnalyser.Trainer.Evaluation;

/// <summary>
/// Measures the shipped model on the owner's real mailbox (a Google Takeout .mbox), which is the only honest
/// test for modern newsletters and receipts. EVALUATION ONLY: nothing here is ever used for training, the
/// mailbox never leaves the machine, and the report contains only counts - no subjects, senders or text.
///
/// Labels come from Gmail itself (X-Gmail-Labels): Promotions / Updates / Purchases / Primary are treated as
/// legitimate, the Spam folder as unwanted mail. Gmail's labels are not ground truth, but they are the best
/// independent reference available.
/// </summary>
public static class InboxEvaluation
{
    public static object Run(string mboxPath, EmailAnalyser analyser, int maxPerCategory = 400)
    {
        var perCategory = new Dictionary<string, List<AnalysisResult>>();
        var language = new Dictionary<string, int>();

        using var stream = File.OpenRead(mboxPath);
        var parser = new MimeParser(stream, MimeFormat.Mbox);
        while (!parser.IsEndOfStream)
        {
            MimeMessage message;
            try { message = parser.ParseMessage(); }
            catch (FormatException) { break; }

            var labels = message.Headers["X-Gmail-Labels"] ?? "";
            var category = Categorise(labels);
            if (category is null)
                continue;
            if (perCategory.TryGetValue(category, out var list) && list.Count >= maxPerCategory)
                continue;

            var submission = ToSubmission(message);
            var result = analyser.Analyse(submission);
            (perCategory.TryGetValue(category, out list) ? list : perCategory[category] = []).Add(result);
            language[result.Language] = language.GetValueOrDefault(result.Language) + 1;
        }

        Console.WriteLine("\nYour mailbox (evaluation only, counts only):");
        var summary = perCategory.OrderBy(kv => kv.Key).ToDictionary(kv => kv.Key, kv =>
        {
            var verdicts = kv.Value.GroupBy(r => r.Verdict).ToDictionary(g => g.Key, g => g.Count());
            var flagged = kv.Value.Count(r => r.Verdict != Verdicts.Safe) / (double)kv.Value.Count;
            Console.WriteLine($"  {kv.Key,-12} n={kv.Value.Count,4}  " +
                              string.Join("  ", new[] { Verdicts.Phishing, Verdicts.Suspicious, Verdicts.Safe }.Select(v => $"{v}={verdicts.GetValueOrDefault(v)}")) +
                              $"   any warning={flagged:P1}");
            return new { count = kv.Value.Count, verdicts, anyWarningRate = Math.Round(flagged, 4) };
        });

        return new { note = "Gmail labels used as reference; counts only, no content stored", categories = summary, languages = language };
    }

    /// <summary>Spam folder first (it overrides categories), then Gmail's inbox categories.</summary>
    private static string? Categorise(string labels)
    {
        if (labels.Contains("Spam", StringComparison.OrdinalIgnoreCase)) return "spam-folder";
        if (labels.Contains("Chat", StringComparison.OrdinalIgnoreCase) || labels.Contains("Sent", StringComparison.OrdinalIgnoreCase) && !labels.Contains("Inbox", StringComparison.OrdinalIgnoreCase))
            return null; // own messages and chats aren't incoming mail
        if (labels.Contains("Category Promotions", StringComparison.OrdinalIgnoreCase)) return "promotions";
        if (labels.Contains("Category Purchases", StringComparison.OrdinalIgnoreCase)) return "purchases";
        if (labels.Contains("Category Updates", StringComparison.OrdinalIgnoreCase)) return "updates";
        if (labels.Contains("Category Social", StringComparison.OrdinalIgnoreCase)) return "social";
        if (labels.Contains("Inbox", StringComparison.OrdinalIgnoreCase) || labels.Contains("Category Personal", StringComparison.OrdinalIgnoreCase)) return "primary";
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
