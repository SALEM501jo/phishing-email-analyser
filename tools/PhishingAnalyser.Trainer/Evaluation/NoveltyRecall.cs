using System.Text.RegularExpressions;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Trainer.Corpus;

namespace PhishingAnalyser.Trainer.Evaluation;

/// <summary>
/// How much does the train/test split leak? The split groups emails by subject, so the same phishing body under a
/// different subject can sit on both sides (found by the evaluation audit). This re-reports test recall separately for
/// test emails whose text is NOT largely contained in the training set - the honest "unseen campaign" number.
/// Containment = share of a test email's (sampled) 6-word shingles that occur anywhere in the training emails.
/// </summary>
public static partial class NoveltyRecall
{
    private const int ShingleWords = 6;
    private const int MinShingles = 5; // shorter emails can't be judged and are reported separately

    [GeneratedRegex(@"\p{L}+")]
    private static partial Regex Word();

    public static void Run(IReadOnlyList<CorpusEmail> train, IReadOnlyList<CorpusEmail> tune, IReadOnlyList<CorpusEmail> test, IContentClassifier classifier)
    {
        Console.WriteLine($"Indexing shingles of {train.Count} training emails ...");
        var seen = new HashSet<ulong>();
        foreach (var e in train)
            foreach (var h in Shingles(e.Text))
                seen.Add(h);
        Console.WriteLine($"  {seen.Count:N0} sampled shingles");

        Console.WriteLine($"Scoring {tune.Count + test.Count} tune + test emails end to end (shipped classifier, default options) ...");
        var e2e = new EndToEndEvaluator(classifier, new ScoringOptions());
        var (phishingThreshold, suspiciousThreshold) = EndToEndEvaluator.TuneThresholds(e2e.Score(tune));
        var scored = e2e.Score(test);
        Console.WriteLine($"  thresholds from the tune split: phishing >= {phishingThreshold:0.00}, suspicious >= {suspiciousThreshold:0.00}");

        var rows = scored.Select(s =>
        {
            var shingles = Shingles(s.Email.Text).ToList();
            double? containment = shingles.Count < MinShingles ? null : shingles.Count(seen.Contains) / (double)shingles.Count;
            return (s, containment);
        }).ToList();

        foreach (var cls in new[] { EmailClasses.Phishing, EmailClasses.Legitimate, EmailClasses.Spam })
        {
            var group = rows.Where(r => r.s.Email.Class == cls).ToList();
            Console.WriteLine($"\n{cls} (test, n={group.Count}):");
            Print("all", group.Select(r => r.s), phishingThreshold, suspiciousThreshold);
            Print("too short to judge", group.Where(r => r.containment is null).Select(r => r.s), phishingThreshold, suspiciousThreshold);
            Print("novel (< 50% of text in training)", group.Where(r => r.containment < 0.5).Select(r => r.s), phishingThreshold, suspiciousThreshold);
            Print("partly seen (50-80%)", group.Where(r => r.containment is >= 0.5 and < 0.8).Select(r => r.s), phishingThreshold, suspiciousThreshold);
            Print("near-copy (>= 80% in training)", group.Where(r => r.containment >= 0.8).Select(r => r.s), phishingThreshold, suspiciousThreshold);
        }
    }

    /// <summary>How many test emails per class are largely contained in training - no model needed. Run after a re-split.</summary>
    public static void LeakReport(IReadOnlyList<CorpusEmail> train, IReadOnlyList<CorpusEmail> test)
    {
        var seen = new HashSet<ulong>();
        foreach (var e in train)
            foreach (var h in Shingles(e.Text))
                seen.Add(h);
        Console.WriteLine("Leak check - test emails whose text is largely in training:");
        foreach (var group in test.GroupBy(e => (e.Modern ? "modern" : "old") + " " + e.Class).OrderBy(g => g.Key))
        {
            var containment = group.Select(e => Shingles(e.Text).ToList()).Where(s => s.Count >= MinShingles)
                .Select(s => s.Count(seen.Contains) / (double)s.Count).ToList();
            Console.WriteLine($"  {group.Key,-18} n={group.Count(),6}  judged={containment.Count,6}  >=50%: {containment.Count(c => c >= 0.5),5}  >=80%: {containment.Count(c => c >= 0.8),5}");
        }
    }

    private static void Print(string label, IEnumerable<ScoredEmail> emails, double phishing, double suspicious)
    {
        var list = emails.ToList();
        if (list.Count == 0)
        {
            Console.WriteLine($"  {label,-36} n=    0");
            return;
        }
        var phishingVerdicts = list.Count(e => e.Final >= phishing);
        var anyWarning = list.Count(e => e.Final >= suspicious);
        Console.WriteLine($"  {label,-36} n={list.Count,5}  'phishing' verdict {phishingVerdicts / (double)list.Count,6:P1}  any warning {anyWarning / (double)list.Count,6:P1}");
    }

    /// <summary>Hashes of every 6-word window, keeping a fixed quarter of them (the same quarter for every email).</summary>
    private static IEnumerable<ulong> Shingles(string text)
    {
        var words = Word().Matches(text.ToLowerInvariant()).Select(m => m.Value).ToArray();
        for (var i = 0; i + ShingleWords <= words.Length; i++)
        {
            var hash = 14695981039346656037UL; // FNV-1a 64
            for (var w = i; w < i + ShingleWords; w++)
            {
                foreach (var ch in words[w])
                    hash = (hash ^ ch) * 1099511628211UL;
                hash = (hash ^ ' ') * 1099511628211UL;
            }
            if (hash % 4 == 0)
                yield return hash;
        }
    }
}
