using System.Security.Cryptography;
using System.Text;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Trainer.Corpus;

public sealed record SourceSpec(string Name, string Class, bool Modern, int? Cap, Func<IEnumerable<RawEmail>> Read, bool NoisyLabels = false);

public sealed record SourceStats(string Name, string Class, bool Modern, int Read, int NonEnglish, int TooShort, int Duplicates, int Kept);

/// <summary>
/// Assembles the training corpus from every source, applying the same cleaning to all of them.
///
///   legitimate  old:    Enron (Nazario_5 ham, TREC-05), TREC-06/07, CEAS-08, SpamAssassin ham            (1990s-2008)
///               modern: public mailing-list archives - Python, Fedora, Mailman                         (2024-2026)
///   spam        old:    TREC-05/06/07, CEAS-08, SpamAssassin spam                                        (2001-2008)
///   phishing    old:    Nazario phishing corpus, Nigerian advance-fee fraud                             (2002-2007)
///               modern: phishing_pot honeypot captures (English subset)                                (2022-2026)
///
/// Excluded on purpose: Enron.csv and Ling.csv (pre-lowercased/tokenised - the model would learn the formatting).
/// </summary>
public static class CorpusBuilder
{
    public const int OldLegitimateCap = 30_000;
    public const int OldSpamCap = 25_000;
    public const int ModernHamPerFileCap = 2_500;
    public const int ModernSpamCap = 12_000;

    /// <summary>Body length kept for export - transformers only read the first ~256 tokens anyway.</summary>
    public const int MaxExportBody = 3_000;

    public static List<SourceSpec> DefaultSources(string raw)
    {
        string P(string f) => Path.Combine(raw, f);
        const string L = EmailClasses.Legitimate, S = EmailClasses.Spam, X = EmailClasses.Phishing;

        var sources = new List<SourceSpec>
        {
            new("Nazario", X, false, null, () => CorpusSources.Csv(P("Nazario.csv"), 1)),
            new("Nazario_5 (phishing)", X, false, null, () => CorpusSources.Csv(P("Nazario_5.csv"), 1)),
            new("Nigerian_Fraud", X, false, null, () => CorpusSources.Csv(P("Nigerian_Fraud.csv"), 1)),
            new("Nazario_5 (Enron ham)", L, false, null, () => CorpusSources.Csv(P("Nazario_5.csv"), 0)),
            new("SpamAssassin ham", L, false, null, () => CorpusSources.Csv(P("SpamAssasin.csv"), 0)),
            new("SpamAssassin spam", S, false, null, () => CorpusSources.Csv(P("SpamAssasin.csv"), 1)),
            new("CEAS_08 ham", L, false, null, () => CorpusSources.Csv(P("CEAS_08.csv"), 0)),
            new("CEAS_08 spam", S, false, null, () => CorpusSources.Csv(P("CEAS_08.csv"), 1)),
        };
        foreach (var trec in new[] { "TREC_05", "TREC_06", "TREC_07" })
        {
            sources.Add(new($"{trec} ham", L, false, null, () => CorpusSources.Csv(P($"{trec}.csv"), 0)));
            sources.Add(new($"{trec} spam", S, false, null, () => CorpusSources.Csv(P($"{trec}.csv"), 1)));
        }

        // The two modern "junk" sources are captured wholesale, so their labels are noisy (the honeypot also catches
        // marketing; the spam trap also catches phishing and fraud) - see ConfidentLearning.
        sources.Add(new("phishing_pot", X, true, null, () => CorpusSources.MessageFiles(P(Path.Combine("phishing_pot", "email"))), NoisyLabels: true));
        if (Directory.Exists(P("modern_spam")))
            sources.Add(new("untroubled.org spam 2024-25", S, true, ModernSpamCap, () => CorpusSources.MessageFiles(P("modern_spam"), "*.txt"), NoisyLabels: true));

        var hamDir = P("modern_ham");
        if (Directory.Exists(hamDir))
            foreach (var mbox in Directory.EnumerateFiles(hamDir, "*.mbox.gz").Order(StringComparer.Ordinal))
                sources.Add(new(Path.GetFileName(mbox).Replace(".mbox.gz", ""), L, true, ModernHamPerFileCap, () => CorpusSources.MboxGz(mbox)));

        return sources;
    }

    public static (List<CorpusEmail> Emails, List<SourceStats> Stats) Build(IEnumerable<SourceSpec> sources, int seed)
    {
        var seen = new HashSet<string>();
        var emails = new List<CorpusEmail>();
        var stats = new List<SourceStats>();

        foreach (var source in sources)
        {
            int read = 0, nonEnglish = 0, tooShort = 0, dupes = 0;
            var kept = new List<CorpusEmail>();

            foreach (var raw in source.Read())
            {
                read++;
                var subject = TextCleaning.StripFormatArtifacts(raw.Subject);
                var body = TextCleaning.VisibleBody(TextCleaning.StripFormatArtifacts(raw.Body));
                var text = TextCleaning.ScrubCorpusArtifacts(EmailTextNormalizer.Normalize(subject, body));

                if (text.Length < 40) { tooShort++; continue; }
                if (!CorpusSources.IsEnglish(text)) { nonEnglish++; continue; }
                var hash = Hash(text);
                if (!seen.Add(hash)) { dupes++; continue; }

                var submission = raw.Submission is null ? null : new EmailSubmission
                {
                    Subject = raw.Submission.Subject,
                    SenderName = raw.Submission.SenderName,
                    SenderEmail = raw.Submission.SenderEmail,
                    ReplyTo = raw.Submission.ReplyTo,
                    Body = body,
                    Links = raw.Submission.Links,
                    RawHeaders = raw.Submission.RawHeaders,
                };

                kept.Add(new CorpusEmail(text, source.Class, source.Name, source.Modern, TextCleaning.GroupKey(raw.Subject, hash), submission, source.NoisyLabels,
                    Subject: subject.Length > 300 ? subject[..300] : subject,
                    VisibleBody: body.Length > MaxExportBody ? body[..MaxExportBody] : body));
            }

            if (source.Cap is { } cap && kept.Count > cap)
                kept = Shuffle(kept, seed).Take(cap).ToList();

            emails.AddRange(kept);
            stats.Add(new SourceStats(source.Name, source.Class, source.Modern, read, nonEnglish, tooShort, dupes, kept.Count));
            Console.WriteLine($"  {source.Name,-45} {source.Class,-10} read={read,6} kept={kept.Count,6} (non-English {nonEnglish}, short {tooShort}, dup {dupes})");
        }

        // Down-sample the huge old ham/spam pools so they don't drown out phishing and modern mail.
        emails = Cap(emails, e => !e.Modern && e.Class == EmailClasses.Legitimate, OldLegitimateCap, seed);
        emails = Cap(emails, e => !e.Modern && e.Class == EmailClasses.Spam, OldSpamCap, seed);
        return (NearDuplicates.Cluster(emails), stats);
    }

    /// <summary>
    /// Deterministic split by campaign group: emails sharing a subject thread OR largely the same text
    /// (<see cref="NearDuplicates"/>), across classes, all land on one side. Buckets: 0-19 test, 20-29 tune (modern
    /// mail only), rest train.
    /// </summary>
    public static Split SplitOf(CorpusEmail email)
    {
        var bucket = StableBucket(email.Group);
        if (bucket < 20) return Split.Test;
        if (bucket < 30 && email.Modern) return Split.Tune;
        return Split.Train;
    }

    /// <summary>Cross-validation fold, by thread/campaign like the split.</summary>
    public static int Fold(CorpusEmail email, int folds) => StableBucket("fold|" + email.Group) % folds;

    private static int StableBucket(string key)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        return (int)(BitConverter.ToUInt32(bytes, 0) % 100);
    }

    private static List<CorpusEmail> Cap(List<CorpusEmail> emails, Func<CorpusEmail, bool> selector, int cap, int seed)
    {
        var selected = emails.Where(selector).ToList();
        if (selected.Count <= cap)
            return emails;
        var keep = Shuffle(selected, seed).Take(cap).ToHashSet();
        return emails.Where(e => !selector(e) || keep.Contains(e)).ToList();
    }

    private static List<T> Shuffle<T>(List<T> items, int seed)
    {
        var rng = new Random(seed);
        return items.OrderBy(_ => rng.Next()).ToList();
    }

    private static string Hash(string text) =>
        Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(text.ToLowerInvariant())));
}
