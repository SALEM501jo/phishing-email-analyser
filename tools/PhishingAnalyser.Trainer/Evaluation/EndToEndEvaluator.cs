using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;
using PhishingAnalyser.Trainer.Corpus;

namespace PhishingAnalyser.Trainer.Evaluation;

public sealed record ScoredEmail(CorpusEmail Email, double Content, double Headers, double Links, double Final, IReadOnlyList<string> RuleCodes);

public sealed record VerdictReport(
    double PhishingThreshold, double SuspiciousThreshold,
    BinaryMetrics PhishingVerdict, BinaryMetrics AnyWarning,
    Dictionary<string, Dictionary<string, int>> Verdicts);

public sealed record RuleRate(string Code, double PhishingRate, double LegitimateRate);

/// <summary>
/// Runs the FULL analyser (text + sender + links, fused) on real modern emails - the number that matters
/// to a user, as opposed to the classifier's accuracy on its own test split.
/// Raw headers are withheld so both classes get exactly what the extension reads from Gmail's page.
/// </summary>
public sealed class EndToEndEvaluator(IContentClassifier classifier, ScoringOptions options)
{
    private readonly HeaderAnalyser _headers = new(BrandCatalog.Default);
    private readonly LinkAnalyser _links = new(BrandCatalog.Default);

    public List<ScoredEmail> Score(IEnumerable<CorpusEmail> emails) =>
        emails.Where(e => e.Submission is not null).Select(e =>
        {
            var s = e.Submission!;
            var domView = new EmailSubmission
            {
                Subject = s.Subject, SenderName = s.SenderName, SenderEmail = s.SenderEmail,
                ReplyTo = s.ReplyTo, Body = s.Body, Links = s.Links,
            };
            var content = classifier.Classify(domView.Subject, domView.Body);
            var headers = _headers.Analyse(domView);
            var links = _links.Analyse(domView.Links);
            var contentEvidence = EmailAnalyser.ContentEvidence(content, options);
            var final = Scoring.NoisyOr([contentEvidence, headers.Score, links.Score]);
            var codes = headers.Findings.Concat(links.Findings).Where(f => f.Weight > 0).Select(f => f.Code).Distinct().ToList();
            return new ScoredEmail(e, contentEvidence, headers.Score, links.Score, final, codes);
        }).ToList();

    public static VerdictReport Report(IReadOnlyList<ScoredEmail> scored, double phishingThreshold, double suspiciousThreshold)
    {
        // Precision/recall are phishing vs legitimate; spam (whose labels are noisy) is reported as its own row.
        var rows = scored.Where(s => s.Email.Class != EmailClasses.Spam).Select(s => (s.Email.Class == EmailClasses.Phishing, s.Final)).ToList();
        string Verdict(double score) => score >= phishingThreshold ? Verdicts.Phishing
            : score >= suspiciousThreshold ? Verdicts.Suspicious : Verdicts.Safe;

        var matrix = new Dictionary<string, Dictionary<string, int>>();
        foreach (var cls in new[] { EmailClasses.Phishing, EmailClasses.Legitimate, EmailClasses.Spam })
            matrix[cls] = new[] { Verdicts.Phishing, Verdicts.Suspicious, Verdicts.Safe }.ToDictionary(v => v, _ => 0);
        foreach (var s in scored)
            matrix[s.Email.Class][Verdict(s.Final)]++;

        return new VerdictReport(phishingThreshold, suspiciousThreshold,
            Metrics.Binary(rows, phishingThreshold), Metrics.Binary(rows, suspiciousThreshold), matrix);
    }

    /// <summary>
    /// Picks thresholds on the TUNE split (never the test split), inside sane bounds so that no single weak rule
    /// (shortener 0.15, risky TLD 0.12 ...) can produce a verdict on its own:
    ///   phishing   ∈ [0.50, 0.95]: best F1 among thresholds keeping false positives ≤ 1%;
    ///   suspicious ∈ [0.25, phishing): lowest threshold keeping the "any warning" false-positive rate ≤ 3%.
    /// </summary>
    public static (double Phishing, double Suspicious) TuneThresholds(IReadOnlyList<ScoredEmail> tune)
    {
        var rows = tune.Where(s => s.Email.Class != EmailClasses.Spam).Select(s => (s.Email.Class == EmailClasses.Phishing, s.Final)).ToList();
        var steps = Enumerable.Range(0, 100).Select(i => i / 100.0).ToList();

        var phishing = steps.Where(t => t is >= 0.5 and <= 0.95)
            .Select(t => (t, m: Metrics.Binary(rows, t)))
            .Where(x => x.m.FalsePositiveRate <= 0.01)
            .OrderByDescending(x => x.m.F1).ThenBy(x => x.t)
            .Select(x => x.t)
            .DefaultIfEmpty(0.9).First();

        var suspicious = steps
            .Where(t => t >= 0.25 && t < phishing && Metrics.Binary(rows, t).FalsePositiveRate <= 0.03)
            .DefaultIfEmpty(Math.Round(phishing - 0.1, 2)).Min();

        return (phishing, suspicious);
    }

    /// <summary>How often each hand-written rule fires on phishing vs legitimate mail - evidence for (or against) its weight.</summary>
    public static List<RuleRate> RuleRates(IReadOnlyList<ScoredEmail> scored)
    {
        var phishing = scored.Where(s => s.Email.Class == EmailClasses.Phishing).ToList();
        var legit = scored.Where(s => s.Email.Class == EmailClasses.Legitimate).ToList(); // spam excluded: noisy labels
        return scored.SelectMany(s => s.RuleCodes).Distinct().Order()
            .Select(code => new RuleRate(code,
                Math.Round(phishing.Count(s => s.RuleCodes.Contains(code)) / (double)Math.Max(1, phishing.Count), 4),
                Math.Round(legit.Count(s => s.RuleCodes.Contains(code)) / (double)Math.Max(1, legit.Count), 4)))
            .OrderByDescending(r => r.PhishingRate)
            .ToList();
    }

    /// <summary>SPF/DKIM/DMARC outcomes on real phishing, using the headers the receiving server stamped.</summary>
    public Dictionary<string, double> AuthenticationStats(IEnumerable<CorpusEmail> phishing)
    {
        var withHeaders = phishing.Where(e => !string.IsNullOrEmpty(e.Submission?.RawHeaders)).ToList();
        var codes = withHeaders.Select(e => _headers.Analyse(e.Submission!).Findings.Select(f => f.Code).ToHashSet()).ToList();
        double Rate(string code) => Math.Round(codes.Count(c => c.Contains(code)) / (double)Math.Max(1, codes.Count), 4);
        return new Dictionary<string, double>
        {
            ["emails"] = withHeaders.Count,
            ["dmarc-fail"] = Rate("dmarc-fail"),
            ["spf-fail-or-softfail"] = Rate("spf-fail"),
            ["dkim-fail"] = Rate("dkim-fail"),
            ["no-dkim-and-no-spf-pass"] = Rate("auth-none"),
            ["compauth-fail"] = Rate("compauth-fail"),
            ["all-pass"] = Rate("auth-pass"),
            ["any-auth-failure"] = Math.Round(codes.Count(c => c.Overlaps(["dmarc-fail", "spf-fail", "dkim-fail", "compauth-fail"])) / (double)Math.Max(1, codes.Count), 4),
        };
    }
}
