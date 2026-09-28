using System.Globalization;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Core;

/// <summary>Runs the three signals and fuses them into a verdict with human-readable reasons.</summary>
public sealed class EmailAnalyser(
    IContentClassifier classifier,
    HeaderAnalyser headerAnalyser,
    LinkAnalyser linkAnalyser,
    ScoringOptions options)
{
    private const int MaxReasons = 6;

    public AnalysisResult Analyse(EmailSubmission email)
    {
        var content = classifier.Classify(email.Subject, email.Body);
        var headers = headerAnalyser.Analyse(email);
        var links = linkAnalyser.Analyse(email.Links);

        var score = Scoring.NoisyOr([ContentEvidence(content, options), headers.Score, links.Score]);

        var verdict = score >= options.PhishingThreshold ? Verdicts.Phishing
            : score >= options.SuspiciousThreshold ? Verdicts.Suspicious
            : Verdicts.Safe;

        return new AnalysisResult(
            verdict,
            Math.Round(score, 3),
            BuildReasons(content, headers, links),
            new AnalysisBreakdown(
                content with { Probability = Math.Round(content.Probability, 3), SpamProbability = Math.Round(content.SpamProbability, 3) },
                headers with { Score = Math.Round(headers.Score, 3) },
                links with { Score = Math.Round(links.Score, 3) }),
            BuildLimitations(email, content),
            classifier.Model?.Version);
    }

    /// <summary>
    /// How much the classifier contributes to the fused score. Halved for non-English text,
    /// where the model is outside its training distribution.
    /// </summary>
    public static double ContentEvidence(ContentResult content, ScoringOptions options)
    {
        if (!content.Evaluated)
            return 0;
        var weight = content.LanguageSupported ? options.ContentWeight : options.ContentWeight * 0.5;
        return weight * content.Probability;
    }

    private static List<string> BuildReasons(ContentResult content, ComponentResult headers, ComponentResult links)
    {
        var ruleFindings = headers.Findings.Concat(links.Findings)
            .Where(f => f.Weight > 0)
            .OrderByDescending(f => f.Weight)
            .Select(f => (f.Weight, f.Message));

        var reasons = new List<(double Weight, string Message)>(ruleFindings);

        if (content.Evaluated)
        {
            var pct = Percent(content.Probability);
            if (content.Probability >= 0.5)
            {
                var terms = content.IndicativeTerms.Count > 0
                    ? $" - strongest cues: {string.Join(", ", content.IndicativeTerms.Take(4).Select(t => $"\"{t}\""))}"
                    : "";
                reasons.Add((content.Probability, $"Wording resembles known phishing ({pct} per the text classifier){terms}"));
            }
            else if (content.SpamProbability >= 0.5)
            {
                reasons.Add((0, $"Wording looks like bulk marketing/spam ({Percent(content.SpamProbability)}), not a targeted phishing attempt (phishing {pct})"));
            }
            else
            {
                reasons.Add((0, $"Wording resembles ordinary correspondence (phishing likelihood {pct})"));
            }
        }

        // Positive evidence (e.g. "SPF, DKIM and DMARC all passed") goes last.
        reasons.AddRange(headers.Findings.Where(f => f.Weight == 0).Select(f => (0.0, f.Message)));

        return reasons
            .OrderByDescending(r => r.Weight)
            .Select(r => r.Message)
            .Distinct()
            .Take(MaxReasons)
            .ToList();
    }

    private static List<string> BuildLimitations(EmailSubmission email, ContentResult content)
    {
        var limitations = new List<string>();
        if (string.IsNullOrWhiteSpace(email.RawHeaders))
            limitations.Add("SPF/DKIM/DMARC not checked: raw headers were not supplied (Gmail's page does not display them).");
        if (!content.Evaluated)
            limitations.Add("Text classifier not applied (model unavailable or empty body).");
        else if (!content.LanguageSupported)
            limitations.Add("The text does not appear to be English; the classifier was trained on English mail, so its weight was halved.");
        return limitations;
    }

    private static string Percent(double p) => (p * 100).ToString("0", CultureInfo.InvariantCulture) + "%";
}
