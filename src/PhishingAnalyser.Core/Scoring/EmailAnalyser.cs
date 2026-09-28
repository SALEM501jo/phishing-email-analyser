using System.Globalization;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Core;

/// <summary>Runs the three signals and fuses them into a verdict with human-readable reasons (Arabic for Arabic emails).</summary>
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

        // The UI language follows the email, independent of whether a model is loaded.
        var language = LanguageHeuristics.Detect(EmailTextNormalizer.Normalize(email.Subject, email.Body)) == Languages.Arabic
            ? Languages.Arabic
            : Languages.English;

        var score = Scoring.NoisyOr([ContentEvidence(content, options), headers.Score, links.Score]);

        var verdict = score >= options.PhishingThreshold ? Verdicts.Phishing
            : score >= options.SuspiciousThreshold ? Verdicts.Suspicious
            : Verdicts.Safe;

        return new AnalysisResult(
            verdict,
            Math.Round(score, 3),
            BuildReasons(content, headers, links, language),
            new AnalysisBreakdown(
                content with { Probability = Math.Round(content.Probability, 3), SpamProbability = Math.Round(content.SpamProbability, 3) },
                headers with { Score = Math.Round(headers.Score, 3) },
                links with { Score = Math.Round(links.Score, 3) }),
            BuildLimitations(email, content, language),
            classifier.Model?.Version,
            language);
    }

    /// <summary>
    /// How much the classifier contributes to the fused score. Halved when the email's language
    /// is outside what the model was trained on.
    /// </summary>
    public static double ContentEvidence(ContentResult content, ScoringOptions options)
    {
        if (!content.Evaluated)
            return 0;
        var weight = content.LanguageSupported ? options.ContentWeight : options.ContentWeight * 0.5;
        return weight * content.Probability;
    }

    private static List<string> BuildReasons(ContentResult content, ComponentResult headers, ComponentResult links, string language)
    {
        var arabic = language == Languages.Arabic;
        var reasons = MergeSameDomain(headers.Findings, links.Findings)
            .Where(f => f.Weight > 0)
            .Select(f => (f.Weight, Message: f.In(language)))
            .ToList();

        // A model that wasn't trained on this language shouldn't describe the wording; the limitation note covers it.
        if (content.Evaluated && content.LanguageSupported)
        {
            var pct = Percent(content.Probability);
            if (content.Probability >= 0.5)
            {
                var cues = content.IndicativeTerms.Take(4).Select(t => $"\"{t}\"").ToList();
                reasons.Add((content.Probability, arabic
                    ? $"صياغة الرسالة تشبه رسائل التصيّد المعروفة ({pct} حسب مصنّف النصوص)" + (cues.Count > 0 ? $" - أبرز المؤشرات: {string.Join("، ", cues)}" : "")
                    : $"Wording resembles known phishing ({pct} per the text classifier)" + (cues.Count > 0 ? $" - strongest cues: {string.Join(", ", cues)}" : "")));
            }
            else if (content.SpamProbability >= 0.5)
            {
                reasons.Add((0, arabic
                    ? $"الصياغة تشبه الرسائل التسويقية الجماعية ({Percent(content.SpamProbability)}) وليست محاولة تصيّد موجّهة (احتمال التصيّد {pct})"
                    : $"Wording looks like bulk marketing/spam ({Percent(content.SpamProbability)}), not a targeted phishing attempt (phishing {pct})"));
            }
            else
            {
                reasons.Add((0, arabic
                    ? $"الصياغة تشبه المراسلات العادية (احتمال التصيّد {pct})"
                    : $"Wording resembles ordinary correspondence (phishing likelihood {pct})"));
            }
        }

        // Positive evidence (e.g. "SPF, DKIM and DMARC all passed") goes last.
        reasons.AddRange(headers.Findings.Where(f => f.Weight == 0).Select(f => (0.0, f.In(language))));

        return reasons
            .OrderByDescending(r => r.Weight)
            .Select(r => r.Message)
            .Distinct()
            .Take(MaxReasons)
            .ToList();
    }

    /// <summary>
    /// When the sender and the links use the same look-alike domain, say it once ("... - the links use the same
    /// domain") instead of two near-identical reasons. Scoring is unaffected; this only tidies the explanation.
    /// </summary>
    private static IEnumerable<Finding> MergeSameDomain(IReadOnlyList<Finding> headerFindings, IReadOnlyList<Finding> linkFindings)
    {
        var sender = headerFindings.FirstOrDefault(f => f.Code == "lookalike-sender" && f.Target is not null);
        foreach (var f in headerFindings)
        {
            var sameInLinks = f == sender && linkFindings.Any(l => l.Code == "lookalike-domain" && l.Target == f.Target);
            yield return sameInLinks
                ? f with
                {
                    Message = f.Message + " - the links use the same domain",
                    MessageArabic = f.MessageArabic + " - والروابط تستخدم النطاق نفسه",
                }
                : f;
        }
        foreach (var l in linkFindings)
            if (!(sender is not null && l.Code == "lookalike-domain" && l.Target == sender.Target))
                yield return l;
    }

    private static List<string> BuildLimitations(EmailSubmission email, ContentResult content, string language)
    {
        var arabic = language == Languages.Arabic;
        var limitations = new List<string>();
        if (string.IsNullOrWhiteSpace(email.RawHeaders))
            limitations.Add(arabic
                ? "لم يتم فحص SPF/DKIM/DMARC: لم تُرسل الترويسات الخام (صفحة Gmail لا تعرضها)."
                : "SPF/DKIM/DMARC not checked: raw headers were not supplied (Gmail's page does not display them).");
        if (!content.Evaluated)
            limitations.Add(arabic
                ? "لم يُطبَّق مصنّف النصوص (النموذج غير متوفر أو نص الرسالة فارغ)."
                : "Text classifier not applied (model unavailable or empty body).");
        else if (!content.LanguageSupported)
            limitations.Add(arabic
                ? "مصنّف النصوص الحالي لم يُدرَّب على اللغة العربية بعد، لذلك خُفّض وزنه إلى النصف؛ فحوص المرسل والروابط تعمل بالكامل."
                : "The classifier was not trained on this email's language, so its weight was halved; sender and link checks still apply in full.");
        return limitations;
    }

    private static string Percent(double p) => (p * 100).ToString("0", CultureInfo.InvariantCulture) + "%";
}
