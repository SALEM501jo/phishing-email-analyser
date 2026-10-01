using System.Globalization;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Reputation;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Core;

/// <summary>Runs every signal (text, sender, links, attachments, reputation) and fuses them into a verdict with human-readable reasons (Arabic for Arabic emails).</summary>
public sealed class EmailAnalyser(
    IContentClassifier classifier,
    HeaderAnalyser headerAnalyser,
    LinkAnalyser linkAnalyser,
    ScoringOptions options,
    ReputationAnalyser? reputationAnalyser = null,
    ShortLinkExpander? shortLinks = null)
{
    private const int MaxReasons = 6;
    private static readonly AttachmentAnalyser Attachments = new();
    private static readonly ObfuscationAnalyser Obfuscation = new();

    /// <summary>Full analysis including network reputation lookups (used by the API).</summary>
    public async Task<AnalysisResult> AnalyseAsync(EmailSubmission email, CancellationToken ct = default)
    {
        email = WithQrLinks(email);
        // Expand shortened links first, so their real destinations go through the link AND reputation checks.
        var expanded = shortLinks is null || email.Links is not { Count: > 0 } ? [] : await shortLinks.ExpandAsync(email.Links, ct);
        if (expanded.Count > 0)
            // No link text: the short URL as "text" would falsely trip the text-vs-destination mismatch rule.
            email = WithLinks(email, [.. email.Links!, .. expanded.Select(e => new EmailLink(null, e.Destination))]);

        var reputation = reputationAnalyser is null ? null : await reputationAnalyser.AnalyseAsync(email, ct);
        return Analyse(email, reputation, expanded);
    }

    /// <summary>Offline analysis (text, sender, links) - also used by the trainer's evaluation, where reputation is meaningless for years-old mail.</summary>
    public AnalysisResult Analyse(EmailSubmission email) => Analyse(WithQrLinks(email), null, []);

    private AnalysisResult Analyse(EmailSubmission email, ComponentResult? reputation, IReadOnlyList<ExpandedLink> expanded)
    {
        var content = classifier.Classify(email.Subject, email.Body);
        var headers = headerAnalyser.Analyse(email);
        var links = linkAnalyser.Analyse(email.Links, DomainUtils.GetEmailDomain(email.SenderEmail));
        if (expanded.Count > 0)
            links = links with
            {
                Findings = [.. links.Findings, .. expanded.Select(e => new Finding(LinkAnalyser.Source, "shortener-expanded",
                    $"Shortened link {e.ShortUrl} really leads to {DomainUtils.GetHost(e.Destination)}", 0,
                    $"الرابط المختصر {e.ShortUrl} يؤدي فعليًا إلى {DomainUtils.GetHost(e.Destination)}"))],
            };
        if (email.QrCodeUrls is { Count: > 0 } qr)
        {
            // Quishing: a QR code moves the link to the victim's phone, outside the company's mail and web filters.
            var host = DomainUtils.GetHost(qr[0]) ?? qr[0];
            var qrFinding = new Finding(LinkAnalyser.Source, "qr-code-link",
                $"The email contains a QR code linking to {host} - QR codes move you to your phone, away from security filters", 0.2,
                $"الرسالة تحتوي على رمز QR يؤدي إلى {host} - رموز QR تنقلك إلى هاتفك بعيدًا عن فلاتر الحماية");
            links = links with { Findings = [.. links.Findings, qrFinding], Score = Scoring.NoisyOr([.. links.Findings.Select(f => f.Weight), qrFinding.Weight]) };
        }
        var attachments = Attachments.Analyse(email.Attachments, email.Body);
        var obfuscation = Obfuscation.Analyse(email);

        // The UI language follows the email, independent of whether a model is loaded.
        var language = LanguageHeuristics.Detect(EmailTextNormalizer.Normalize(email.Subject, email.Body)) == Languages.Arabic
            ? Languages.Arabic
            : Languages.English;

        var otherEvidence = new[] { headers.Score, links.Score, attachments.Score, obfuscation.Score, reputation?.Score ?? 0 };
        var contentEvidence = ContentEvidence(content, options);
        var verifiedBrand = options.TrustVerifiedBrandSenders && otherEvidence.All(s => s <= 0)
                            && headers.Findings.Any(f => f.Code == "verified-brand-sender");
        if (verifiedBrand)
            contentEvidence *= options.VerifiedBrandContentFactor;
        var allFindings = headers.Findings.Concat(links.Findings).Concat(attachments.Findings).Concat(obfuscation.Findings)
            .Concat(reputation?.Findings ?? []).ToList();
        var establishedSender = !verifiedBrand && options.TrustEstablishedSenders
                                && allFindings.Any(f => f.Code == "auth-pass") && allFindings.Any(f => f.Code == "established-sender")
                                && allFindings.All(f => f.Weight <= 0.1);
        if (establishedSender)
            contentEvidence *= options.EstablishedSenderContentFactor;
        var textOnly = options.RequireCorroboration && otherEvidence.All(s => s <= 0) && contentEvidence >= options.PhishingThreshold;
        if (textOnly)
            contentEvidence = options.PhishingThreshold - 0.01;

        var score = Scoring.NoisyOr([contentEvidence, .. otherEvidence]);

        var verdict = score >= options.PhishingThreshold ? Verdicts.Phishing
            : score >= options.SuspiciousThreshold ? Verdicts.Suspicious
            : Verdicts.Safe;

        return new AnalysisResult(
            verdict,
            Math.Round(score, 3),
            BuildReasons(content, headers, links, reputation, [.. attachments.Findings, .. obfuscation.Findings], language),
            new AnalysisBreakdown(
                content with { Probability = Math.Round(content.Probability, 3), SpamProbability = Math.Round(content.SpamProbability, 3) },
                headers with { Score = Math.Round(headers.Score, 3) },
                links with { Score = Math.Round(links.Score, 3) },
                reputation is null ? null : reputation with { Score = Math.Round(reputation.Score, 3) },
                attachments with { Score = Math.Round(attachments.Score, 3) },
                obfuscation with { Score = Math.Round(obfuscation.Score, 3) }),
            BuildLimitations(email, content, reputation, language, verifiedBrand, textOnly, establishedSender),
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

    private static List<string> BuildReasons(ContentResult content, ComponentResult headers, ComponentResult links, ComponentResult? reputation, IReadOnlyList<Finding> otherFindings, string language)
    {
        var arabic = language == Languages.Arabic;
        var reasons = MergeSameDomain(headers.Findings, links.Findings)
            .Concat(reputation?.Findings ?? [])
            .Concat(otherFindings)
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

        // Context and positive evidence (where short links lead; "SPF, DKIM and DMARC all passed") go last.
        reasons.AddRange(links.Findings.Concat(headers.Findings).Where(f => f.Weight == 0).Select(f => (0.0, f.In(language))));

        return reasons
            .OrderByDescending(r => r.Weight)
            .Select(r => r.Message)
            .Distinct()
            .Take(MaxReasons)
            .ToList();
    }

    private static EmailSubmission WithLinks(EmailSubmission e, IReadOnlyList<EmailLink> links) => new()
    {
        Subject = e.Subject, SenderName = e.SenderName, SenderEmail = e.SenderEmail, ReplyTo = e.ReplyTo,
        Body = e.Body, RawHeaders = e.RawHeaders, Links = links, Attachments = e.Attachments, QrCodeUrls = e.QrCodeUrls,
    };

    /// <summary>QR-code destinations are checked exactly like ordinary links (look-alike domains, blocklists, age ...).</summary>
    private static EmailSubmission WithQrLinks(EmailSubmission e) =>
        e.QrCodeUrls is not { Count: > 0 } qr || e.Links?.Any(l => l.Text == QrLinkText) == true
            ? e
            : WithLinks(e, [.. e.Links ?? [], .. qr.Take(10).Select(u => new EmailLink(QrLinkText, u))]);

    private const string QrLinkText = "QR code";

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

    private static List<string> BuildLimitations(EmailSubmission email, ContentResult content, ComponentResult? reputation, string language,
        bool verifiedBrand = false, bool textOnly = false, bool establishedSender = false)
    {
        var arabic = language == Languages.Arabic;
        var limitations = new List<string>();
        if (reputation is { Evaluated: false } && (email.Links?.Count > 0 || email.SenderEmail is not null))
            limitations.Add(arabic
                ? "لم يتم التحقق من سمعة النطاقات أو عمرها (الخدمات الخارجية غير متاحة حاليًا)."
                : "Domain reputation and age were not checked (lookup services unavailable right now).");
        if (string.IsNullOrWhiteSpace(email.RawHeaders))
            limitations.Add(arabic
                ? "لم يتم فحص SPF/DKIM/DMARC: لم تُرسل الترويسات الخام (صفحة Gmail لا تعرضها)."
                : "SPF/DKIM/DMARC not checked: raw headers were not supplied (Gmail's page does not display them).");
        if (!content.Evaluated)
            limitations.Add(arabic
                ? "لم يُطبَّق مصنّف النصوص (النموذج غير متوفر أو نص الرسالة فارغ)."
                : "Text classifier not applied (model unavailable or empty body).");
        else if (content.LanguagePreview)
            limitations.Add(arabic
                ? "تحليل النص العربي في مرحلة تجريبية (دُرّب أساسًا على رسائل مترجمة آليًا)، لذلك خُفّض وزنه إلى النصف ولا يكفي وحده لاعتبار الرسالة تصيّدًا؛ فحوص المرسل والروابط تعمل بالكامل."
                : "Text analysis for this language is in preview (trained mostly on machine-translated mail), so its weight was halved and wording alone can't make a phishing verdict; sender and link checks still apply in full.");
        else if (!content.LanguageSupported)
            limitations.Add(arabic
                ? "مصنّف النصوص الحالي لم يُدرَّب على اللغة العربية بعد، لذلك خُفّض وزنه إلى النصف؛ فحوص المرسل والروابط تعمل بالكامل."
                : "The classifier was not trained on this email's language, so its weight was halved; sender and link checks still apply in full.");
        if (verifiedBrand)
            limitations.Add(arabic
                ? "الرسالة مرسلة من النطاق الحقيقي للجهة وتم التحقق منها، لذلك خُفّض وزن تحليل النص."
                : "Sent from the brand's verified real domain, so the wording analysis was down-weighted.");
        if (establishedSender)
            limitations.Add(arabic
                ? "المرسل موثَّق ونطاقه مسجّل منذ أكثر من سنة، لذلك خُفّض وزن تحليل النص إلى النصف."
                : "The sender is authenticated and its domain has existed for over a year, so the wording analysis counts half.");
        if (textOnly)
            limitations.Add(arabic
                ? "الصياغة وحدها تبدو مريبة، ولا يوجد دليل من المرسل أو الروابط؛ لذلك صُنّفت مريبة وليست تصيّدًا مؤكدًا."
                : "Only the wording looks suspicious - there is no sender or link evidence - so this is marked suspicious rather than phishing.");
        return limitations;
    }

    private static string Percent(double p) => (p * 100).ToString("0", CultureInfo.InvariantCulture) + "%";
}
