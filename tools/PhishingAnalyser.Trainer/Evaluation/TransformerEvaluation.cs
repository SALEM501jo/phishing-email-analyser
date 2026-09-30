using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Trainer.Corpus;

namespace PhishingAnalyser.Trainer.Evaluation;

/// <summary>
/// --evaluate-transformer: turns the exported ONNX model into a shippable one, measured the same way as the
/// linear model so the two can be compared honestly.
///   1. Platt calibration of the phishing probability on held-out data (modern English tune split + Arabic val)
///   2. model-info.json (version, calibration, languages en+ar) next to model.onnx
///   3. reload exactly as the API does (transformer decides, linear model explains) and run the FULL analyser
///      on the same modern English tune/test emails as the linear model; thresholds tuned on tune only
///   4. Arabic and LLM-generated test rows (text only - no sender/links exist for them), content evidence only
///   5. the unseen probe emails, in both languages
/// All data used here was held out from transformer training (train split only was trained on).
/// </summary>
public static class TransformerEvaluation
{
    public static void Run(string directory, IReadOnlyList<CorpusEmail> modernTune, IReadOnlyList<CorpusEmail> modernTest, string processedDir)
    {
        var total = Stopwatch.StartNew();
        var infoPath = Path.Combine(directory, ContentClassifier.ModelInfoFileName);
        File.Delete(infoPath); // start uncalibrated

        var val = ReadRows(Path.Combine(processedDir, "transformer_val.jsonl"));
        var test = ReadRows(Path.Combine(processedDir, "transformer_test.jsonl"));

        // ---------------------------------------------------------------- 1. calibration
        Console.WriteLine($"Calibrating on {modernTune.Count} modern English tune emails + {val.Count(r => r.Language == "ar")} Arabic val rows ...");
        using (var raw = TransformerClassifier.Load(directory))
        {
            var rows = modernTune.Select(e => ((double)raw.Probabilities(e.Text)[EmailClasses.Phishing], e.Class == EmailClasses.Phishing))
                .Concat(val.Where(r => r.Language == "ar").Select(r => ((double)raw.Probabilities(r.Text)[EmailClasses.Phishing], r.Label == EmailClasses.Phishing)))
                .ToList();
            var calibration = Calibration.FitPlatt(rows);
            var brierBefore = Calibration.Brier(rows);
            var brierAfter = Calibration.Brier(rows.Select(r => (calibration.Apply(r.Item1), r.Item2)));
            Console.WriteLine($"  Platt A={calibration.A} B={calibration.B}  Brier {brierBefore} -> {brierAfter}  ({total.Elapsed.TotalMinutes:F1} min)");

            var modelBytes = File.ReadAllBytes(Path.Combine(directory, "model.onnx"));
            var tinfo = JsonSerializer.Deserialize<TransformerInfo>(File.ReadAllText(Path.Combine(directory, "transformer-info.json")), ContentClassifier.JsonOptions)!;
            var info = new ModelInfo(
                $"{DateTime.UtcNow:yyyy.MM.dd}-t{Convert.ToHexString(SHA256.HashData(modelBytes))[..8].ToLowerInvariant()}",
                File.GetLastWriteTimeUtc(Path.Combine(directory, "model.onnx")),
                $"Multilingual transformer ({tinfo.Base}, int8 ONNX) fine-tuned on English + Arabic (NLLB-translated and LLM-generated paired) mail, 3 classes; Platt-calibrated. Explanations from the linear model.",
                calibration, Thresholds: null, Languages: [Languages.English],
                // Arabic stays in preview: on LLM-generated (realistic, transactional) Arabic test mail the first
                // model flagged 14% of legitimate emails as phishing. Promote it once that is fixed.
                PreviewLanguages: [Languages.Arabic]);
            File.WriteAllText(infoPath, JsonSerializer.Serialize(info, ContentClassifier.JsonOptions));
            _calibrationReport = new { brierBefore, brierAfter, rows = rows.Count };
        }

        // ---------------------------------------------------------------- 2. end-to-end, as the API runs it
        var linear = ContentClassifier.Load(Path.Combine("models", "phishing-content-model.zip"));
        using var transformer = TransformerClassifier.Load(directory);
        var shipped = new HybridContentClassifier(transformer, linear);
        var defaults = new ScoringOptions();
        var e2e = new EndToEndEvaluator(shipped, defaults);

        Console.WriteLine($"Scoring {modernTune.Count + modernTest.Count} modern English emails end to end ...");
        var tuneScored = e2e.Score(modernTune);
        var testScored = e2e.Score(modernTest);
        var (phishingThreshold, suspiciousThreshold) = EndToEndEvaluator.TuneThresholds(tuneScored);
        var report = EndToEndEvaluator.Report(testScored, phishingThreshold, suspiciousThreshold);
        Print("transformer, thresholds tuned on tune split, test split", report);

        var saved = JsonSerializer.Deserialize<ModelInfo>(File.ReadAllText(infoPath), ContentClassifier.JsonOptions)!
            with { Thresholds = new VerdictThresholds(phishingThreshold, suspiciousThreshold) };
        File.WriteAllText(infoPath, JsonSerializer.Serialize(saved, ContentClassifier.JsonOptions));

        // The linear model on the very same emails, for a like-for-like comparison.
        var linearOptions = new ScoringOptions();
        if (linear.Model?.Thresholds is { } lt) { linearOptions.PhishingThreshold = lt.Phishing; linearOptions.SuspiciousThreshold = lt.Suspicious; }
        var linearReport = EndToEndEvaluator.Report(new EndToEndEvaluator(linear, linearOptions).Score(modernTest),
            linearOptions.PhishingThreshold, linearOptions.SuspiciousThreshold);
        Print($"linear model {linear.Model?.Version} (current), same test emails", linearReport);

        // ---------------------------------------------------------------- 3. Arabic + generated (content only)
        // Each group is scored twice: as shipped (Arabic in preview = half weight) and as if Arabic were promoted
        // to full support. The promoted numbers decide whether Arabic leaves preview - on evidence, not by hand.
        var options = new ScoringOptions { PhishingThreshold = phishingThreshold, SuspiciousThreshold = suspiciousThreshold };
        var promoted = new PromotedLanguage(shipped, Languages.Arabic);
        static string Group(TrainingRow r) =>
            $"{r.Language}:" + (r.Source.StartsWith("generated-test", StringComparison.Ordinal) ? "independent"
                : r.Source.StartsWith("generated", StringComparison.Ordinal) ? "generated" : "translated");
        var heldOut = test.Where(r => r.Language == Languages.Arabic || r.Source.StartsWith("generated", StringComparison.Ordinal))
            .Where(r => r.Label != EmailClasses.Spam) // spam excluded, as in the end-to-end numbers
            .ToList();
        (BinaryMetrics PhishingVerdict, BinaryMetrics AnyWarning) Score(IEnumerable<TrainingRow> rows, IContentClassifier classifier)
        {
            var scored = rows.Select(r => (r.Label == EmailClasses.Phishing, EmailAnalyser.ContentEvidence(classifier.Classify(null, r.Text), options))).ToList();
            return (Metrics.Binary(scored, phishingThreshold), Metrics.Binary(scored, suspiciousThreshold));
        }
        var contentOnly = heldOut.GroupBy(Group).OrderBy(g => g.Key).ToDictionary(g => g.Key, g =>
        {
            var asShipped = Score(g, shipped);
            var ifPromoted = g.Key.StartsWith("ar", StringComparison.Ordinal) ? Score(g, promoted) : asShipped;
            Console.WriteLine($"  {g.Key,-15} shipped : phishing verdict {asShipped.PhishingVerdict}");
            Console.WriteLine($"  {"",-15}           any warning      {asShipped.AnyWarning}");
            if (g.Key.StartsWith("ar", StringComparison.Ordinal))
            {
                Console.WriteLine($"  {"",-15} promoted: phishing verdict {ifPromoted.PhishingVerdict}");
                Console.WriteLine($"  {"",-15}           any warning      {ifPromoted.AnyWarning}");
            }
            return new { shipped = new { asShipped.PhishingVerdict, asShipped.AnyWarning }, ifPromoted = new { ifPromoted.PhishingVerdict, ifPromoted.AnyWarning } };
        });

        // Promotion rule for Arabic, on REALISTIC Arabic mail (LLM-generated, including the independent generator):
        // few false alarms, most phishing caught, enough data to trust it, and translated mail must not regress.
        var realistic = heldOut.Where(r => r.Language == Languages.Arabic && Group(r) != "ar:translated").ToList();
        var translatedArabic = heldOut.Where(r => Group(r) == "ar:translated").ToList();
        var (realPhishing, realWarning) = Score(realistic, promoted);
        var (translatedPhishing, _) = Score(translatedArabic, promoted);
        var checks = new Dictionary<string, bool>
        {
            ["at least 100 legitimate and 100 phishing realistic Arabic test emails"] = realPhishing.Count - realPhishing.Positives >= 100 && realPhishing.Positives >= 100,
            ["legitimate -> 'phishing' at most 1%"] = realPhishing.FalsePositiveRate <= 0.01,
            ["legitimate -> any warning at most 3%"] = realWarning.FalsePositiveRate <= 0.03,
            ["phishing gets a warning at least 80%"] = realWarning.Recall >= 0.80,
            ["translated Arabic: legitimate -> 'phishing' at most 1%"] = translatedPhishing.FalsePositiveRate <= 0.01,
        };
        var promote = checks.Values.All(v => v);
        Console.WriteLine($"\nArabic promotion ({realistic.Count} realistic test emails, full weight): {(promote ? "PROMOTED to full support" : "stays in PREVIEW")}");
        foreach (var (check, ok) in checks)
            Console.WriteLine($"  [{(ok ? "x" : " ")}] {check}");
        if (promote)
        {
            saved = saved with { Languages = [Languages.English, Languages.Arabic], PreviewLanguages = null };
            File.WriteAllText(infoPath, JsonSerializer.Serialize(saved, ContentClassifier.JsonOptions));
        }
        var arabicPromotion = new { promoted = promote, checks, realisticArabic = new { phishingVerdict = realPhishing, anyWarning = realWarning } };

        // ---------------------------------------------------------------- 4. probes
        var probes = Probes.Select(p =>
        {
            var r = shipped.Classify(p.Subject, p.Body);
            Console.WriteLine($"  {r.Probability,7:P1} {r.SpamProbability,7:P1} [{r.Language}] {p.Subject}");
            return new { p.Subject, language = r.Language, phishing = Math.Round(r.Probability, 4), spam = Math.Round(r.SpamProbability, 4) };
        }).ToList();

        var metrics = new
        {
            model = saved,
            calibration = _calibrationReport,
            endToEndModernEnglish = new
            {
                note = "Full analyser (transformer + header + link rules), DOM-equivalent input, same modern tune/test emails as the linear model. Thresholds tuned on tune only.",
                transformer = report,
                linearBaseline = linearReport,
            },
            contentOnlyHeldOut = new
            {
                note = "Text-only rows (no sender or links exist for translated/generated mail): content evidence at the tuned thresholds. Spam excluded, as in the end-to-end numbers.",
                groups = contentOnly,
            },
            arabicPromotion,
            probes,
            evaluationMinutes = Math.Round(total.Elapsed.TotalMinutes, 1),
        };
        var metricsPath = Path.Combine(directory, "metrics.json");
        File.WriteAllText(metricsPath, JsonSerializer.Serialize(metrics, ContentClassifier.JsonOptions));
        Console.WriteLine($"\nWrote {infoPath} and {metricsPath} ({total.Elapsed.TotalMinutes:F1} min)");
    }

    private static object? _calibrationReport;

    private static void Print(string label, VerdictReport r)
    {
        Console.WriteLine($"  {label}: phishing>={r.PhishingThreshold:F2} suspicious>={r.SuspiciousThreshold:F2}");
        Console.WriteLine($"    'phishing' verdict : {r.PhishingVerdict}");
        Console.WriteLine($"    any warning        : {r.AnyWarning}");
        foreach (var (cls, row) in r.Verdicts)
            Console.WriteLine($"    {cls,-11} -> " + string.Join("  ", row.Select(kv => $"{kv.Key}={kv.Value}")));
    }

    private static List<TrainingRow> ReadRows(string path) =>
        File.ReadLines(path).Select(l => JsonSerializer.Deserialize<TrainingRow>(l, TransformerDataset.Json)!).ToList();

    private static readonly (string Subject, string Body)[] Probes =
    [
        ("Your account has been suspended", "Dear customer, we detected unusual activity. Verify your identity within 24 hours or your account will be permanently closed. Click here to restore access."),
        ("You have (1) pending package", "Your parcel could not be delivered due to an unpaid customs fee of $1.99. Update your payment information here."),
        ("50% off everything this weekend only!", "Shop our biggest sale of the year. Free shipping on orders over $50. Use code SAVE50 at checkout. Unsubscribe from these emails at any time."),
        ("Your order #112-4432 has shipped", "Good news! Your order is on its way and should arrive Thursday. You can track your package from your orders page."),
        ("Minutes from Tuesday's sprint review", "Hi all, attached are the notes from the review. Action items: Omar to update the API docs, Lina to fix the flaky login test. Next review is on the 14th."),
        // Legitimate transactional mail - the known weak spot (both round-1 and round-2 models scored an Apple receipt >90%).
        ("Your receipt from Apple", "Receipt. Order ID MT2K8Q9. iCloud+ 50 GB, 0.99 USD. Billed to Visa ending 4242. If you have questions about your bill, visit Apple Support."),
        ("Your Uber trip on Tuesday", "Thanks for riding, Salem. Total 3.45 JOD. Trip from Abdali to Sweifieh, 14 minutes. Rate your driver in the app. Download PDF receipt."),
        ("Payment received", "We have received your payment of 23.40 JOD for your electricity bill, account 7731-22. Thank you for using eFAWATEERcom."),
        ("Your verification code", "Your verification code is 482913. It expires in 10 minutes. Never share this code with anyone, including our staff."),
        ("Security alert: new sign-in", "We noticed a new sign-in to your Google Account on a Windows device. If this was you, you don't need to do anything. If not, we'll help you secure your account. Check activity."),
        ("Your weekly deals from Noon", "Top picks for you this week: headphones from 19 JOD, smart watches 25% off, and free delivery on your first order. Shop now in the app. You are receiving this because you subscribed. Unsubscribe."),
        ("You won a gift card", "Congratulations! You have been selected to receive a 500 USD Amazon gift card. Claim your reward now by confirming your card details for shipping."),
        ("تم تعليق حسابك", "عزيزي العميل، لاحظنا نشاطاً غير معتاد على حسابك. يرجى تأكيد هويتك وإدخال كلمة المرور خلال ٢٤ ساعة وإلا سيتم إغلاق الحساب نهائياً. اضغط هنا لاستعادة الوصول."),
        ("شحنتك بانتظار دفع رسوم الجمارك", "لم نتمكن من توصيل طردك بسبب رسوم جمركية غير مدفوعة بقيمة ١٫٥ دينار. يرجى تحديث بيانات بطاقتك عبر الرابط لإعادة الجدولة."),
        ("تم شحن طلبك رقم 4432", "أخبار سارة! طلبك في الطريق ومن المتوقع وصوله يوم الخميس. يمكنك تتبع الشحنة من صفحة الطلبات في التطبيق."),
        ("محضر اجتماع يوم الثلاثاء", "مرحباً بالجميع، مرفق ملاحظات الاجتماع. المهام: عمر يحدّث توثيق الواجهة البرمجية، وليلى تصلح اختبار تسجيل الدخول. الاجتماع القادم يوم ١٤."),
    ];
}
