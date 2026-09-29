using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.ML;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Trainer.Corpus;
using PhishingAnalyser.Trainer.Evaluation;

// Usage: dotnet run --project tools/PhishingAnalyser.Trainer -c Release -- [dataDir=data/raw] [outDir=models]
//        dotnet run --project tools/PhishingAnalyser.Trainer -c Release -- --eval-inbox data/eval/All-mail.mbox
//        dotnet run --project tools/PhishingAnalyser.Trainer -c Release -- --evaluate-transformer   (after the ONNX export)
if (args.ElementAtOrDefault(0) == "--eval-inbox")
{
    var mbox = args.ElementAtOrDefault(1) ?? throw new ArgumentException("Pass the path of the Takeout .mbox file");
    var classifier = ContentClassifier.Load(Path.Combine("models", "phishing-content-model.zip"));
    var scoring = new ScoringOptions();
    if (classifier.Model?.Thresholds is { } t) { scoring.PhishingThreshold = t.Phishing; scoring.SuspiciousThreshold = t.Suspicious; }
    var analyser = new EmailAnalyser(classifier, new PhishingAnalyser.Core.Rules.HeaderAnalyser(PhishingAnalyser.Core.Rules.BrandCatalog.Default),
                                     new PhishingAnalyser.Core.Rules.LinkAnalyser(PhishingAnalyser.Core.Rules.BrandCatalog.Default), scoring);
    var inboxReport = InboxEvaluation.Run(mbox, analyser);
    var reportPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(mbox))!, "inbox-report.json"); // stays in git-ignored data/
    File.WriteAllText(reportPath, JsonSerializer.Serialize(new { model = classifier.Model?.Version, report = inboxReport }, ContentClassifier.JsonOptions));
    Console.WriteLine($"Wrote {reportPath}");
    return;
}

var processedDir = Path.Combine("data", "processed");
if (args.ElementAtOrDefault(0) == "--prepare-transformer")
{
    TransformerDataset.Prepare(args.ElementAtOrDefault(1) ?? processedDir);
    return;
}
var exportOnly = args.ElementAtOrDefault(0) == "--export-corpus";
var evaluateTransformer = args.ElementAtOrDefault(0) == "--evaluate-transformer"; // calibrate + evaluate models/transformer/
if (exportOnly || evaluateTransformer)
    args = args.Skip(1).ToArray();

var dataDir = args.ElementAtOrDefault(0) ?? Path.Combine("data", "raw");
var outDir = args.ElementAtOrDefault(1) ?? "models";
Directory.CreateDirectory(outDir);

const int Seed = 42;
var ml = new MLContext(seed: Seed);
var total = Stopwatch.StartNew();

// ------------------------------------------------------------------ 1. corpus
Console.WriteLine($"Building corpus from {Path.GetFullPath(dataDir)}");
var (emails, sourceStats) = CorpusBuilder.Build(CorpusBuilder.DefaultSources(dataDir), Seed);

var split = emails.ToLookup(CorpusBuilder.SplitOf);
List<CorpusEmail> Where(Split s, bool? modern = null) =>
    split[s].Where(e => modern is null || e.Modern == modern).ToList();

var oldTrain = Where(Split.Train, modern: false);
var oldTest = Where(Split.Test, modern: false);
var modernTrain = Where(Split.Train, modern: true);
var modernTune = Where(Split.Tune, modern: true);
var modernTest = Where(Split.Test, modern: true);

Console.WriteLine("\nCorpus (after cleaning, de-duplication and caps):");
foreach (var g in emails.GroupBy(e => (e.Modern ? "modern" : "old", e.Class)).OrderBy(g => g.Key))
    Console.WriteLine($"  {g.Key.Item1,-7} {g.Key.Class,-11} {g.Count(),7}");
Console.WriteLine($"  splits: old train={oldTrain.Count} old test={oldTest.Count} | modern train={modernTrain.Count} tune={modernTune.Count} test={modernTest.Count}");

if (evaluateTransformer)
{
    TransformerEvaluation.Run(Path.Combine("models", "transformer"), modernTune, modernTest, processedDir);
    return;
}

if (exportOnly)
{
    // Same confident-learning flags as the linear model, so the transformer trains on the same cleaned labels.
    var (kept, _) = ConfidentLearning.Clean([.. oldTrain, .. modernTrain],
        rows => ContentClassifier.FromModel(ml, Train("fold model", rows), ml.Data.LoadFromEnumerable(Array.Empty<EmailTextInput>()).Schema));
    var keptSet = kept.ToHashSet(ReferenceEqualityComparer.Instance);
    var issues = oldTrain.Concat(modernTrain).Where(e => !keptSet.Contains(e)).ToHashSet<CorpusEmail>(ReferenceEqualityComparer.Instance);
    TransformerDataset.Export(emails, issues, Path.Combine(processedDir, "corpus.jsonl"));
    return;
}

// ------------------------------------------------------------------ 2. experiments
ITransformer Train(string name, IReadOnlyCollection<CorpusEmail> rows)
{
    Console.WriteLine($"\nTraining [{name}] on {rows.Count} emails ...");
    var sw = Stopwatch.StartNew();
    var view = ml.Data.Cache(ml.Data.LoadFromEnumerable(rows.Select(e => new EmailTextInput { Text = e.Text, Label = e.Class })));
    var trainer = ml.MulticlassClassification.Trainers.SdcaMaximumEntropy(maximumNumberOfIterations: 30);
    var model = ContentPipeline.Build(ml, FeatureSet.WordsAndChars, trainer).Fit(view);
    Console.WriteLine($"  trained in {sw.Elapsed.TotalSeconds:F0}s");
    return model;
}

object Evaluate(string name, ContentClassifier classifier, IReadOnlyList<CorpusEmail> rows)
{
    var predictions = rows.Select(e => (e, p: classifier.Probabilities(e.Text))).ToList();
    var binary = Metrics.Binary(predictions.Select(x => (x.e.Class == EmailClasses.Phishing, (double)x.p[EmailClasses.Phishing])).ToList(), 0.5);
    var confusion = Metrics.Confusion(predictions.Select(x => (x.e.Class, x.p.MaxBy(kv => kv.Value).Key)), EmailClasses.All);
    var accuracy = predictions.Count(x => x.p.MaxBy(kv => kv.Value).Key == x.e.Class) / (double)Math.Max(1, predictions.Count);

    Console.WriteLine($"  {name,-32} phishing-vs-rest: {binary}   3-class accuracy={accuracy:P2}");
    Metrics.PrintConfusion(confusion);

    var perSource = predictions.GroupBy(x => x.e.Source).OrderBy(g => g.Key).ToDictionary(g => g.Key,
        g => Math.Round(g.Count(x => x.p.MaxBy(kv => kv.Value).Key == x.e.Class) / (double)g.Count(), 4));
    return new { phishingVsRest = binary, threeClassAccuracy = Math.Round(accuracy, 4), confusion, accuracyBySource = perSource };
}

DataViewSchema InputSchema() => ml.Data.LoadFromEnumerable(Array.Empty<EmailTextInput>()).Schema;

// Experiment 1: the old approach - train on 1990s-2008 mail only - tested on today's mail.
var oldOnly = ContentClassifier.FromModel(ml, Train("old data only", oldTrain), InputSchema());
Console.WriteLine("\nExperiment 1 - trained on OLD mail only:");
var exp1 = new
{
    oldTest = Evaluate("old test (same era)", oldOnly, oldTest),
    modernTest = Evaluate("modern test (2022-2026)", oldOnly, modernTest),
};

// Experiment 2: the shipped model - old + modern training data, after confident-learning label cleanup.
Console.WriteLine("\nCleaning noisy labels (honeypot / spam trap) with out-of-fold predictions ...");
var (cleanTrain, labelIssues) = ConfidentLearning.Clean([.. oldTrain, .. modernTrain],
    rows => ContentClassifier.FromModel(ml, Train("fold model", rows), InputSchema()));
Console.WriteLine($"  removed {oldTrain.Count + modernTrain.Count - cleanTrain.Count} likely-mislabelled training emails:");
foreach (var issue in labelIssues)
    Console.WriteLine($"    {issue.Source,-30} labelled {issue.GivenClass,-10} but clearly {issue.PredictedClass,-10} x{issue.Count}");

var finalModel = Train("old + modern, cleaned (shipped)", cleanTrain);
var modelPath = Path.Combine(outDir, "phishing-content-model.zip");
var infoPath = Path.Combine(outDir, ContentClassifier.ModelInfoFileName);
ml.Model.Save(finalModel, InputSchema(), modelPath);

var version = $"{DateTime.UtcNow:yyyy.MM.dd}-{Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(modelPath)))[..8].ToLowerInvariant()}";
var info = new ModelInfo(version, DateTime.UtcNow,
    "3-class (legitimate/spam/phishing) SDCA maximum-entropy on word 1-2-grams + char 3-grams; old + 2022-2026 English mail; confident-learning label cleanup; Platt-calibrated");
void SaveInfo() => File.WriteAllText(infoPath, JsonSerializer.Serialize(info, ContentClassifier.JsonOptions));
SaveInfo();
Console.WriteLine($"\nSaved {modelPath} ({new FileInfo(modelPath).Length / 1024} KB), version {version}");

// Calibrate the phishing probability on the TUNE split (Platt scaling).
var raw = ContentClassifier.Load(modelPath);
var tuneRaw = modernTune.Select(e => ((double)raw.Probabilities(e.Text)[EmailClasses.Phishing], e.Class == EmailClasses.Phishing)).ToList();
info = info with { Calibration = Calibration.FitPlatt(tuneRaw) };
var brierBefore = Calibration.Brier(tuneRaw);
var brierAfter = Calibration.Brier(tuneRaw.Select(r => (info.Calibration.Apply(r.Item1), r.Item2)));
Console.WriteLine($"  Platt calibration A={info.Calibration.A} B={info.Calibration.B}  Brier score on tune: {brierBefore} -> {brierAfter}");
SaveInfo();

// Reload from disk exactly as the API will.
var shipped = ContentClassifier.Load(modelPath);
Console.WriteLine("\nExperiment 2 - trained on OLD + MODERN mail (shipped model):");
var exp2 = new
{
    oldTest = Evaluate("old test", shipped, oldTest),
    modernTest = Evaluate("modern test (2022-2026)", shipped, modernTest),
};

var (phishingTerms, legitTerms) = shipped.TopWeightedTerms(30);
Console.WriteLine("\nTerms pushing towards PHISHING:   " + string.Join(", ", phishingTerms));
Console.WriteLine("Terms pushing towards LEGITIMATE: " + string.Join(", ", legitTerms));

// ------------------------------------------------------------------ 3. end-to-end + threshold calibration
Console.WriteLine("\nEnd-to-end (full analyser, DOM-equivalent input) on modern mail:");
var defaults = new ScoringOptions();
var e2e = new EndToEndEvaluator(shipped, defaults);
var tuneScored = e2e.Score(modernTune);
var testScored = e2e.Score(modernTest);

var before = EndToEndEvaluator.Report(testScored, defaults.PhishingThreshold, defaults.SuspiciousThreshold);
var (tunedPhishing, tunedSuspicious) = EndToEndEvaluator.TuneThresholds(tuneScored);
var after = EndToEndEvaluator.Report(testScored, tunedPhishing, tunedSuspicious);
info = info with { Thresholds = new VerdictThresholds(tunedPhishing, tunedSuspicious) };
SaveInfo();

void PrintVerdicts(string label, VerdictReport r)
{
    Console.WriteLine($"  {label}: thresholds phishing>={r.PhishingThreshold:F2} suspicious>={r.SuspiciousThreshold:F2}");
    Console.WriteLine($"    'phishing' verdict : {r.PhishingVerdict}");
    Console.WriteLine($"    any warning        : {r.AnyWarning}");
    foreach (var (cls, row) in r.Verdicts)
        Console.WriteLine($"    {cls,-11} → " + string.Join("  ", row.Select(kv => $"{kv.Key}={kv.Value}")));
}
PrintVerdicts("default thresholds 0.70/0.40 (test split)", before);
PrintVerdicts("thresholds tuned on tune split, reported on test split", after);

var ruleRates = EndToEndEvaluator.RuleRates([.. tuneScored, .. testScored]);
Console.WriteLine("\n  Rule firing rates (phishing vs legitimate):");
foreach (var r in ruleRates)
    Console.WriteLine($"    {r.Code,-24} phishing {r.PhishingRate,7:P1}   legitimate {r.LegitimateRate,7:P1}");

var auth = e2e.AuthenticationStats(emails.Where(e => e.Modern && e.Class == EmailClasses.Phishing));
Console.WriteLine("\n  SPF/DKIM/DMARC on real modern phishing: " + string.Join(", ", auth.Select(kv => $"{kv.Key}={kv.Value}")));

// ------------------------------------------------------------------ 4. probes + report
var probes = new (string Subject, string Body)[]
{
    ("Your account has been suspended", "Dear customer, we detected unusual activity. Verify your identity within 24 hours or your account will be permanently closed. Click here to restore access."),
    ("Invoice #4821 overdue - action required", "Please review the attached invoice and confirm payment details immediately to avoid late fees. Login with your email password to view the document."),
    ("You have (1) pending package", "Your parcel could not be delivered due to an unpaid customs fee of $1.99. Update your payment information here."),
    ("50% off everything this weekend only!", "Shop our biggest sale of the year. Free shipping on orders over $50. Use code SAVE50 at checkout. Unsubscribe from these emails at any time."),
    ("Your order #112-4432 has shipped", "Good news! Your order is on its way and should arrive Thursday. You can track your package from your orders page."),
    ("Lunch tomorrow?", "Hey, are we still on for lunch tomorrow at 1? I can book the place near the office. Let me know."),
    ("Minutes from Tuesday's sprint review", "Hi all, attached are the notes from the review. Action items: Omar to update the API docs, Lina to fix the flaky login test. Next review is on the 14th."),
    ("Reset your password", "We received a request to reset the password for your account. If you made this request, use the link below within 30 minutes. If you didn't, you can ignore this email."),
};
Console.WriteLine("\nProbe emails (unseen):   phishing / spam");
var probeResults = probes.Select(p =>
{
    var r = shipped.Classify(p.Subject, p.Body);
    Console.WriteLine($"  {r.Probability,7:P1} {r.SpamProbability,7:P1}  {p.Subject}   [{string.Join(", ", r.IndicativeTerms)}]");
    return new { p.Subject, phishing = Math.Round(r.Probability, 4), spam = Math.Round(r.SpamProbability, 4), terms = r.IndicativeTerms };
}).ToList();

var report = new
{
    model = info,
    calibration = new { brierBefore, brierAfter },
    labelCleaning = new { removed = oldTrain.Count + modernTrain.Count - cleanTrain.Count, issues = labelIssues },
    datasets = new
    {
        zenodo = "Phishing Email Curated Datasets (Champa et al.), doi:10.5281/zenodo.8339691, CC BY 4.0",
        phishingPot = "github.com/rf-peixoto/phishing_pot - honeypot phishing captures 2022-2026",
        modernHam = "Public mailing-list archives 2024-2026: mail.python.org, lists.fedoraproject.org, mailman3.org",
        modernSpam = "untroubled.org spam archive (Bruce Guenter) 2024-2025",
        sources = sourceStats,
        splits = new { oldTrain = oldTrain.Count, oldTest = oldTest.Count, modernTrain = modernTrain.Count, modernTune = modernTune.Count, modernTest = modernTest.Count },
    },
    experiment1_oldDataOnly = exp1,
    experiment2_shipped = exp2,
    endToEnd = new
    {
        note = "Full analyser on modern tune/test splits, DOM-equivalent input (no raw headers). Thresholds tuned on tune split only.",
        defaultThresholds = before,
        calibrated = after,
        ruleRates,
        authenticationOnModernPhishing = auth,
    },
    topPhishingTerms = phishingTerms,
    topLegitimateTerms = legitTerms,
    probes = probeResults,
    trainingMinutes = Math.Round(total.Elapsed.TotalMinutes, 1),
};

var metricsPath = Path.Combine(outDir, "metrics.json");
File.WriteAllText(metricsPath, JsonSerializer.Serialize(report, ContentClassifier.JsonOptions));
Console.WriteLine($"\nWrote {metricsPath}  (total {total.Elapsed.TotalMinutes:F1} min)");
