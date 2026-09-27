using System.Diagnostics;
using System.Text.Json;
using Microsoft.ML;
using Microsoft.ML.Data;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Trainer;

// Usage: dotnet run --project tools/PhishingAnalyser.Trainer -- [dataDir=data/raw] [outDir=models]
var dataDir = args.ElementAtOrDefault(0) ?? Path.Combine("data", "raw");
var outDir = args.ElementAtOrDefault(1) ?? "models";
Directory.CreateDirectory(outDir);

const int Seed = 42;
var ml = new MLContext(seed: Seed);

Console.WriteLine($"Loading corpora from {Path.GetFullPath(dataDir)} ...");
var emails = CorpusLoader.Load(dataDir, out var corpusStats);
foreach (var (file, (p, l)) in corpusStats)
    Console.WriteLine($"  {file,-18} phishing={p,5}  legitimate={l,5}");
Console.WriteLine($"  total (deduplicated): {emails.Count} ({emails.Count(e => e.IsPhishing)} phishing / {emails.Count(e => !e.IsPhishing)} legitimate)");

// Stratified 80/20 split so both classes keep their ratio in the held-out set.
var rng = new Random(Seed);
var train = new List<LabelledEmail>();
var test = new List<LabelledEmail>();
foreach (var group in emails.GroupBy(e => e.IsPhishing))
{
    var shuffled = group.OrderBy(_ => rng.Next()).ToList();
    var cut = (int)(shuffled.Count * 0.8);
    train.AddRange(shuffled.Take(cut));
    test.AddRange(shuffled.Skip(cut));
}

IDataView ToView(IEnumerable<LabelledEmail> rows) =>
    ml.Data.LoadFromEnumerable(rows.Select(e => new EmailTextInput { Text = e.Text, Label = e.IsPhishing }));

var trainView = ml.Data.Cache(ToView(train));
var testView = ToView(test);
Console.WriteLine($"  train={train.Count}  test={test.Count}\n");

var candidates = new (string Name, FeatureSet Features, Func<IEstimator<ITransformer>> Trainer)[]
{
    ("words + SDCA logistic regression", FeatureSet.Words,
        () => ml.BinaryClassification.Trainers.SdcaLogisticRegression(l2Regularization: 1e-5f, maximumNumberOfIterations: 50)),
    ("words + L-BFGS logistic regression", FeatureSet.Words,
        () => ml.BinaryClassification.Trainers.LbfgsLogisticRegression(l1Regularization: 0f, l2Regularization: 1f)),
    ("words + char-3grams + SDCA logistic regression", FeatureSet.WordsAndChars,
        () => ml.BinaryClassification.Trainers.SdcaLogisticRegression(l2Regularization: 1e-5f, maximumNumberOfIterations: 50)),
    ("words + char-3grams + L-BFGS logistic regression", FeatureSet.WordsAndChars,
        () => ml.BinaryClassification.Trainers.LbfgsLogisticRegression(l1Regularization: 0f, l2Regularization: 1f)),
};

var results = new List<(string Name, ITransformer Model, CalibratedBinaryClassificationMetrics Metrics, double Seconds)>();
foreach (var (name, features, trainer) in candidates)
{
    Console.WriteLine($"Training: {name}");
    var sw = Stopwatch.StartNew();
    var model = ContentPipeline.Featurizer(ml, features).Append(trainer()).Fit(trainView);
    sw.Stop();

    var metrics = ml.BinaryClassification.Evaluate(model.Transform(testView));
    results.Add((name, model, metrics, sw.Elapsed.TotalSeconds));
    Console.WriteLine($"  accuracy={metrics.Accuracy:P2}  precision={metrics.PositivePrecision:P2}  recall={metrics.PositiveRecall:P2}  " +
                      $"F1={metrics.F1Score:P2}  AUC={metrics.AreaUnderRocCurve:F4}  ({sw.Elapsed.TotalSeconds:F1}s)");
}

var best = results.MaxBy(r => r.Metrics.F1Score);
Console.WriteLine($"\nBest by F1: {best.Name}");
Console.WriteLine(best.Metrics.ConfusionMatrix.GetFormattedConfusionTable());

var modelPath = Path.Combine(outDir, "phishing-content-model.zip");
ml.Model.Save(best.Model, trainView.Schema, modelPath);
Console.WriteLine($"Saved {modelPath} ({new FileInfo(modelPath).Length / 1024} KB)");

// Reload from disk exactly as the API will, then show what was learned.
var classifier = ContentClassifier.Load(modelPath);
var (phishingTerms, legitTerms) = classifier.TopWeightedTerms(25);
Console.WriteLine("\nTerms pushing towards PHISHING: " + string.Join(", ", phishingTerms.Select(t => t.Term)));
Console.WriteLine("Terms pushing towards LEGITIMATE: " + string.Join(", ", legitTerms.Select(t => t.Term)));

// Hand-written probes - none of these are in the training data.
var probes = new (string Subject, string Body)[]
{
    ("Your account has been suspended", "Dear customer, we detected unusual activity. Verify your identity within 24 hours or your account will be permanently closed. Click here to restore access."),
    ("Invoice #4821 overdue - action required", "Please review the attached invoice and confirm payment details immediately to avoid late fees. Login with your email password to view the document."),
    ("You have (1) pending package", "Your parcel could not be delivered due to an unpaid customs fee of $1.99. Update your payment information here."),
    ("Lunch tomorrow?", "Hey, are we still on for lunch tomorrow at 1? I can book the place near the office. Let me know."),
    ("Minutes from Tuesday's sprint review", "Hi all, attached are the notes from the review. Action items: Omar to update the API docs, Lina to fix the flaky login test. Next review is on the 14th."),
    ("Re: draft of chapter 3", "Thanks for the comments. I reworked the second section and moved the table into the appendix. Can you take another look when you have time?"),
};
Console.WriteLine("\nProbe emails (unseen):");
var probeResults = probes.Select(p =>
{
    var r = classifier.Classify(p.Subject, p.Body);
    Console.WriteLine($"  {r.Probability,6:P1}  {p.Subject}   [{string.Join(", ", r.IndicativeTerms)}]");
    return new { p.Subject, probability = Math.Round(r.Probability, 4), terms = r.IndicativeTerms };
}).ToList();

var report = new
{
    trainedAt = DateTime.UtcNow,
    dataset = new
    {
        source = "Phishing Email Curated Datasets (Champa et al.), Zenodo, doi:10.5281/zenodo.8339691, CC BY 4.0",
        files = corpusStats.ToDictionary(kv => kv.Key, kv => new { phishing = kv.Value.Phishing, legitimate = kv.Value.Legit }),
        train = train.Count,
        test = test.Count,
    },
    selected = best.Name,
    candidates = results.Select(r => new
    {
        name = r.Name,
        accuracy = Math.Round(r.Metrics.Accuracy, 4),
        precision = Math.Round(r.Metrics.PositivePrecision, 4),
        recall = Math.Round(r.Metrics.PositiveRecall, 4),
        f1 = Math.Round(r.Metrics.F1Score, 4),
        auc = Math.Round(r.Metrics.AreaUnderRocCurve, 4),
        trainSeconds = Math.Round(r.Seconds, 1),
    }),
    topPhishingTerms = phishingTerms.Select(t => t.Term),
    topLegitimateTerms = legitTerms.Select(t => t.Term),
    probes = probeResults,
};

var metricsPath = Path.Combine(outDir, "metrics.json");
File.WriteAllText(metricsPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"\nWrote {metricsPath}");
