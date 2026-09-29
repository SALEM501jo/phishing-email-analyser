using System.Text.Json;
using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers;
using Microsoft.Extensions.ObjectPool;

namespace PhishingAnalyser.Core.Content;

public interface IContentClassifier
{
    bool IsLoaded { get; }
    ModelInfo? Model { get; }
    ContentResult Classify(string? subject, string? body);
}

/// <summary>Identity of the trained model, written by the trainer next to the .zip as model-info.json.</summary>
/// <param name="Calibration">Platt scaling for the phishing probability, fitted on held-out modern mail.</param>
/// <param name="Thresholds">Verdict thresholds calibrated end-to-end with this model; the API uses them unless configured.</param>
/// <param name="Languages">Languages the model was trained on; others get a halved weight and a stated limitation.</param>
public sealed record ModelInfo(
    string Version,
    DateTime TrainedAtUtc,
    string Description,
    PlattCalibration? Calibration = null,
    VerdictThresholds? Thresholds = null,
    string[]? Languages = null,
    string[]? PreviewLanguages = null)
{
    public bool Supports(string language) => (Languages ?? [Content.Languages.English]).Contains(language);

    /// <summary>
    /// Trained on, but not yet trusted: evaluation showed too many false alarms on realistic mail in this language.
    /// Scored at half weight (like an unsupported language) with an honest "preview" note instead of "not trained".
    /// </summary>
    public bool IsPreview(string language) => PreviewLanguages?.Contains(language) == true;
}

/// <summary>calibrated = sigmoid(A · logit(raw) + B)</summary>
public sealed record PlattCalibration(double A, double B)
{
    public double Apply(double raw)
    {
        var p = Math.Clamp(raw, 1e-6, 1 - 1e-6);
        return 1 / (1 + Math.Exp(-(A * Math.Log(p / (1 - p)) + B)));
    }
}

public sealed record VerdictThresholds(double Phishing, double Suspicious);

/// <summary>
/// Wraps the trained ML.NET model. Besides class probabilities it reports which n-grams in THIS email
/// pushed it towards "phishing" most (feature value x learned weight), so the verdict is explainable.
/// </summary>
public sealed class ContentClassifier : IContentClassifier
{
    public const string ModelInfoFileName = "model-info.json";
    private const int MaxTerms = 6;

    // Still used as features (the model legitimately learned that "your" is phishing-ward),
    // but not useful to show a user as an explanation.
    private static readonly HashSet<string> FunctionWords =
    [
        "your", "you", "the", "to", "a", "an", "of", "and", "or", "is", "are", "in", "on", "for", "this",
        "that", "we", "our", "it", "be", "as", "at", "by", "with", "from", "de", "en", "me", "my", "i",
    ];

    // PredictionEngine is not thread-safe and costly to create, so requests borrow one from a pool
    // (the same approach as Microsoft.Extensions.ML's PredictionEnginePool) instead of queuing behind a lock.
    private readonly ObjectPool<PredictionEngine<EmailTextInput, EmailTextPrediction>> _engines;
    private readonly Dictionary<string, int> _classIndex;
    private readonly float[]? _phishingDirection; // per-feature weight towards "phishing" vs the other classes
    private readonly float[]? _legitimateDirection;
    private readonly string[] _slotNames;

    public bool IsLoaded => true;
    public ModelInfo? Model { get; }

    private ContentClassifier(MLContext ml, ITransformer model, DataViewSchema inputSchema, ModelInfo? info)
    {
        _engines = new DefaultObjectPool<PredictionEngine<EmailTextInput, EmailTextPrediction>>(
            new EnginePolicy(() => ml.Model.CreatePredictionEngine<EmailTextInput, EmailTextPrediction>(model, inputSchema)),
            maximumRetained: Environment.ProcessorCount * 2);
        var outputSchema = model.GetOutputSchema(inputSchema);
        _slotNames = ReadSlotNames(outputSchema["Features"]);

        var classes = ReadSlotNames(outputSchema["Score"]);
        if (classes.Length == 0)
            classes = EmailClasses.All.Order(StringComparer.Ordinal).ToArray(); // key order is ByValue
        _classIndex = classes.Select((c, i) => (c, i)).ToDictionary(x => x.c, x => x.i);

        var weights = ExtractClassWeights(model);
        if (weights is not null)
        {
            _phishingDirection = Direction(weights, _classIndex[EmailClasses.Phishing]);
            _legitimateDirection = Direction(weights, _classIndex[EmailClasses.Legitimate]);
        }

        Model = info;
    }

    /// <summary>Loads the model and, if present, model-info.json (version, calibration, thresholds) from the same folder.</summary>
    public static ContentClassifier Load(string modelPath)
    {
        var ml = new MLContext(seed: 0);
        var model = ml.Model.Load(modelPath, out var inputSchema);

        ModelInfo? info = null;
        var infoPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(modelPath))!, ModelInfoFileName);
        if (File.Exists(infoPath))
            info = JsonSerializer.Deserialize<ModelInfo>(File.ReadAllText(infoPath), JsonOptions);

        return new ContentClassifier(ml, model, inputSchema, info);
    }

    public static ContentClassifier FromModel(MLContext ml, ITransformer model, DataViewSchema inputSchema) =>
        new(ml, model, inputSchema, null);

    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public ContentResult Classify(string? subject, string? body)
    {
        var text = EmailTextNormalizer.Normalize(subject, body);
        if (text.Length == 0)
            return ContentResult.NotEvaluated;

        var prediction = Predict(text);
        var language = LanguageHeuristics.Detect(text);
        var phishing = (double)prediction.Score[_classIndex[EmailClasses.Phishing]];
        if (Model?.Calibration is { } calibration)
            phishing = calibration.Apply(phishing);

        return new ContentResult(
            Evaluated: true,
            Probability: phishing,
            SpamProbability: prediction.Score[_classIndex[EmailClasses.Spam]],
            IndicativeTerms: TopContributingTerms(prediction.Features),
            LanguageSupported: Model?.Supports(language) ?? language == Languages.English,
            Language: language);
    }

    /// <summary>Per-class probabilities, for the trainer's evaluation.</summary>
    public IReadOnlyDictionary<string, float> Probabilities(string normalizedText)
    {
        var prediction = Predict(normalizedText);
        return _classIndex.ToDictionary(kv => kv.Key, kv => prediction.Score[kv.Value]);
    }

    private EmailTextPrediction Predict(string text)
    {
        var engine = _engines.Get();
        try
        {
            // A fresh output object per call, so the result stays valid after the engine goes back to the pool.
            return engine.Predict(new EmailTextInput { Text = text });
        }
        finally
        {
            _engines.Return(engine);
        }
    }

    private sealed class EnginePolicy(Func<PredictionEngine<EmailTextInput, EmailTextPrediction>> create)
        : IPooledObjectPolicy<PredictionEngine<EmailTextInput, EmailTextPrediction>>
    {
        public PredictionEngine<EmailTextInput, EmailTextPrediction> Create() => create();
        public bool Return(PredictionEngine<EmailTextInput, EmailTextPrediction> engine) => true;
    }

    /// <summary>Returns the word n-grams with the largest positive (phishing-ward) contribution.</summary>
    private IReadOnlyList<string> TopContributingTerms(VBuffer<float> features)
    {
        if (_phishingDirection is null || _slotNames.Length == 0)
            return [];

        var contributions = new List<(string Term, float Value)>();
        var values = features.GetValues();
        var indices = features.GetIndices();
        var isDense = features.IsDense;

        for (var i = 0; i < values.Length; i++)
        {
            var slot = isDense ? i : indices[i];
            if (slot >= _phishingDirection.Length || slot >= _slotNames.Length)
                continue;

            var contribution = values[i] * _phishingDirection[slot];
            if (contribution <= 0)
                continue;

            var term = ToDisplayTerm(_slotNames[slot]);
            if (term is not null && !FunctionWords.Contains(term))
                contributions.Add((term, contribution));
        }

        return contributions
            .OrderByDescending(c => c.Value)
            .Select(c => c.Term)
            .Distinct()
            .Take(MaxTerms)
            .ToList();
    }

    /// <summary>Globally strongest word n-grams towards phishing and towards legitimate - what the model has learned.</summary>
    public (IReadOnlyList<string> Phishing, IReadOnlyList<string> Legitimate) TopWeightedTerms(int count)
    {
        if (_phishingDirection is null || _legitimateDirection is null || _slotNames.Length == 0)
            return ([], []);

        IReadOnlyList<string> Top(float[] direction) => direction
            .Select((w, i) => (Term: i < _slotNames.Length ? ToDisplayTerm(_slotNames[i]) : null, Weight: w))
            .Where(t => t.Term is not null)
            .OrderByDescending(t => t.Weight)
            .Select(t => t.Term!)
            .Take(count)
            .ToList();

        return (Top(_phishingDirection), Top(_legitimateDirection));
    }

    /// <summary>Maps a slot name like "WordFeatures.verify|your" to "verify your"; drops char-grams and placeholder tokens.</summary>
    internal static string? ToDisplayTerm(string slotName)
    {
        var name = slotName;
        if (name.StartsWith(ContentPipeline.CharFeatures + ".", StringComparison.Ordinal))
            return null;
        if (name.StartsWith(ContentPipeline.WordFeatures + ".", StringComparison.Ordinal))
            name = name[(ContentPipeline.WordFeatures.Length + 1)..];

        var tokens = name.Split('|');
        if (tokens.All(t => t is "numtoken" or "urltoken" or "emailtoken" || t.Length < 2))
            return null;

        return string.Join(' ', tokens.Select(t => t switch
        {
            "numtoken" => "<number>",
            "urltoken" => "<link>",
            "emailtoken" => "<email>",
            _ => t,
        }));
    }

    private static string[] ReadSlotNames(DataViewSchema.Column column)
    {
        if (!column.HasSlotNames())
            return [];

        VBuffer<ReadOnlyMemory<char>> names = default;
        column.GetSlotNames(ref names);
        return names.DenseValues().Select(n => n.ToString()).ToArray();
    }

    /// <summary>How much each feature favours class <paramref name="target"/> over the average of the other classes.</summary>
    private static float[] Direction(float[][] weights, int target)
    {
        var direction = new float[weights[target].Length];
        for (var f = 0; f < direction.Length; f++)
        {
            float others = 0;
            for (var c = 0; c < weights.Length; c++)
                if (c != target) others += weights[c][f];
            direction[f] = weights[target][f] - others / (weights.Length - 1);
        }
        return direction;
    }

    /// <summary>Pulls the per-class weight vectors out of the multiclass linear model.</summary>
    private static float[][]? ExtractClassWeights(ITransformer model)
    {
        if (model is not TransformerChain<ITransformer> chain)
            return null;

        foreach (var transformer in chain.Reverse())
        {
            if (transformer.GetType().GetProperty("Model")?.GetValue(transformer) is LinearMulticlassModelParametersBase linear)
            {
                VBuffer<float>[] weights = [];
                linear.GetWeights(ref weights, out _);
                return weights.Select(w => w.DenseValues().ToArray()).ToArray();
            }
        }

        return null;
    }
}

/// <summary>Used when no model file is available - the API still runs its rule-based checks.</summary>
public sealed class UnavailableContentClassifier : IContentClassifier
{
    public bool IsLoaded => false;
    public ModelInfo? Model => null;
    public ContentResult Classify(string? subject, string? body) => ContentResult.NotEvaluated;
}
