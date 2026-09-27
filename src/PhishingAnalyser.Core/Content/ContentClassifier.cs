using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers;

namespace PhishingAnalyser.Core.Content;

public interface IContentClassifier
{
    bool IsLoaded { get; }
    ContentResult Classify(string? subject, string? body);
}

/// <summary>
/// Wraps the trained ML.NET model. Besides the probability it reports which n-grams in THIS email
/// pushed the score up most (feature value x learned weight), so the verdict is explainable.
/// </summary>
public sealed class ContentClassifier : IContentClassifier
{
    private const int MaxTerms = 6;

    // Still used as features (the model legitimately learned that "your" is phishing-ward),
    // but not useful to show a user as an explanation.
    private static readonly HashSet<string> FunctionWords =
    [
        "your", "you", "the", "to", "a", "an", "of", "and", "or", "is", "are", "in", "on", "for", "this",
        "that", "we", "our", "it", "be", "as", "at", "by", "with", "from", "de", "en", "me", "my", "i",
    ];

    private readonly PredictionEngine<EmailTextInput, EmailTextPrediction> _engine;
    private readonly float[]? _weights;
    private readonly string[] _slotNames;
    private readonly object _gate = new();// PredictionEngine is not thread-safe

    public bool IsLoaded => true;

    private ContentClassifier(MLContext ml, ITransformer model, DataViewSchema inputSchema)
    {
        _engine = ml.Model.CreatePredictionEngine<EmailTextInput, EmailTextPrediction>(model, inputSchema);
        _weights = ExtractLinearWeights(model);
        _slotNames = ReadSlotNames(model.GetOutputSchema(inputSchema));
    }

    public static ContentClassifier Load(string modelPath)
    {
        var ml = new MLContext(seed: 0);
        var model = ml.Model.Load(modelPath, out var inputSchema);
        return new ContentClassifier(ml, model, inputSchema);
    }

    public static ContentClassifier FromModel(MLContext ml, ITransformer model, DataViewSchema inputSchema) =>
        new(ml, model, inputSchema);

    public ContentResult Classify(string? subject, string? body)
    {
        var text = EmailTextNormalizer.Normalize(subject, body);
        if (text.Length == 0)
            return new ContentResult(false, 0, []);

        EmailTextPrediction prediction;
        lock (_gate)
            prediction = _engine.Predict(new EmailTextInput { Text = text });

        return new ContentResult(true, prediction.Probability, TopContributingTerms(prediction.Features));
    }

    /// <summary>Returns the word n-grams with the largest positive (phishing-ward) contribution.</summary>
    private IReadOnlyList<string> TopContributingTerms(VBuffer<float> features)
    {
        if (_weights is null || _slotNames.Length == 0)
            return [];

        var contributions = new List<(string Term, float Value)>();
        var values = features.GetValues();
        var indices = features.GetIndices();
        var isDense = features.IsDense;

        for (var i = 0; i < values.Length; i++)
        {
            var slot = isDense ? i : indices[i];
            if (slot >= _weights.Length || slot >= _slotNames.Length)
                continue;

            var contribution = values[i] * _weights[slot];
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

    /// <summary>Globally strongest word n-grams in each direction - what the model has learned overall.</summary>
    public (IReadOnlyList<(string Term, float Weight)> Phishing, IReadOnlyList<(string Term, float Weight)> Legitimate) TopWeightedTerms(int count)
    {
        if (_weights is null || _slotNames.Length == 0)
            return ([], []);

        var terms = _weights
            .Select((w, i) => (Term: i < _slotNames.Length ? ToDisplayTerm(_slotNames[i]) : null, Weight: w))
            .Where(t => t.Term is not null)
            .Select(t => (t.Term!, t.Weight))
            .ToList();

        return (terms.OrderByDescending(t => t.Item2).Take(count).ToList(),
                terms.OrderBy(t => t.Item2).Take(count).ToList());
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

    private static string[] ReadSlotNames(DataViewSchema outputSchema)
    {
        var column = outputSchema["Features"];
        if (!column.HasSlotNames())
            return [];

        VBuffer<ReadOnlyMemory<char>> names = default;
        column.GetSlotNames(ref names);
        return names.DenseValues().Select(n => n.ToString()).ToArray();
    }

    /// <summary>
    /// Pulls the linear weights out of the final (calibrated) logistic-regression transformer.
    /// Reflection is used because the concrete calibrated type differs by trainer and after deserialisation.
    /// </summary>
    private static float[]? ExtractLinearWeights(ITransformer model)
    {
        var last = model is TransformerChain<ITransformer> chain ? chain.LastTransformer : model;
        var parameters = PropertyValue(last, "Model");

        for (var depth = 0; depth < 4 && parameters is not null; depth++)
        {
            if (parameters is LinearModelParameters linear)
                return linear.Weights.ToArray();
            parameters = PropertyValue(parameters, "SubModel");
        }

        return null;
    }

    // Generic calibrated types expose several same-named properties (base + interface re-declarations).
    private static object? PropertyValue(object target, string name) =>
        target.GetType().GetProperties()
            .Where(p => p.Name == name && p.GetIndexParameters().Length == 0)
            .Select(p => p.GetValue(target))
            .OrderByDescending(v => v is LinearModelParameters)
            .FirstOrDefault(v => v is not null);
}

/// <summary>Used when no model file is available - the API still runs its rule-based checks.</summary>
public sealed class UnavailableContentClassifier : IContentClassifier
{
    public bool IsLoaded => false;
    public ContentResult Classify(string? subject, string? body) => new(false, 0, []);
}
