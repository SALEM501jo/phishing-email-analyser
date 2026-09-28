using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Transforms;
using Microsoft.ML.Transforms.Text;

namespace PhishingAnalyser.Core.Content;

/// <summary>
/// The classifier distinguishes three kinds of mail. Spam is its own class because bulk marketing
/// is not phishing - lumping them together teaches the model "newsletter = attack".
/// </summary>
public static class EmailClasses
{
    public const string Legitimate = "legitimate";
    public const string Spam = "spam";
    public const string Phishing = "phishing";

    public static readonly string[] All = [Legitimate, Spam, Phishing];
}

public sealed class EmailTextInput
{
    public string Text { get; set; } = "";

    /// <summary>One of <see cref="EmailClasses"/>; empty at prediction time.</summary>
    public string Label { get; set; } = "";
}

public sealed class EmailTextPrediction
{
    [ColumnName("PredictedLabel")]
    public string PredictedClass { get; set; } = "";

    /// <summary>Per-class probabilities, in key order (see <see cref="ContentClassifier"/>).</summary>
    public float[] Score { get; set; } = [];

    /// <summary>The TF-IDF feature vector, kept so predictions can be explained.</summary>
    public VBuffer<float> Features { get; set; }
}

public enum FeatureSet
{
    /// <summary>Word unigrams + bigrams, TF-IDF weighted.</summary>
    Words,

    /// <summary>Words plus character trigrams (more robust to obfuscation like "Pay-Pal", "acc0unt").</summary>
    WordsAndChars,
}

/// <summary>The ML pipeline. Lives in Core so the trainer and tests build it the same way.</summary>
public static class ContentPipeline
{
    public const string WordFeatures = "WordFeatures";
    public const string CharFeatures = "CharFeatures";

    /// <summary>Label → key, featurize, multiclass logistic regression (maximum entropy), key → label.</summary>
    public static IEstimator<ITransformer> Build(MLContext ml, FeatureSet featureSet, IEstimator<ITransformer> trainer) =>
        ml.Transforms.Conversion
            .MapValueToKey("Label", keyOrdinality: ValueToKeyMappingEstimator.KeyOrdinality.ByValue)
            .Append(Featurizer(ml, featureSet))
            .Append(trainer)
            .Append(ml.Transforms.Conversion.MapKeyToValue("PredictedLabel"));

    public static IEstimator<ITransformer> Featurizer(MLContext ml, FeatureSet featureSet)
    {
        IEstimator<ITransformer> words = ml.Transforms.Text
            .NormalizeText("NormText", nameof(EmailTextInput.Text),
                TextNormalizingEstimator.CaseMode.Lower, keepDiacritics: false, keepPunctuations: false, keepNumbers: false)
            .Append(ml.Transforms.Text.TokenizeIntoWords("Tokens", "NormText"))
            .Append(ml.Transforms.Conversion.MapValueToKey("TokenKeys", "Tokens"))
            .Append(ml.Transforms.Text.ProduceNgrams("WordGrams", "TokenKeys",
                ngramLength: 2, useAllLengths: true, maximumNgramsCount: 200_000,
                weighting: NgramExtractingEstimator.WeightingCriteria.TfIdf))
            .Append(ml.Transforms.NormalizeLpNorm(WordFeatures, "WordGrams"));

        if (featureSet == FeatureSet.Words)
            return words.Append(ml.Transforms.CopyColumns("Features", WordFeatures));

        return words
            .Append(ml.Transforms.Text.TokenizeIntoCharactersAsKeys("Chars", "NormText", useMarkerCharacters: true))
            .Append(ml.Transforms.Text.ProduceNgrams("CharGrams", "Chars",
                ngramLength: 3, useAllLengths: false, maximumNgramsCount: 60_000,
                weighting: NgramExtractingEstimator.WeightingCriteria.TfIdf))
            .Append(ml.Transforms.NormalizeLpNorm(CharFeatures, "CharGrams"))
            .Append(ml.Transforms.Concatenate("Features", WordFeatures, CharFeatures));
    }
}
