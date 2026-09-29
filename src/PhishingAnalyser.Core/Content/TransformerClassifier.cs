using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

namespace PhishingAnalyser.Core.Content;

/// <summary>Written by ml/train_transformer.py next to model.onnx.</summary>
public sealed record TransformerInfo(string Base, string[] Classes, int MaxLength, string Tokenizer, bool Lowercase);

/// <summary>
/// Multilingual (English + Arabic) transformer fine-tuned in Python, served here through ONNX Runtime - so the
/// production API stays pure .NET. Unlike the bag-of-words model it reads word order and context, which is what
/// paraphrased or LLM-written phishing and Arabic need.
///
/// Tokenisation must reproduce the Python tokenizer id-for-id; tests compare against parity.json from training.
/// </summary>
public sealed class TransformerClassifier : IContentClassifier, IDisposable
{
    private readonly InferenceSession _session;
    private readonly Func<string, int[]> _encode;
    private readonly TransformerInfo _info;
    private readonly bool _needsTokenTypeIds;
    private readonly Dictionary<string, int> _classIndex;

    public bool IsLoaded => true;
    public ModelInfo? Model { get; }

    private TransformerClassifier(string directory)
    {
        _info = JsonSerializer.Deserialize<TransformerInfo>(File.ReadAllText(Path.Combine(directory, "transformer-info.json")), ContentClassifier.JsonOptions)!;
        _classIndex = _info.Classes.Select((c, i) => (c, i)).ToDictionary(x => x.c, x => x.i);

        // Tuned for a small container: no memory arena, no memory-pattern planning and no pre-packed second copy
        // of the weights. Costs a little latency, saves most of ONNX Runtime's overhead on top of the 136 MB model.
        var options = new SessionOptions
        {
            GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_ALL,
            IntraOpNumThreads = 2,
            EnableCpuMemArena = false,
            EnableMemoryPattern = false,
        };
        options.AddSessionConfigEntry("session.disable_prepacking", "1");
        _session = new InferenceSession(Path.Combine(directory, "model.onnx"), options);
        _needsTokenTypeIds = _session.InputMetadata.ContainsKey("token_type_ids");
        _encode = _info.Tokenizer == "wordpiece" ? WordPiece(directory, _info) : XlmRobertaSentencePiece(directory, _info);

        var infoPath = Path.Combine(directory, ContentClassifier.ModelInfoFileName);
        if (File.Exists(infoPath))
            Model = JsonSerializer.Deserialize<ModelInfo>(File.ReadAllText(infoPath), ContentClassifier.JsonOptions);
    }

    public static TransformerClassifier Load(string directory) => new(directory);

    public ContentResult Classify(string? subject, string? body)
    {
        var text = EmailTextNormalizer.Normalize(subject, body);
        if (text.Length == 0)
            return ContentResult.NotEvaluated;

        var probabilities = Softmax(Logits(text));
        var phishing = (double)probabilities[_classIndex[EmailClasses.Phishing]];
        if (Model?.Calibration is { } calibration)
            phishing = calibration.Apply(phishing);

        var language = LanguageHeuristics.Detect(text);
        return new ContentResult(
            Evaluated: true,
            Probability: phishing,
            SpamProbability: probabilities[_classIndex[EmailClasses.Spam]],
            IndicativeTerms: [],
            LanguageSupported: Model?.Supports(language) ?? language is Languages.English or Languages.Arabic,
            Language: language,
            LanguagePreview: Model?.IsPreview(language) == true);
    }

    /// <summary>Per-class probabilities for already-normalised text (used by the trainer's evaluation).</summary>
    public IReadOnlyDictionary<string, float> Probabilities(string normalizedText)
    {
        var p = Softmax(Logits(normalizedText));
        return _classIndex.ToDictionary(kv => kv.Key, kv => p[kv.Value]);
    }

    /// <summary>Token ids exactly as the model sees them (public for the parity tests).</summary>
    public int[] Encode(string normalizedText) => _encode(normalizedText);

    /// <summary>Raw logits (public for the parity tests). InferenceSession.Run is thread-safe.</summary>
    public float[] Logits(string normalizedText)
    {
        var ids = _encode(normalizedText);
        var shape = new[] { 1, ids.Length };
        var inputs = new List<NamedOnnxValue>
        {
            NamedOnnxValue.CreateFromTensor("input_ids", new DenseTensor<long>(ids.Select(i => (long)i).ToArray(), shape)),
            NamedOnnxValue.CreateFromTensor("attention_mask", new DenseTensor<long>(Enumerable.Repeat(1L, ids.Length).ToArray(), shape)),
        };
        if (_needsTokenTypeIds)
            inputs.Add(NamedOnnxValue.CreateFromTensor("token_type_ids", new DenseTensor<long>(new long[ids.Length], shape)));

        using var results = _session.Run(inputs);
        return results.First().AsEnumerable<float>().ToArray();
    }

    /// <summary>BERT WordPiece (distilbert-multilingual), via <see cref="HfBertTokenizer"/> - Hugging Face-exact ids.</summary>
    private static Func<string, int[]> WordPiece(string directory, TransformerInfo info)
    {
        var tokenizer = HfBertTokenizer.Load(Path.Combine(directory, "vocab.txt"), info.Lowercase);
        return text => tokenizer.Encode(text, info.MaxLength);
    }

    /// <summary>
    /// XLM-R style SentencePiece (multilingual-e5, XLM-R). Hugging Face shifts every sentencepiece id by +1
    /// (the "fairseq offset") and reserves 0-3 for &lt;s&gt; &lt;pad&gt; &lt;/s&gt; &lt;unk&gt; - raw sentencepiece ids would be off by one.
    /// </summary>
    private static Func<string, int[]> XlmRobertaSentencePiece(string directory, TransformerInfo info)
    {
        using var model = File.OpenRead(Path.Combine(directory, "sentencepiece.bpe.model"));
        var tokenizer = SentencePieceTokenizer.Create(model, addBeginningOfSentence: false, addEndOfSentence: false);
        const int Bos = 0, Eos = 2, Unk = 3, FairseqOffset = 1;
        return text =>
        {
            var pieces = tokenizer.EncodeToIds(text, addBeginningOfSentence: false, addEndOfSentence: false, considerPreTokenization: true, considerNormalization: true);
            var body = pieces.Take(info.MaxLength - 2).Select(id => id == 0 ? Unk : id + FairseqOffset);
            return [Bos, .. body, Eos];
        };
    }

    private static float[] Softmax(float[] logits)
    {
        var max = logits.Max();
        var exp = logits.Select(l => MathF.Exp(l - max)).ToArray();
        var sum = exp.Sum();
        return exp.Select(e => e / sum).ToArray();
    }

    public void Dispose() => _session.Dispose();
}

/// <summary>
/// The shipped combination: the transformer decides (probabilities, languages, calibration), the linear
/// bag-of-words model explains - it supplies the "strongest cues" words, which a transformer can't give cheaply.
/// </summary>
public sealed class HybridContentClassifier(IContentClassifier decider, ContentClassifier? explainer) : IContentClassifier
{
    public bool IsLoaded => decider.IsLoaded;
    public ModelInfo? Model => decider.Model;

    public ContentResult Classify(string? subject, string? body)
    {
        var decision = decider.Classify(subject, body);
        if (!decision.Evaluated || explainer is null)
            return decision;
        var terms = explainer.Classify(subject, body).IndicativeTerms;
        return decision with { IndicativeTerms = terms };
    }
}
