using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Trainer.Evaluation;

/// <summary>The same classifier, but treating one preview language as fully supported (full weight).</summary>
public sealed class PromotedLanguage(IContentClassifier inner, string language) : IContentClassifier
{
    public bool IsLoaded => inner.IsLoaded;
    public ModelInfo? Model => inner.Model;
    public ContentResult Classify(string? subject, string? body)
    {
        var result = inner.Classify(subject, body);
        return result.Language == language ? result with { LanguageSupported = true, LanguagePreview = false } : result;
    }
}
