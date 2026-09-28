using System.Text.RegularExpressions;

namespace PhishingAnalyser.Core.Content;

public static class Languages
{
    public const string English = "en";
    public const string Arabic = "ar";
    public const string Other = "other";
}

/// <summary>
/// Cheap language identification for the two languages the system supports. The classifier only scores
/// languages it was trained on reliably, the trainer filters on this, and the API picks the UI language with it.
/// </summary>
public static partial class LanguageHeuristics
{
    private static readonly HashSet<string> EnglishFunctionWords =
    [
        "the", "and", "to", "of", "a", "in", "is", "for", "you", "your", "this", "that", "with", "on", "are",
        "be", "we", "our", "it", "have", "please", "not", "will", "from", "if", "can", "or", "by", "at", "as",
    ];

    // Frequent function words of the languages most common in the phishing corpora (pt/es/de/nl/fr/it).
    // A mostly-foreign email with a few English words must not pass as English.
    private static readonly HashSet<string> ForeignFunctionWords =
    [
        "de", "da", "do", "que", "para", "não", "nao", "com", "uma", "os", "seu", "sua", "el", "los", "las", "por",
        "und", "der", "die", "das", "sie", "ist", "nicht", "mit", "het", "een", "wij", "voor", "niet", "je",
        "le", "les", "des", "vous", "est", "pour", "il", "della", "che", "per", "sono",
    ];

    [GeneratedRegex(@"\p{L}+")]
    private static partial Regex Word();

    /// <summary>"en", "ar" or "other". Short texts without evidence default to English.</summary>
    public static string Detect(string text, int minWords = 12)
    {
        var sample = text.Length > 4000 ? text[..4000] : text;
        var words = Word().Matches(sample);
        if (words.Count == 0)
            return Languages.English;

        var arabicWords = words.Count(w => ArabicText.ContainsArabic(w.Value));
        // Arabic mail routinely mixes in Latin brand names, URLs and codes - a solid Arabic share is enough.
        if (arabicWords >= 3 && arabicWords >= words.Count * 0.4)
            return Languages.Arabic;

        if (words.Count < minWords)
            return Languages.English;

        int latin = 0, function = 0, foreign = 0;
        foreach (Match w in words)
        {
            var word = w.Value.ToLowerInvariant();
            if (word.All(ch => ch < 0x250)) latin++;
            if (EnglishFunctionWords.Contains(word)) function++;
            else if (ForeignFunctionWords.Contains(word)) foreign++;
        }

        return latin >= words.Count * 0.8 && function >= words.Count * 0.08 && foreign < function * 0.5
            ? Languages.English
            : Languages.Other;
    }

    public static bool IsLikelyEnglish(string text, int minWords = 12) => Detect(text, minWords) == Languages.English;
}
