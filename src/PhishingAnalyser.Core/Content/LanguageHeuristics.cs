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

    // The normaliser's stand-ins for numbers, links and addresses: Latin words that say nothing about the language.
    private static readonly HashSet<string> Placeholders = ["numtoken", "urltoken", "emailtoken"];

    // Letters of Persian and Urdu that Arabic doesn't use; they share the script but the model wasn't trained on them.
    [GeneratedRegex("[\u067E\u0686\u0698\u06AF\u06A9\u06CC\u06D2\u06BA\u06C1\u06BE\u0679\u0688\u0691]")]
    private static partial Regex PersianUrduLetter();

    [GeneratedRegex("[\u0600-\u06FF]")]
    private static partial Regex ArabicScriptLetter();

    /// <summary>"en", "ar" or "other". Short texts without evidence default to English.</summary>
    public static string Detect(string text, int minWords = 12)
    {
        var sample = text.Length > 4000 ? text[..4000] : text;
        var words = Word().Matches(sample).Select(m => m.Value).Where(w => !Placeholders.Contains(w)).ToList();
        if (words.Count == 0)
            return Languages.English;

        var arabicWords = words.Count(ArabicText.ContainsArabic);
        // Arabic mail routinely mixes in Latin brand names, URLs and codes - a solid Arabic share is enough. A short
        // text that is mostly Arabic ("تحديث الحساب", a subject alone in privacy mode) is Arabic too.
        if ((arabicWords >= 3 && arabicWords >= words.Count * 0.4) || (words.Count < minWords && arabicWords * 2 >= words.Count))
        {
            var persianUrdu = PersianUrduLetter().Count(sample);
            return persianUrdu >= 3 && persianUrdu >= ArabicScriptLetter().Count(sample) * 0.03 ? Languages.Other : Languages.Arabic;
        }

        if (words.Count < minWords)
            return Languages.English;

        // Judged over the non-Arabic words: an Arabic signature under an English email doesn't make it "other" (which
        // would halve the text evidence - an evasion found by the Arabic audit).
        int latin = 0, function = 0, foreign = 0;
        foreach (var w in words.Where(w => !ArabicText.ContainsArabic(w)))
        {
            var word = w.ToLowerInvariant();
            if (word.All(ch => ch < 0x250)) latin++;
            if (EnglishFunctionWords.Contains(word)) function++;
            else if (ForeignFunctionWords.Contains(word)) foreign++;
        }

        var nonArabic = words.Count - arabicWords;
        return latin >= nonArabic * 0.8 && function >= nonArabic * 0.08 && foreign < function * 0.5
            ? Languages.English
            : Languages.Other;
    }

    public static bool IsLikelyEnglish(string text, int minWords = 12) => Detect(text, minWords) == Languages.English;
}
