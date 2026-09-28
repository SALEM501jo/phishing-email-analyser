using System.Text.RegularExpressions;

namespace PhishingAnalyser.Core.Content;

/// <summary>
/// Cheap "is this English?" check. The classifier is trained on English mail, so its output on other
/// languages is unreliable - the trainer filters on this and the API reports it as a limitation.
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

    /// <param name="minWords">Below this many words there isn't enough evidence; the text is given the benefit of the doubt.</param>
    public static bool IsLikelyEnglish(string text, int minWords = 12)
    {
        var words = Word().Matches(text.Length > 4000 ? text[..4000] : text);
        if (words.Count < minWords)
            return true;

        int latin = 0, function = 0, foreign = 0;
        foreach (Match w in words)
        {
            var word = w.Value.ToLowerInvariant();
            if (word.All(ch => ch < 0x250)) latin++;
            if (EnglishFunctionWords.Contains(word)) function++;
            else if (ForeignFunctionWords.Contains(word)) foreign++;
        }

        return latin >= words.Count * 0.8 && function >= words.Count * 0.08 && foreign < function * 0.5;
    }
}
