using System.Text;
using System.Text.RegularExpressions;

namespace PhishingAnalyser.Core.Content;

/// <summary>
/// Orthographic normalisation for Arabic, the standard step before matching or modelling Arabic text:
/// the same word is written with or without diacritics, stretched with tatweel, or with alef/yaa/taa-marbuta
/// variants - and phishers exploit those variants to dodge keyword filters.
/// </summary>
public static partial class ArabicText
{
    // Tashkeel (harakat, tanween, shadda, sukun, superscript alef) and tatweel/kashida.
    [GeneratedRegex("[ً-ٰٟـ]")]
    private static partial Regex DiacriticsAndTatweel();

    [GeneratedRegex(@"[؀-ۿ]")]
    private static partial Regex ArabicLetter();

    public static bool ContainsArabic(string? text) => text is not null && ArabicLetter().IsMatch(text);

    public static string Normalize(string text)
    {
        if (!ContainsArabic(text))
            return text;

        var sb = new StringBuilder(DiacriticsAndTatweel().Replace(text, ""));
        sb.Replace('أ', 'ا').Replace('إ', 'ا').Replace('آ', 'ا').Replace('ٱ', 'ا')
          .Replace('ى', 'ي').Replace('ة', 'ه').Replace('ؤ', 'و').Replace('ئ', 'ي');
        return sb.ToString();
    }
}
