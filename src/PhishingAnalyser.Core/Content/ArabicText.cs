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
    // Tashkeel (harakat, tanween, shadda, sukun, superscript alef), tatweel/kashida, and the extended marks that
    // render as nothing or a dot (honorifics U+0610-061A, Quranic annotation U+06D6-06ED, extended marks U+08D3-08FF).
    [GeneratedRegex("[\u064B-\u065F\u0670\u0640\u0610-\u061A\u06D6-\u06ED\u08D3-\u08FF]")]
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

    /// <summary>
    /// Persian/Urdu letters that look like Arabic ones (keheh, Farsi yeh, heh goal, heh doachashmee, yeh barree): for
    /// matching names only - "البنک العربی" renders like "البنك العربي". Not applied to model input.
    /// </summary>
    public static string FoldLookalikes(string text) =>
        !ContainsArabic(text) ? text
            : new StringBuilder(text).Replace('\u06A9', 'ك').Replace('\u06CC', 'ي').Replace('\u06C1', 'ه')
                .Replace('\u06BE', 'ه').Replace('\u06C3', 'ه').Replace('\u06D2', 'ي').ToString();
}
