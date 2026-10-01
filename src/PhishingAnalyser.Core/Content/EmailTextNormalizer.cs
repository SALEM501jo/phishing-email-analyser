using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishingAnalyser.Core.Content;

/// <summary>
/// Turns subject + body into the single text field the classifier sees.
/// Used by BOTH the trainer and the API, so training and inference see identical input.
/// </summary>
public static partial class EmailTextNormalizer
{
    public const int MaxChars = 6000;

    [GeneratedRegex(@"<(script|style)\b[^>]*>.*?</\1\s*>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex ScriptOrStyle();

    [GeneratedRegex(@"<[^>]{1,2000}>")]
    private static partial Regex HtmlTag();

    [GeneratedRegex(@"(https?://|www\.)\S+", RegexOptions.IgnoreCase)]
    private static partial Regex Url();

    [GeneratedRegex(@"[\w.+-]+@[\w-]+(\.[\w-]+)+")]
    private static partial Regex EmailAddress();

    // Digits are collapsed so the model can't key on years/timestamps that differ between
    // corpora (e.g. 2002 ham vs 2015+ phishing) - "24 hours" still survives as "numtoken hours".
    [GeneratedRegex(@"\d+")]
    private static partial Regex Digits();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    // Zero-width and soft-hyphen characters are used to split words ("pa​ssword") so keyword
    // and n-gram matching misses them; they never carry meaning in email text.
    [GeneratedRegex("[­​-‏⁠﻿]")]
    private static partial Regex Invisible();

    /// <summary>
    /// False when the runtime can't do Unicode normalization: .NET's invariant-globalization mode silently skips it, so
    /// "𝐏𝐚𝐲𝐏𝐚𝐥" would reach the models unfolded although training folded it to "PayPal" (found by the red-team review).
    /// </summary>
    public static bool NormalizationAvailable => "\uFB01".Normalize(NormalizationForm.FormKC) == "fi";

    public static string Normalize(string? subject, string? body)
    {
        var text = $"{subject}\n{body}";
        if (text.Length > MaxChars * 4)
            text = text[..(MaxChars * 4)];

        text = ScriptOrStyle().Replace(text, " ");
        text = HtmlTag().Replace(text, " ");
        text = WebUtility.HtmlDecode(text);
        text = WithoutInvalidCodePoints(Invisible().Replace(text, "")).Normalize(NormalizationForm.FormKC);
        text = ArabicText.Normalize(text);
        text = Url().Replace(text, " urltoken ");
        text = EmailAddress().Replace(text, " emailtoken ");
        text = Digits().Replace(text, " numtoken ");
        text = Whitespace().Replace(text, " ").Trim();

        return text.Length > MaxChars ? text[..MaxChars] : text;
    }

    /// <summary>
    /// Drops what string.Normalize rejects - unpaired surrogates and the noncharacters U+FFFE/U+FFFF (HTML "&amp;#xFFFE;"
    /// produces one) - which made it throw, leaving the email without a verdict (red-team review). Valid text is returned
    /// unchanged, so training and inference still see identical input.
    /// </summary>
    private static string WithoutInvalidCodePoints(string text)
    {
        StringBuilder? clean = null;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            var pair = char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]);
            var invalid = !pair && (char.IsSurrogate(c) || c is '\uFFFE' or '\uFFFF');
            if (invalid && clean is null)
                clean = new StringBuilder(text.Length).Append(text, 0, i);
            if (!invalid)
            {
                clean?.Append(c);
                if (pair)
                    clean?.Append(text[i + 1]);
            }
            if (pair)
                i++;
        }
        return clean?.ToString() ?? text;
    }
}
