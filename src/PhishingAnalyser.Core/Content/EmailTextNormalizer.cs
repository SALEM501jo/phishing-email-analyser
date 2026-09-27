using System.Net;
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

    public static string Normalize(string? subject, string? body)
    {
        var text = $"{subject}\n{body}";
        if (text.Length > MaxChars * 4)
            text = text[..(MaxChars * 4)];

        text = ScriptOrStyle().Replace(text, " ");
        text = HtmlTag().Replace(text, " ");
        text = WebUtility.HtmlDecode(text);
        text = Url().Replace(text, " urltoken ");
        text = EmailAddress().Replace(text, " emailtoken ");
        text = Digits().Replace(text, " numtoken ");
        text = Whitespace().Replace(text, " ").Trim();

        return text.Length > MaxChars ? text[..MaxChars] : text;
    }
}
