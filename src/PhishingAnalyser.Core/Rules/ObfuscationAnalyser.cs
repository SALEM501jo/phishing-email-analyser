using System.Globalization;
using System.Text.RegularExpressions;

namespace PhishingAnalyser.Core.Rules;

/// <summary>
/// Detects words that mix Latin with Cyrillic or Greek letters ("Pаypal" with a Cyrillic "а", "Micrоsoft" with
/// a Cyrillic "о"). They look identical to the real word, but defeat keyword filters and classifiers - and
/// genuine text essentially never mixes those scripts inside a single word.
/// </summary>
public sealed partial class ObfuscationAnalyser
{
    public const string Source = "obfuscation";

    [GeneratedRegex(@"\p{L}{3,}")]
    private static partial Regex Word();

    public ComponentResult Analyse(EmailSubmission email)
    {
        var findings = new List<Finding>();

        var inName = MixedScriptWords(email.SenderName).FirstOrDefault();
        if (inName is not null)
            findings.Add(new(Source, "mixed-script-sender", $"The sender name \"{inName}\" mixes look-alike letters from different alphabets to imitate a real name", 0.5,
                $"اسم المرسل \"{inName}\" يخلط أحرفًا متشابهة من أبجديات مختلفة لتقليد اسم حقيقي"));

        var inText = MixedScriptWords($"{email.Subject} {email.Body}").Distinct().Take(3).ToList();
        if (inText.Count > 0)
            findings.Add(new(Source, "mixed-script-text", $"Words written with look-alike letters from another alphabet ({string.Join(", ", inText)}) - a trick to evade filters", 0.35,
                $"كلمات مكتوبة بأحرف متشابهة من أبجدية أخرى ({string.Join("، ", inText)}) - حيلة لتجاوز الفلاتر"));

        return new ComponentResult(Source, Scoring.NoisyOr(findings), true, findings);
    }

    internal static IEnumerable<string> MixedScriptWords(string? text)
    {
        if (string.IsNullOrEmpty(text))
            yield break;
        foreach (Match m in Word().Matches(text.Length > 20_000 ? text[..20_000] : text))
        {
            bool latin = false, other = false;
            foreach (var ch in m.Value)
            {
                if (ch is >= 'A' and <= 'Z' or >= 'a' and <= 'z') latin = true;
                else if (ch is >= 'Ͱ' and <= 'Ͽ' or >= 'Ѐ' and <= 'ӿ') other = true; // Greek, Cyrillic
            }
            if (latin && other)
                yield return m.Value;
        }
    }
}
