using System.Text.RegularExpressions;

namespace PhishingAnalyser.Trainer.Corpus;

/// <summary>
/// Removes things that identify WHICH dataset an email came from rather than whether it is phishing.
/// Every rule here exists because an earlier model learned it as a shortcut.
/// </summary>
public static partial class TextCleaning
{
    // Nazario honeypot owner, Enron internals (incl. its Houston HQ), spam-trap owner, SpamAssassin/list footers,
    // and the names of the mailing lists that supply modern legitimate mail.
    [GeneratedRegex(@"\b(jose|monkey\.org|monkey|enron|ect|hou|houston|corp|untroubled|bruce|spamassassin|sourceforge|exmh|razor|listinfo|mailman3?|hyperkitty|fedora(project)?|python|zzzz|yyyy|jm|fork|xent|irish linux users)\b", RegexOptions.IgnoreCase)]
    private static partial Regex CorpusArtifacts();

    // Undecoded MIME encoded-words survive only in the phishing dump; "URL:/Date:" lines come from SpamAssassin RSS digests.
    [GeneratedRegex(@"=\?[\w-]+\?[BQbq]\?[^?\s]*\?=|^\s*(URL|Date):.*$", RegexOptions.Multiline)]
    private static partial Regex FormatArtifacts();

    // Mailing-list archives obfuscate addresses as "user(a)lists.example.org".
    [GeneratedRegex(@"\S+\(a\)\S+")]
    private static partial Regex ObfuscatedAddress();

    // "On Sat, Jan 11, 2025 at 3:53 PM Jane via users <...> wrote:" (may wrap onto a second line)
    [GeneratedRegex(@"^On [^\n]{0,250}(\n[^\n]{0,250})?wrote:\s*$", RegexOptions.Multiline)]
    private static partial Regex ReplyAttribution();

    [GeneratedRegex(@"^\s*>.*$\n?", RegexOptions.Multiline)]
    private static partial Regex QuotedLine();

    // Everything after a mailman footer separator, a "-- " signature marker or a forwarded/original-message banner.
    [GeneratedRegex(@"^(_{20,}|-- ?|-{3,}\s*Original Message\s*-{3,}|-{5,} ?Forwarded message ?-{5,})\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex TrailerStart();

    // " via users" style list attribution inside display names.
    [GeneratedRegex(@"\bvia \S+ mailing list\b|\bvia (users|devel|announce)\b", RegexOptions.IgnoreCase)]
    private static partial Regex ViaList();

    /// <summary>
    /// Makes a raw body look like what Gmail's page shows: quoted history and footers are collapsed in Gmail,
    /// so they are removed here too (otherwise "has quoted replies" becomes a proxy for "legitimate").
    /// </summary>
    public static string VisibleBody(string? body)
    {
        if (string.IsNullOrEmpty(body))
            return "";

        body = body.Replace("\r\n", "\n");
        var trailer = TrailerStart().Match(body);
        if (trailer.Success && trailer.Index > 0)
            body = body[..trailer.Index];

        body = ReplyAttribution().Replace(body, " ");
        body = QuotedLine().Replace(body, "");
        return ObfuscatedAddress().Replace(body, " emailtoken ");
    }

    public static string StripFormatArtifacts(string? text) => FormatArtifacts().Replace(text ?? "", " ");

    public static string ScrubCorpusArtifacts(string normalizedText) =>
        CorpusArtifacts().Replace(ViaList().Replace(normalizedText, " "), " ");

    /// <summary>Thread/campaign key: subject without reply prefixes, list tags or digits.</summary>
    public static string GroupKey(string? subject, string fallback)
    {
        var s = (subject ?? "").ToLowerInvariant();
        s = Regex.Replace(s, @"^\s*((re|fw|fwd|aw|sv)\s*:\s*|\[[^\]]*\]\s*)+", "");
        s = Regex.Replace(s, @"[\d\W_]+", " ").Trim();
        return s.Length == 0 ? "body:" + fallback : s; // no subject: the email is its own group
    }
}
